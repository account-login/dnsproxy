package dnsproxy

import (
	"context"
	"encoding/json"
	"github.com/account-login/ctxlog"
	"github.com/pkg/errors"
	"net"
	"time"
)

type Server struct {
	Listen       string
	Timeout      time.Duration
	RootResolver Resolver
	// private
	UDPResolver
}

func MakeServerFromString(input []byte) (*Server, error) {
	type jsonResolver struct {
		Name     string   `json:"name"`
		Type     string   `json:"type"`
		Addr     string   `json:"addr"`
		Child    string   `json:"child"`
		Children []string `json:"children"`
		// for CNResolver
		CNList []string `json:"cn_list"`
		AbList []string `json:"ab_list"`
		MaxTTL uint32   `json:"max_ttl"`
		// for DynResolver
		DBPath          string   `json:"db_path"`
		Suffixes        []string `json:"suffixes"`
		HTTPAddr        string   `json:"http_addr"`
		HTTPSAddr       string   `json:"https_addr"`
		TLSCertFile     string   `json:"tls_cert_file"`
		TLSKeyFile      string   `json:"tls_key_file"`
		TLSClientCAFile string   `json:"tls_client_ca_file"`
	}
	type jsonConfig struct {
		Listen    string         `json:"listen"`
		TimeoutMS int64          `json:"timeout_ms"`
		Resolvers []jsonResolver `json:"resolvers"`
		GFWIPList []string       `json:"gfw_ip_list"`
	}

	cfg := jsonConfig{}
	err := json.Unmarshal(input, &cfg)
	if err != nil {
		return nil, err
	}

	s := &Server{}
	s.Listen = cfg.Listen
	s.Timeout = time.Duration(cfg.TimeoutMS) * time.Millisecond

	name2resolver := map[string]Resolver{}
	parents := map[string]struct{}{}
	var loadResolver func(name string) (Resolver, error)
	loadResolver = func(name string) (Resolver, error) {
		// check loaded resolver
		if res, ok := name2resolver[name]; ok {
			return res, nil
		}

		// check dead loop
		if _, ok := parents[name]; ok {
			return nil, errors.Errorf("circular ref for name %q", name)
		}

		// get json obj
		var jr *jsonResolver
		for i := range cfg.Resolvers {
			if cfg.Resolvers[i].Name == name {
				jr = &cfg.Resolvers[i]
				break
			}
		}
		if jr == nil {
			return nil, errors.Errorf("resolver %q expected", name)
		}

		loadChildren := func(childNameList []string) ([]Resolver, error) {
			var children []Resolver
			parents[name] = struct{}{}
			for _, childName := range childNameList {
				var child Resolver
				child, err = loadResolver(childName)
				if err != nil {
					return nil, err
				}

				children = append(children, child)
			}
			delete(parents, name)
			return children, nil
		}

		var res Resolver
		switch jr.Type {
		case "hosts":
			res = &HostsResolver{Name: name}
		case "leaf":
			remote, err := net.ResolveUDPAddr("udp", jr.Addr)
			if err != nil {
				return nil, errors.Wrapf(err, "bad addr for resolver %v", jr)
			}
			res = &RemoteBindedUDPResolver{
				Name:        name,
				Remote:      remote,
				UDPResolver: &s.UDPResolver,
			}
		case "gfw-filter", "cache":
			parents[name] = struct{}{}
			child, err := loadResolver(jr.Child)
			delete(parents, name)
			if err != nil {
				return nil, err
			}

			switch jr.Type {
			case "gfw-filter":
				resolver := GFWFilterResolver{Name: name, Child: child}
				for _, ipaddr := range cfg.GFWIPList {
					resolver.AddBlackIP(ipaddr)
				}
				res = &resolver
			case "cache":
				res = &CacheResolver{Name: name, Child: child}
			}
		case "parallel", "chain":
			children, err := loadChildren(jr.Children)
			if err != nil {
				return nil, err
			}

			switch jr.Type {
			case "parallel":
				res = &ParallelResolver{Name: name, Children: children}
			case "chain":
				res = &ChainResolver{Name: name, Children: children}
			}
		case "cn":
			CNList, err := loadChildren(jr.CNList)
			if err != nil {
				return nil, err
			}
			AbList, err := loadChildren(jr.AbList)
			if err != nil {
				return nil, err
			}

			resolver := CNResolver{
				Name:    name,
				CNList:  CNList,
				AbList:  AbList,
				Timeout: s.Timeout,
				MaxTTL:  jr.MaxTTL,
			}
			for _, ipaddr := range cfg.GFWIPList {
				resolver.AddBlackIP(ipaddr)
			}
			res = &resolver
		case "dyn":
			resolver := DynResolver{
				Name:            jr.Name,
				DBPath:          jr.DBPath,
				Suffixies:       jr.Suffixes,
				HTTPAddr:        jr.HTTPAddr,
				HTTPSAddr:       jr.HTTPSAddr,
				TLSCertFile:     jr.TLSCertFile,
				TLSKeyFile:      jr.TLSKeyFile,
				TLSClientCAFile: jr.TLSClientCAFile,
			}
			ctx := context.Background()
			if err = resolver.StartHTTP(ctx); err != nil {
				ctxlog.Errorf(ctx, "DynResolver.StartHTTP() error: %v", err)
				// ignore err
			}
			res = &resolver
		default:
			return nil, errors.Errorf("unknown resolver: %v", jr)
		}

		// ok
		name2resolver[name] = res
		return res, nil
	} // func loadResolver

	s.RootResolver, err = loadResolver("root")
	if err != nil {
		return nil, err
	}

	return s, nil
}
