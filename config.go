package dnsproxy

import (
	"encoding/json"
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
		Addr     string   `json:"addr,omitempty"`
		Child    string   `json:"child,omitempty"`
		Children []string `json:"children,omitempty"`
	}
	type jsonConfig struct {
		Listen    string         `json:"listen"`
		TimeoutMS int64          `json:"timeout_ms"`
		Resolvers []jsonResolver `json:"resolvers"`
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
				res = &GFWFilterResolver{Name: name, Child: child}
			case "cache":
				res = &CacheResolver{Name: name, Child: child}
			}
		case "parallel", "chain":
			children := make([]Resolver, 0)
			var err error

			parents[name] = struct{}{}
			for _, childName := range jr.Children {
				var child Resolver
				child, err = loadResolver(childName)
				if err != nil {
					break
				}

				children = append(children, child)
			}
			delete(parents, name)

			if err != nil {
				return nil, err
			}

			switch jr.Type {
			case "parallel":
				res = &ParallelResolver{Name: name, Children: children}
			case "chain":
				res = &ChainResolver{Name: name, Children: children}
			}
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
