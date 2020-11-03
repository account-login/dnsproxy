package dnsproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/account-login/ctxlog"
	dm "golang.org/x/net/dns/dnsmessage"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type DynResolver struct {
	Name     string
	DBPath   string
	HTTPAddr string
	// private
	mu       sync.Mutex
	ts       time.Time
	name2ip4 map[string]net.IP
	name2ip6 map[string]net.IP
	name2ttl map[string]uint32 // FIXME: v4 v6
	config   dynConfig
}

func (r *DynResolver) GetName() string {
	return r.Name
}

type dynItem struct {
	// input
	Name string
	Addr string
	TTL  uint32
	// stats
	Updated uint64 // in us
}

type dynConfig struct {
	Items []dynItem
}

// from https://github.com/asaskevich/govalidator/blob/50839af6027e22ff776fa2a99a9c164e10002119/patterns.go#L33
var reDomainName = regexp.MustCompile(
	`^([a-zA-Z0-9_][a-zA-Z0-9_-]{0,62})(\.[a-zA-Z0-9_][a-zA-Z0-9_-]{0,62})*[._]?$`,
)

func domainNormalize(s string) string {
	if len(s) == 0 {
		return ""
	}
	if s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	if !reDomainName.MatchString(s) {
		return ""
	}
	return strings.ToLower(s)
}

func parseItem(ctx context.Context, item dynItem) (name string, ip net.IP) {
	name = domainNormalize(item.Name)
	if name == "" {
		ctxlog.Errorf(ctx, "bad name: %q", item.Name)
		return "", nil
	}
	ip = net.ParseIP(item.Addr)
	if ip == nil {
		ctxlog.Errorf(ctx, "bad ip: %q", item.Addr)
		return "", nil
	}

	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return name, ip
}

func reloadDB(ctx context.Context, r *DynResolver) error {
	ctx = ctxlog.Push(ctx, "[reloadDB]")

	r.mu.Lock()
	if r.ts.Add(5 * time.Second).After(time.Now()) {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()
	ctxlog.Debugf(ctx, "start reload DB")

	fp, err := os.OpenFile(r.DBPath, os.O_CREATE|os.O_RDWR, 0o664)
	if err != nil {
		return err
	}
	defer safeClose(ctx, fp)

	data, err := ioutil.ReadAll(fp)
	if err != nil {
		return err
	}

	config := dynConfig{}
	if len(data) > 0 { // allow empty file
		err = json.Unmarshal(data, &config)
		if err != nil {
			return err
		}
	}

	v4 := map[string]net.IP{}
	v6 := map[string]net.IP{}
	ttl := map[string]uint32{}
	for i, item := range config.Items {
		name, ip := parseItem(ctx, item)
		if ip == nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			v4[name] = ip4
			ip = ip4
		} else {
			v6[name] = ip
		}
		ttl[name] = item.TTL
		// normalize items
		config.Items[i].Name = name
	}

	// ok
	r.mu.Lock()
	r.name2ip4 = v4
	r.name2ip6 = v6
	r.name2ttl = ttl
	r.config = config
	r.ts = time.Now()
	r.mu.Unlock()
	return nil
}

func updateDB(ctx context.Context, r *DynResolver, name string, ip net.IP, ttl uint32) error {
	ctx = ctxlog.Pushf(ctx, "[updateDB][name:%s][ip:%s]", name, ip)
	ctxlog.Infof(ctx, "[ttl:%v]", ttl)

	_ = reloadDB(ctx, r)

	r.mu.Lock()
	defer r.mu.Unlock()

	// update map
	if ip4 := ip.To4(); ip4 != nil {
		if r.name2ip4 == nil {
			r.name2ip4 = map[string]net.IP{}
		}
		r.name2ip4[name] = ip4
		ip = ip4
	} else {
		if r.name2ip6 == nil {
			r.name2ip6 = map[string]net.IP{}
		}
		r.name2ip6[name] = ip
	}
	if r.name2ttl == nil {
		r.name2ttl = map[string]uint32{}
	}
	r.name2ttl[name] = ttl

	// update json config
	at := -1
	for i := range r.config.Items {
		if r.config.Items[i].Name != name {
			continue
		}
		prev := net.ParseIP(r.config.Items[i].Addr)
		if (prev.To4() != nil) == (ip.To4() != nil) {
			at = i
			break
		}
	}
	if at < 0 {
		at = len(r.config.Items)
		r.config.Items = append(r.config.Items, dynItem{})
	}
	r.config.Items[at].Name = name
	r.config.Items[at].Addr = ip.String()
	r.config.Items[at].TTL = ttl
	r.config.Items[at].Updated = uint64(time.Now().UnixNano() / 1000)

	// save to file
	tmpFile := r.DBPath + fmt.Sprintf(".tmp.pid.%v", os.Getpid())
	fp, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o664)
	if err != nil {
		ctxlog.Errorf(ctx, "can not create tmp [file:%s] err: %v", tmpFile, err)
		return err
	}
	defer func() {
		if fp != nil {
			safeClose(ctx, fp)
		}
	}()

	encoder := json.NewEncoder(fp)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(&r.config)
	if err != nil {
		ctxlog.Errorf(ctx, "json encode: %v", err)
		return err
	}
	safeClose(ctx, fp) // can not rename opened file on windows
	fp = nil

	err = os.Rename(tmpFile, r.DBPath)
	if err != nil {
		ctxlog.Errorf(ctx, "rename tmp file: %v", err)
		// try to remove tmp file
		_ = os.Remove(tmpFile)
		return err
	}
	return nil
}

func resolveDB(ctx context.Context, r *DynResolver, q *dm.Question, rrList []dm.Resource) []dm.Resource {
	// reload db
	err := reloadDB(ctx, r)
	if err != nil {
		ctxlog.Errorf(ctx, "reloadDB: %v", err)
		// ignore err
	}

	switch q.Type {
	case dm.TypeA, dm.TypeAAAA, dm.TypeALL:
		qname := bytes.ToLower(q.Name.Data[:q.Name.Length])
		if len(qname) > 0 && qname[len(qname)-1] == '.' {
			qname = qname[:len(qname)-1]
		}

		r.mu.Lock()
		ip4 := r.name2ip4[string(qname)].To4()
		ip6 := r.name2ip6[string(qname)]
		ttl := r.name2ttl[string(qname)]
		r.mu.Unlock()

		for _, ip := range [2]net.IP{ip4, ip6} {
			if ip == nil {
				continue
			}

			var ipType dm.Type
			if ip.To4() != nil {
				ipType = dm.TypeA
			} else {
				ipType = dm.TypeAAAA
			}

			if q.Type != dm.TypeALL && q.Type != ipType {
				continue
			}
			ctxlog.Infof(ctx, "[dyn] hit %s -> %s", qname, ip)

			rr := dm.Resource{
				Header: dm.ResourceHeader{
					Name:  q.Name,
					Type:  ipType,
					Class: q.Class,
					TTL:   ttl,
				},
			}

			switch ipType {
			case dm.TypeA:
				rb := &dm.AResource{}
				rr.Body = rb
				copy(rb.A[:], ip)
			case dm.TypeAAAA:
				rb := &dm.AAAAResource{}
				rr.Body = rb
				copy(rb.AAAA[:], ip)
			}

			rrList = append(rrList, rr)
		}
	}

	return rrList
}

func (r *DynResolver) Resolve(ctx context.Context, req *dm.Message) (*dm.Message, error) {
	var rrList []dm.Resource
	for i := range req.Questions {
		rrList = resolveDB(ctx, r, &req.Questions[i], rrList)
	}

	if len(rrList) == 0 {
		return nil, ErrNoResult
	}

	m := &dm.Message{
		Header:  dm.Header{ID: req.ID, Response: true, RecursionAvailable: true},
		Answers: rrList,
	}
	return m, nil
}

func response(rw http.ResponseWriter, errCode int, msg string) {
	rw.WriteHeader(http.StatusBadRequest)
	obj := map[string]interface{}{
		"err": errCode,
		"msg": msg,
	}
	data, _ := json.Marshal(obj)
	data = append(data, '\n')
	_, _ = rw.Write(data)
}

// http handler
func (r *DynResolver) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	ctx = ctxlog.Pushf(ctx, "[ServeHTTP][remove:%v]", req.RemoteAddr)

	if req.URL.Path != "/update_dyn" || req.Method != "POST" {
		ctxlog.Warnf(ctx, "bad [uri:%s] or [method:%s]", req.URL.Path, req.Method)
		response(rw, -1, "bad req")
		return
	}

	item := dynItem{}
	decoder := json.NewDecoder(req.Body)
	if err := decoder.Decode(&item); err != nil {
		ctxlog.Warnf(ctx, "json Decode() err: %v", err)
		response(rw, -1, "bad req")
		return
	}

	name, ip := parseItem(ctx, item)
	if ip == nil {
		ctxlog.Warnf(ctx, "can not parseItem()")
		response(rw, -1, "bad params")
		return
	}

	if err := updateDB(ctx, r, name, ip, item.TTL); err != nil {
		ctxlog.Warnf(ctx, "updateDB() error: %v", err)
		response(rw, -1, "error")
		return
	}

	// ok
	response(rw, 0, "OK")
}

// TODO: https and client cert
func (r *DynResolver) StartHTTP(ctx context.Context) error {
	if r.HTTPAddr == "" {
		return nil
	}

	server := http.Server{
		Addr:    r.HTTPAddr,
		Handler: r,
	}

	go func() {
		err := server.ListenAndServe()
		if err != nil {
			ctxlog.Errorf(ctx, "DynResolver.StartHTTP: %v", err)
		}
	}()
	return nil
}
