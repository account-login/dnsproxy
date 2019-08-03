package dnsproxy

import (
	"context"
	"github.com/account-login/ctxlog"
	"github.com/account-login/dnsproxy/hosts"
	dm "golang.org/x/net/dns/dnsmessage"
	"net"
)

type HostsResolver struct {
	Name string
}

func (r *HostsResolver) GetName() string {
	return r.Name
}

func resolveHosts(ctx context.Context, q *dm.Question, rrList []dm.Resource) []dm.Resource {
	switch q.Type {
	case dm.TypeA, dm.TypeAAAA, dm.TypeALL:
		qname := string(q.Name.Data[:q.Name.Length])
		addrList := hosts.LookupStaticHost(qname)
		for _, addr := range addrList {
			ip := net.ParseIP(addr)
			if ip == nil {
				ctxlog.Warnf(ctx, "bad ip: %v", addr)
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
			ctxlog.Infof(ctx, "[hosts] hit %v -> %v", qname, ip)

			rr := dm.Resource{
				Header: dm.ResourceHeader{
					Name:  q.Name,
					Type:  ipType,
					Class: q.Class,
					TTL:   uint32(hosts.CacheMaxAge.Seconds()),
				},
			}

			switch ipType {
			case dm.TypeA:
				rb := &dm.AResource{}
				rr.Body = rb
				copy(rb.A[:], ip.To4())
			case dm.TypeAAAA:
				rb := &dm.AAAAResource{}
				rr.Body = rb
				copy(rb.AAAA[:], ip.To16())
			}

			rrList = append(rrList, rr)
		}
	}

	return rrList
}

func (r *HostsResolver) Resolve(ctx context.Context, req *dm.Message) (*dm.Message, error) {
	var rrList []dm.Resource
	for i := range req.Questions {
		rrList = resolveHosts(ctx, &req.Questions[i], rrList)
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
