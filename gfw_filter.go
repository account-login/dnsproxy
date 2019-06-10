package dnsproxy

import (
	"context"
	"github.com/pkg/errors"
	dm "golang.org/x/net/dns/dnsmessage"
	"net"
)

type GFWFilterResolver struct {
	Child Resolver
	Name  string
}

var ErrMaybePolluted = errors.New("result may be polluted")

func (r *GFWFilterResolver) GetName() string {
	return r.Name
}

func rr2ip(rr *dm.Resource) net.IP {
	switch rr.Header.Type {
	case dm.TypeA:
		return rr.Body.(*dm.AResource).A[:]
	case dm.TypeAAAA:
		return rr.Body.(*dm.AAAAResource).AAAA[:]
	default:
		return nil
	}
}

func isPolluted(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// FIXME: ipv6 data
	if len(ip) == 16 {
		return true
	}
	return !isCNIPV4(ip)
}

func (r *GFWFilterResolver) Resolve(ctx context.Context, req *dm.Message) (*dm.Message, error) {
	res, err := r.Child.Resolve(ctx, req)
	if err != nil {
		return res, err
	}
	if len(res.Answers) == 0 {
		return nil, ErrMaybePolluted
	}
	if len(res.Answers) == 1 && isPolluted(rr2ip(&res.Answers[0])) {
		return nil, ErrMaybePolluted
	}
	return res, err
}
