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
	// private
	blackIPs map[string]bool
}

var ErrMaybePolluted = errors.New("result may be polluted")

func (r *GFWFilterResolver) GetName() string {
	return r.Name
}

func (r *GFWFilterResolver) AddBlackIP(ipaddr string) {
	ip := net.ParseIP(ipaddr)
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	if ip == nil {
		return
	}
	if r.blackIPs == nil {
		r.blackIPs = map[string]bool{}
	}
	r.blackIPs[string(ip)] = true
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
	if len(res.Answers) == 1 {
		ip := rr2ip(&res.Answers[0])
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		}
		if isPolluted(ip) || r.blackIPs[string(ip)] {
			return nil, ErrMaybePolluted
		}
	}
	return res, err
}
