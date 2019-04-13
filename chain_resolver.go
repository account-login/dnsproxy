package dnsproxy

import (
	"context"
	"github.com/account-login/ctxlog"
	dm "golang.org/x/net/dns/dnsmessage"
)

type ChainResolver struct {
	Children []Resolver
	Name     string
}

func (r *ChainResolver) GetName() string {
	return r.Name
}

func (r *ChainResolver) Resolve(ctx context.Context, req *dm.Message) (*dm.Message, error) {
	ctx = ctxlog.Pushf(ctx, "[chain:%v]", r.Name)

	for _, cr := range r.Children {
		m, err := cr.Resolve(ctx, req)
		if err != nil {
			ctxlog.Debugf(ctx, "[child:%v] error: %v", cr.GetName(), err)
			continue
		}

		return m, err
	}

	return nil, ErrNoResult
}
