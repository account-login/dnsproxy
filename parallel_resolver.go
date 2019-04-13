package dnsproxy

import (
	"context"
	"github.com/account-login/ctxlog"
	"github.com/pkg/errors"
	dm "golang.org/x/net/dns/dnsmessage"
	"sync/atomic"
)

type ParallelResolver struct {
	Children []Resolver
	Name     string
}

var ErrNoResult = errors.New("no result selected")

func (r *ParallelResolver) Resolve(ctx context.Context, req *dm.Message) (*dm.Message, error) {
	ctx = ctxlog.Pushf(ctx, "[parallel:%v]", r.Name)

	ch := make(chan *dm.Message, 0)
	remains := int32(len(r.Children))
	for _, cr := range r.Children {
		go func(cr Resolver) {
			defer func() {
				cur := atomic.AddInt32(&remains, -1)
				if cur == 0 {
					ch <- nil // no result
				}
			}()

			res, err := cr.Resolve(ctx, req)
			if err != nil {
				ctxlog.Infof(ctx, "[child:%v] error: %v", cr.GetName(), err)
				return
			}

			select {
			case ch <- res:
				ctxlog.Debugf(ctx, "[picked:%v]", cr.GetName())
			default:
				// pass
			}
		}(cr)
	}

	res := <-ch
	if res == nil {
		ctxlog.Debugf(ctx, "no result")
		return nil, ErrNoResult
	} else {
		return res, nil
	}
}

func (r *ParallelResolver) GetName() string {
	return r.Name
}
