package dnsproxy

import (
	"context"
	"github.com/account-login/ctxlog"
	"github.com/pkg/errors"
	dm "golang.org/x/net/dns/dnsmessage"
)

type ParallelResolver struct {
	Children []Resolver
	Name     string
}

var ErrNoResult = errors.New("no result selected")

func (r *ParallelResolver) Resolve(ctx context.Context, req *dm.Message) (*dm.Message, error) {
	ctx = ctxlog.Pushf(ctx, "[parallel:%v]", r.Name)

	errs := make([]error, len(r.Children))
	replies := make([]*dm.Message, len(r.Children))
	notifify := make(chan int, 0)

	for idx := range r.Children {
		go func(idx int) {
			cr := r.Children[idx]
			replies[idx], errs[idx] = cr.Resolve(ctx, req)
			if errs[idx] != nil {
				ctxlog.Infof(ctx, "[child:%v] error: %v", cr.GetName(), errs[idx])
			}
			notifify <- idx
		}(idx)
	}

	done := make([]bool, len(r.Children))
	for idx := range notifify {
		done[idx] = true

		doneCnt := 0
		cls2 := -1
		cls3 := -1
		for idx, ok := range done {
			if !ok {
				continue
			}

			// the first non-empty reply
			if errs[idx] == nil && len(replies[idx].Answers) > 0 {
				ctxlog.Debugf(ctx, "[picked:%v]", r.Children[idx].GetName())
				return replies[idx], nil
			}
			// empty reply
			if cls2 < 0 && errs[idx] == nil {
				cls2 = idx
			}
			// error reply
			if cls3 < 0 && replies[idx] != nil {
				cls3 = idx
			}

			doneCnt++
		}

		if doneCnt == len(r.Children) {
			// all kids done
			var reply *dm.Message
			if cls3 >= 0 {
				reply = replies[cls3]
			}
			if cls2 >= 0 {
				reply = replies[cls2]
			}

			ctxlog.Debugf(ctx, "no result")
			return reply, ErrNoResult
		}
	}
	panic("Unreachable")
}

func (r *ParallelResolver) GetName() string {
	return r.Name
}
