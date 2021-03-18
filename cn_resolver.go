package dnsproxy

import (
	"context"
	"github.com/account-login/ctxlog"
	dm "golang.org/x/net/dns/dnsmessage"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type CNResolver struct {
	Name    string
	CNList  []Resolver
	AbList  []Resolver
	Timeout time.Duration
	MaxTTL  uint32
	// private
	blackIPs map[string]bool
	// for sharing cache code
	cache CacheResolver
}

func (r *CNResolver) GetName() string {
	return r.Name
}

// FIXME: dup code
func (r *CNResolver) AddBlackIP(ipaddr string) {
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

type CNContext struct {
	// input
	ctx context.Context
	r   *CNResolver
	req *dm.Message
	// private
	mu     sync.Mutex
	gfwhit bool
	// the array of results
	res []*dm.Message
	err []error
	// the response
	idx     int
	answer  chan struct{}
	timeout bool
}

// server class
const (
	sCN = 1 << 4
	sAb = 2 << 4
)

// result class
const (
	rCN = 1
	rAb = 2
	rOt = 3
)

var classOrder = map[uint32]uint32{
	sCN | rCN: 1,
	sAb | rCN: 2,
	sAb | rAb: 3,
	sCN | rAb: 4,
	sAb | rOt: 5,
	sCN | rOt: 6,
}

func getResolverName(cnctx *CNContext, idx int) string {
	if idx < 0 {
		return "(None)"
	} else if idx < len(cnctx.r.CNList) {
		return cnctx.r.CNList[idx].GetName()
	} else {
		return cnctx.r.AbList[idx-len(cnctx.r.CNList)].GetName()
	}
}

// with lock
func CNUpdate(cnctx *CNContext) {
	ctx := cnctx.ctx
	candidates := make([]int, 0)
	classList := make([]uint32, len(cnctx.res))

	// for each result
	for idx := range cnctx.res {
		if cnctx.err[idx] != nil || cnctx.res[idx] == nil {
			continue
		}

		resClass := uint32(rOt)
		// for each rr, to determine the resClass
		for _, ans := range cnctx.res[idx].Answers {
			// TODO: dm.TypeAAAA
			if ans.Header.Type == dm.TypeA || ans.Header.Type == dm.TypeALL {
				// get ipv4
				ip := rr2ip(&ans)
				if ip4 := ip.To4(); ip4 != nil {
					ip = ip4
				}
				if len(ip) != 4 {
					continue // TODO: dm.TypeAAAA
				}

				// check gfw
				if cnctx.r.blackIPs[string(ip)] {
					ctxlog.Debugf(ctx, "gfw hit by [name:%s][ip:%s]",
						getResolverName(cnctx, idx), ip.String())
					cnctx.err[idx] = ErrMaybePolluted
					cnctx.gfwhit = true
					break
				}
				// use the first ip for result class
				if resClass == rOt {
					if isCNIPV4(ip) {
						resClass = rCN
					} else {
						resClass = rAb
					}
				}
			} // if type A
			// other types are classified as rOt
		} // for each rr

		if cnctx.err[idx] != nil {
			continue // gfw hit
		}

		// add candidates
		candidates = append(candidates, idx)
		srvClass := uint32(0)
		if idx < len(cnctx.r.CNList) {
			srvClass = sCN
		} else {
			srvClass = sAb
		}
		classList[idx] = srvClass | resClass
	} // for each result

	// choose the candidate
	winner := -1
	winScore := ^uint32(0)
	for _, idx := range candidates {
		if classOrder[classList[idx]] < winScore {
			winner = idx
			winScore = classOrder[classList[idx]]
		}
	}

	if winner < 0 {
		return // no canditates, nothing to do
	}

	// should we waiting for more responses from CNList or AbList?
	needMore := func(begin, end int) bool {
		for i := begin; i < end; i++ {
			if cnctx.res[i] != nil && cnctx.err[i] == nil {
				return false // done
			}
		}
		for i := begin; i < end; i++ {
			if cnctx.res[i] == nil && cnctx.err[i] == nil {
				return true // pending
			}
		}
		return false // not done and no pending
	}

	prevIdx := cnctx.idx
	alreadyAnswered := cnctx.idx >= 0
	CNHit := classList[winner]&0xf == rCN
	noNeedMore := (cnctx.gfwhit || !needMore(0, len(cnctx.r.CNList))) &&
		!needMore(len(cnctx.r.CNList), len(cnctx.r.CNList)+len(cnctx.r.AbList))
	shouldAnswer := !alreadyAnswered && (CNHit || noNeedMore || cnctx.timeout)
	// update cache (maybe after response)
	if prevIdx != winner {
		cnctx.r.cache.set(cnctx.req, cnctx.res[winner])
	}
	// response
	if shouldAnswer {
		cnctx.idx = winner
		close(cnctx.answer)
	}
	// log
	ctxlog.Debugf(ctx, "[prev:%v][cur:%v] [win:%v][win_cls:%x] [cn_hit:%d][no_need_more:%d][timeout:%d][should_ans:%d]",
		getResolverName(cnctx, prevIdx), getResolverName(cnctx, cnctx.idx),
		getResolverName(cnctx, winner), classList[winner],
		b2i(CNHit), b2i(noNeedMore), b2i(cnctx.timeout), b2i(shouldAnswer),
	)
}

func fixMaxTTL(maxTTL uint32, res *dm.Message) uint32 {
	newTTL := uint32(0)
	for _, ans := range res.Answers {
		if ans.Header.TTL > 0 {
			newTTL = ans.Header.TTL
			break
		}
	}

	if maxTTL == 0 {
		return newTTL
	}

	if newTTL > maxTTL {
		newTTL = maxTTL
		for i := range res.Answers {
			res.Answers[i].Header.TTL = newTTL // FIXME: race
		}
	}
	return newTTL
}

func (r *CNResolver) Resolve(ctx context.Context, req *dm.Message) (*dm.Message, error) {
	// cache
	if reqShouldCache(req) {
		item, ok := r.cache.get(req)
		// hit
		if ok {
			newTTL := fixMaxTTL(r.MaxTTL, &item.res)
			ctxlog.Debugf(ctx, "cache hit: [key:%d:%s][ttl:%v]",
				req.Questions[0].Type, req.Questions[0].Name, newTTL)
			return &item.res, nil
		}
	}

	cnctx := &CNContext{
		ctx:    ctx,
		r:      r,
		req:    req,
		res:    make([]*dm.Message, len(r.CNList)+len(r.AbList)),
		err:    make([]error, len(r.CNList)+len(r.AbList)),
		idx:    -1,
		answer: make(chan struct{}),
	}

	// only cancelled after all children were done
	childCtx, childCancel := context.WithTimeout(context.Background(), r.Timeout)
	childCtx = ctxlog.Push(childCtx, ctxlog.Ctx(ctx))
	childRemains := int32(len(r.CNList) + len(r.AbList))
	childDone := func() {
		if 0 == atomic.AddInt32(&childRemains, -1) {
			childCancel()
		}
	}
	childFunc := func(i int, resolver Resolver) {
		defer childDone()
		res, err := resolver.Resolve(childCtx, req)

		cnctx.mu.Lock()
		defer cnctx.mu.Unlock()
		cnctx.res[i] = res
		cnctx.err[i] = err
		CNUpdate(cnctx)
	}

	// cn list
	for i, resolver := range r.CNList {
		go childFunc(i, resolver)
	}
	// ab list
	for i, resolver := range r.AbList {
		go childFunc(len(r.CNList)+i, resolver)
	}

	// answer
	select {
	case <-cnctx.answer:
		break
	case <-time.After(r.Timeout):
		// timeout, must make decision
		cnctx.mu.Lock()
		cnctx.timeout = true
		CNUpdate(cnctx)
		cnctx.mu.Unlock()
	}
	if cnctx.idx < 0 {
		return nil, ErrNoResult // TODO: select a error response
	}
	_ = fixMaxTTL(r.MaxTTL, cnctx.res[cnctx.idx])
	return cnctx.res[cnctx.idx], cnctx.err[cnctx.idx]
}
