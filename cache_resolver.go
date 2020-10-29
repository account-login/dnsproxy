package dnsproxy

import (
	"container/heap"
	"context"
	"fmt"
	"github.com/account-login/ctxlog"
	dm "golang.org/x/net/dns/dnsmessage"
	"sync"
	"time"
)

type CacheResolver struct {
	Child Resolver
	Name  string
	// key: type + name
	cache map[string]cacheItem
	heap  cacheHeap
	mu    sync.Mutex
}

type cacheItem struct {
	expireNs int64
	res      dm.Message
}

type heapItem struct {
	expireNs int64
	key      string
}

type cacheHeap []heapItem

func (h *cacheHeap) Push(x interface{}) {
	*h = append(*h, x.(heapItem))
}

func (h *cacheHeap) Pop() interface{} {
	x := (*h)[len(*h)-1]
	*h = (*h)[:len(*h)-1]
	return x
}

func (h cacheHeap) Len() int {
	return len(h)
}

func (h cacheHeap) Less(i, j int) bool {
	return h[i].expireNs < h[j].expireNs
}

func (h cacheHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (r *CacheResolver) GetName() string {
	return r.Name
}

func reqShouldCache(req *dm.Message) bool {
	if len(req.Questions) != 1 {
		return false
	}
	typ := req.Questions[0].Type
	return typ == dm.TypeA || typ == dm.TypeAAAA || typ == dm.TypeALL
}

func (r *CacheResolver) get(req *dm.Message) (cacheItem, bool) {
	nowNs := time.Now().UnixNano()
	key := fmt.Sprintf("%d:%s", req.Questions[0].Type, req.Questions[0].Name)

	r.mu.Lock()
	// expire cache
	for len(r.heap) > 0 && r.heap[0].expireNs <= nowNs {
		hi := heap.Pop(&r.heap).(heapItem)
		delete(r.cache, hi.key)
	}
	// get cache
	item, ok := r.cache[key]
	r.mu.Unlock()

	// hit
	if ok {
		// id
		item.res.ID = req.ID
		// update TTL
		newTTL := (item.expireNs - nowNs) / 1e9
		for i := range item.res.Answers {
			item.res.Answers[i].Header.TTL = uint32(newTTL) // FIXME: race
		}
	}

	return item, ok
}

func (r *CacheResolver) set(req *dm.Message, res *dm.Message) {
	if len(res.Answers) == 0 {
		return // negative response, or uncommon type. not worth caching
	}

	nowNs := time.Now().UnixNano()
	key := fmt.Sprintf("%d:%s", req.Questions[0].Type, req.Questions[0].Name)

	// FIXME: assume TTL is same for all answers
	expireNs := nowNs + int64(res.Answers[0].Header.TTL)*1e9

	r.mu.Lock()
	if r.cache == nil {
		r.cache = map[string]cacheItem{}
	}
	r.cache[key] = cacheItem{expireNs: expireNs, res: *res}
	heap.Push(&r.heap, heapItem{expireNs: expireNs, key: key})
	r.mu.Unlock()
}

func (r *CacheResolver) Resolve(ctx context.Context, req *dm.Message) (*dm.Message, error) {
	if !reqShouldCache(req) {
		return r.Child.Resolve(ctx, req)
	}

	item, ok := r.get(req)

	// hit
	if ok {
		key := fmt.Sprintf("%d:%s", req.Questions[0].Type, req.Questions[0].Name)
		newTTL := item.res.Answers[0].Header.TTL
		ctxlog.Debugf(ctx, "cache hit: [key:%s][ttl:%v]", key, newTTL)
		return &item.res, nil
	}

	// miss
	res, err := r.Child.Resolve(ctx, req)
	if err != nil {
		return nil, err
	}

	// write cache
	if len(res.Answers) > 0 && res.Answers[0].Header.TTL > 0 {
		r.set(req, res)
	}

	return res, err
}
