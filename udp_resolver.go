package dnsproxy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"github.com/account-login/ctxlog"
	"github.com/pkg/errors"
	dm "golang.org/x/net/dns/dnsmessage"
	"net"
	"sync"
	"sync/atomic"
)

type UDPResolver struct {
	// params
	Local string
	// private
	conn    net.PacketConn
	txid    uint32
	txid2ch sync.Map
	quit    int32
	exited  chan struct{}
}

type RemoteBindedUDPResolver struct {
	Remote *net.UDPAddr
	*UDPResolver
	Name string
}

func (r *RemoteBindedUDPResolver) Resolve(ctx context.Context, req *dm.Message) (*dm.Message, error) {
	ctx = ctxlog.Pushf(ctx, "[UDP:%v][remote:%v]", r.Name, r.Remote)
	return r.UDPResolver.Resolve(ctx, r.Remote, req)
}

func (r *RemoteBindedUDPResolver) GetName() string {
	return r.Name
}

func (r *UDPResolver) Start() error {
	// listen
	if r.Local == "" {
		r.Local = ":0"
	}
	conn, err := net.ListenPacket("udp", r.Local)
	if err != nil {
		return err
	}
	r.conn = conn

	// init txid
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	r.txid = binary.LittleEndian.Uint32(buf[:])

	// init channels
	r.exited = make(chan struct{}, 0)

	// reader loop
	go func() {
		defer close(r.exited)

		session := 0
		buf := make([]byte, 64*1024)
		for {
			session += 1
			ctx := ctxlog.Pushf(context.Background(), "[reader:%v]", session)

			// read
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				ctxlog.Errorf(ctx, "UDPResolver ReadFrom: %v", err)
				if atomic.LoadInt32(&r.quit) != 0 {
					break
				} else {
					continue
				}
			}

			// parse
			m := &dm.Message{}
			err = m.Unpack(buf[:n])
			if err != nil {
				ctxlog.Warnf(ctx, "UDPResolver Unpack: %v", err)
				continue
			}

			// post
			if v, ok := r.txid2ch.Load(m.ID); ok {
				ctxlog.Debugf(ctx, "got msg from [remote:%v] %v", addr, ReprMessageShort(m))
				ch := v.(chan *dm.Message)
				select {
				case ch <- m:
					// pass
				default:
					ctxlog.Errorf(ctx, "channel for [txid:%v] full. [remote:%v]", m.ID, addr)
				}
			} else {
				ctxlog.Warnf(ctx, "unknown [txid:%v] from [remote:%v] %v",
					m.ID, addr, ReprMessageShort(m))
				continue
			}
		}
	}()

	return nil
}

func (r *UDPResolver) Stop() {
	atomic.StoreInt32(&r.quit, 1)
	_ = r.conn.Close()
	r.txid2ch.Range(func(key, value interface{}) bool { r.txid2ch.Delete(key); return true })
}

func (r *UDPResolver) Wait() {
	<-r.exited
}

func (r *UDPResolver) Resolve(
	ctx context.Context, remote *net.UDPAddr, req *dm.Message) (
	*dm.Message, error) {

	// txid
	txid := uint16(atomic.AddUint32(&r.txid, 1))
	originID := req.ID

	// listen for ID
	ch := make(chan *dm.Message, 1)
	r.txid2ch.Store(txid, ch)
	defer r.txid2ch.Delete(txid)

	// send request
	newReq := *req
	newReq.ID = txid
	buf, err := newReq.Pack()
	if err != nil {
		return nil, errors.Wrap(err, "req.Pack()")
	}
	_, err = r.conn.WriteTo(buf, remote)
	if err != nil {
		return nil, errors.Wrap(err, "r.conn.WriteTo()")
	}

	// TODO: retry

	// wait for response
	select {
	case <-ctx.Done():
		ctxlog.Debugf(ctx, "abandoned: %v", ctx.Err())
		return nil, ctx.Err()
	case res := <-ch:
		// modify ID
		res.ID = originID
		return res, nil
	}
}
