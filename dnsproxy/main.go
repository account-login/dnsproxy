package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/account-login/ctxlog"
	"github.com/account-login/dnsproxy"
	"github.com/account-login/dnsproxy/dns"
	"golang.org/x/net/dns/dnsmessage"
)

// TODO: rtt metric
// TODO: tcp resolver
// TODO: adblock
// TODO: ipv6 pollution
// FIXME: dnsmessage.Message.Pack() is not thread safe
// FIXME: unpacking Answer: invalid resource type: ı

func questionRepr(m *dnsmessage.Message) string {
	if len(m.Questions) > 0 {
		return dnsproxy.ReprQuestionShort(&m.Questions[0])
	} else {
		return "[NOT-QUESTION]"
	}
}

type serverState struct {
	// for logging
	session uint64
	// tcp listener
	listener net.Listener
	// udp conn
	conn net.PacketConn

	// for gracefull shutdown
	quit       bool
	cond       sync.Cond
	concurency int
}

func newServerState() *serverState {
	s := &serverState{}
	s.cond.L = &sync.Mutex{}
	return s
}

func (s *serverState) inc() {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	s.concurency += 1
}

func (s *serverState) dec() {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	s.concurency -= 1
	if s.concurency < 0 {
		panic("s.concurency < 0")
	}
	if s.concurency == 0 {
		s.cond.Signal()
	}
}

func (s *serverState) exiting() bool {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	return s.quit
}

func (s *serverState) close(ctx context.Context) {
	s.cond.L.Lock()
	s.quit = true
	s.cond.L.Unlock()

	safeClose(ctx, s.listener)
	safeClose(ctx, s.conn)
}

func (s *serverState) wait() {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	for s.concurency != 0 {
		s.cond.Wait()
	}
}

func initUDP(ctx context.Context, server *dnsproxy.Server, state *serverState) {
	// listen for udp reply
	err := server.UDPResolver.Start()
	if err != nil {
		ctxlog.Fatal(ctx, err)
	}

	// listen for udp client
	state.conn, err = net.ListenPacket("udp", server.Listen)
	if err != nil {
		ctxlog.Fatal(ctx, err)
	}
	ctxlog.Infof(ctx, "udp server listening on %v", state.conn.LocalAddr())
}

func errReply(req *dnsmessage.Message) *dnsmessage.Message {
	return &dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:    req.ID,
			RCode: dnsmessage.RCodeNameError,
			// flags
			Authoritative: false, Response: true, RecursionDesired: true,
		},
		Questions: req.Questions,
	}
}

func doUDP(ctx context.Context, server *dnsproxy.Server, state *serverState) {
	defer state.dec()
	defer server.UDPResolver.Wait()
	defer server.UDPResolver.Stop()

	conn := state.conn.(*net.UDPConn)
	if err := dns.SetSessionUDPOptions(conn); err != nil {
		ctxlog.Errorf(ctx, "dns.SetSessionUDPOptions: %v", err)
		// ignore err
	}

	// loop for udp client
	buf := make([]byte, 64*1024)
	for {
		ctx := ctxlog.Pushf(ctx, "[session:%v]", atomic.AddUint64(&state.session, 1))

		// read from client
		n, sess, err := dns.ReadFromSessionUDP(conn, buf)
		if err == io.EOF {
			ctxlog.Infof(ctx, "server eof")
			break
		}
		if err != nil {
			ctxlog.Errorf(ctx, "conn.ReadFrom(): %v", err)
			if state.exiting() {
				break
			} else {
				continue
			}
		}
		ctx = ctxlog.Pushf(ctx, "[client:%v]", sess.RemoteAddr())

		// parse req
		m := &dnsmessage.Message{}
		err = m.Unpack(buf[:n])
		if err != nil {
			ctxlog.Warnf(ctx, "unpack: %v", err)
			continue
		}

		// log
		ctx = ctxlog.Push(ctx, questionRepr(m))
		ctxlog.Infof(ctx, "req: %v", dnsproxy.ReprMessageShort(m))

		// resolve and reply
		state.inc()
		go func(sess *dns.SessionUDP) {
			defer state.dec()

			ctx, cancel := context.WithTimeout(ctx, server.Timeout)
			defer cancel()

			// resolve
			res, err := server.RootResolver.Resolve(ctx, m)
			if err != nil {
				ctxlog.Errorf(ctx, "server.RootResolver.Resolve: %v", err)
			}

			// log
			ctxlog.Infof(ctx, "res: %v", dnsproxy.ReprMessageShort(res))

			// generate error reply
			if res == nil {
				res = errReply(m)
			}

			// pack result
			buf, err := res.Pack()
			if err != nil {
				ctxlog.Errorf(ctx, "res.Pack(): %v", err)
				return
			}

			// reply client
			_, err = dns.WriteToSessionUDP(conn, buf, sess)
			if err != nil {
				ctxlog.Errorf(ctx, "conn.WriteTo(): %v", err)
				return
			}
		}(sess)
	} // loop for req
}

func safeClose(ctx context.Context, closer io.Closer) {
	err := closer.Close()
	if err != nil {
		ctxlog.Errorf(ctx, "close: %v", err)
	}
}

func initTCP(ctx context.Context, server *dnsproxy.Server, state *serverState) {
	// listen
	var err error
	state.listener, err = net.Listen("tcp", server.Listen)
	if err != nil {
		ctxlog.Fatal(ctx, err)
	}

	ctxlog.Infof(ctx, "tcp server listening on %v", state.listener.Addr())
}

func doTCP(ctx context.Context, server *dnsproxy.Server, state *serverState) {
	defer state.dec()
	//defer safeClose(ctx, state.listener)

	for {
		ctx := ctxlog.Pushf(ctx, "[session:%v]", atomic.AddUint64(&state.session, 1))

		// accept
		conn, err := state.listener.Accept()
		if err != nil {
			ctxlog.Errorf(ctx, "accept: %v", err)
			if state.exiting() {
				break
			} else {
				continue
			}
		}

		state.inc()
		go func(conn net.Conn) {
			defer state.dec()
			defer safeClose(ctx, conn)

			ctx := ctxlog.Pushf(ctx, "[client:%v]", conn.RemoteAddr())

			// TODO: try sync.Pool?
			rbuf := bufio.NewReaderSize(conn, 64*1024)
			buf := make([]byte, 64*1024)
			for {
				// read len field
				_, err := io.ReadFull(rbuf, buf[:2])
				if err == io.EOF {
					ctxlog.Infof(ctx, "client leave")
					break
				}

				// read body
				length := binary.BigEndian.Uint16(buf[:2])
				_, err = io.ReadFull(rbuf, buf[:length])
				if err != nil {
					ctxlog.Errorf(ctx, "read body: %v", err)
					break
				}

				// parse req
				m := &dnsmessage.Message{}
				err = m.Unpack(buf[:length])
				if err != nil {
					ctxlog.Warnf(ctx, "unpack: %v", err)
					break
				}

				// log
				ctx = ctxlog.Push(ctx, questionRepr(m))
				ctxlog.Infof(ctx, "req: %v", dnsproxy.ReprMessageShort(m))

				func() {
					ctx, cancel := context.WithTimeout(ctx, server.Timeout)
					defer cancel()

					// resolve
					res, err := server.RootResolver.Resolve(ctx, m)
					if err != nil {
						ctxlog.Errorf(ctx, "server.RootResolver.Resolve: %v", err)
					}

					// log
					ctxlog.Infof(ctx, "res: %v", dnsproxy.ReprMessageShort(res))

					// generate error reply
					if res == nil {
						res = errReply(m)
					}

					// pack result
					rpack := buf[:2]
					rpack, err = res.AppendPack(rpack)
					if err != nil {
						ctxlog.Errorf(ctx, "res.Pack(): %v", err)
						return
					}

					// reply length field
					binary.BigEndian.PutUint16(rpack[:2], uint16(len(rpack)-2))

					// reply client
					_, err = conn.Write(rpack)
					if err != nil {
						ctxlog.Errorf(ctx, "conn.Write(): %v", err)
						return
					}
				}()
			} // loop parse req
		}(conn)
	} // loop accept conn
}

func StartDebugServer(ctx context.Context, addr string) (server *http.Server) {
	server = &http.Server{Addr: addr, Handler: nil}
	go func() {
		err := server.ListenAndServe()
		if err != nil {
			ctxlog.Errorf(ctx, "StartDebugServer: %v", err)
		}
	}()
	return
}

func main() {
	// logging
	log.SetFlags(log.Flags() | log.Lmicroseconds)

	// args
	cfgFilePtr := flag.String("c", "cfg.json", "config file")
	debugServerPtr := flag.String("debug", "", "debug server addr")
	flag.Parse()

	// ctx
	ctx := context.Background()

	// config
	cfgString, err := ioutil.ReadFile(*cfgFilePtr)
	if err != nil {
		ctxlog.Fatal(ctx, err)
	}

	server, err := dnsproxy.MakeServerFromString(cfgString)
	if err != nil {
		ctxlog.Fatal(ctx, err)
	}

	// shared state
	state := newServerState()

	// debug server
	var debugSrv *http.Server
	if *debugServerPtr != "" {
		debugSrv = StartDebugServer(ctx, *debugServerPtr)
	}

	// loop for tcp client
	initTCP(ctx, server, state)
	state.inc()
	go doTCP(ctx, server, state)
	// loop for udp client
	initUDP(ctx, server, state)
	state.inc()
	go doUDP(ctx, server, state)

	// wait for ctrl-c
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	signal.Stop(sig)

	// shutdown
	ctxlog.Infof(ctx, "before exiting. number of goroutine: %v", runtime.NumGoroutine())
	state.close(ctx)
	ctxlog.Infof(ctx, "wait for goroutines")
	state.wait()

	//debugSrv.Shutdown(ctx)
	if debugSrv != nil {
		safeClose(ctx, debugSrv)
	}
	ctxlog.Infof(ctx, "exited. number of goroutine: %v", runtime.NumGoroutine())
}
