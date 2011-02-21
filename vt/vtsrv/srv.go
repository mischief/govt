// Copyright 2010 The Govt Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vtsrv

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"govt.googlecode.com/hg/vt"
)

const (
	Cnew = iota
	Chello
)

const (
	DbgPrintCalls = 1 << iota
	DbgPrintPackets
	DbgLogCalls
	DbgLogPackets
)

type ConnOps interface {
	ConnOpened(*Conn)
	ConnClosed(*Conn)
}

type ReqOps interface {
	ReqProcess(*Req)
	ReqRespond(*Req)
}

type PingOp interface {
	Ping(*Req)
}

type HelloOp interface {
	Hello(*Req)
}

type SyncOp interface {
	Sync(*Req)
}

type ReadOp interface {
	Read(*Req)
}

type WriteOp interface {
	Write(*Req)
}

type StatsOps interface {
	statsRegister()
	statsUnregister()
}

type Conn struct {
	sync.Mutex
	Srv        *Srv
	Id         string
	Debuglevel int
	status     int
	conn       net.Conn
	reqs       *Req
	reqout     chan *Req
	prev, next *Conn
	done       chan bool

	// stats
	nreqs   int    // number of requests processed
	tsz     uint64 // total size of the T messages received
	rsz     uint64 // total size of the R messages sent
	npend   int    // number of currently pending requests
	maxpend int    // maximum number of pending requests
	nreads  int    // number of reads from the connection
	nwrites int    // number of writes to the connection
}

type Req struct {
	Tc   *vt.Call
	Rc   *vt.Call
	Conn *Conn
}

type Srv struct {
	sync.Mutex
	Id         string
	Debuglevel int
	Log        *vt.Logger
	ops        interface{}
	connlist   *Conn
	rchan      chan *Req

	// stats
	nreqs   int    // number of requests processed
	tsz     uint64 // total size of the T messages received
	rsz     uint64 // total size of the R messages sent
	maxpend int    // maximum number of pending requests
	nreads  int    // number of reads from the connection
	nwrites int    // number of writes to the connection
}

func (srv *Srv) Start(ops interface{}) {
	srv.ops = ops
	srv.rchan = make(chan *Req, 64)
	if srv.Log == nil {
		srv.Log = vt.NewLogger(1024)
	}

	if sop, ok := (interface{}(srv)).(StatsOps); ok {
		sop.statsRegister()
	}
}

func (srv *Srv) String() string {
	return srv.Id
}

func (srv *Srv) ReqAlloc() *Req {
	var r *Req

	select {
	default:
		r = new(Req)
		r.Tc = new(vt.Call)
		r.Rc = new(vt.Call)
	case r = <-srv.rchan:
	}

	return r
}

func (srv *Srv) ReqFree(r *Req) {
	r.Conn = nil
	r.Tc.Clear()
	r.Rc.Clear()
	select {
	case srv.rchan <- r:
		break
	default:
	}

}

func (req *Req) process() {
	if rop, ok := req.Conn.Srv.ops.(ReqOps); ok {
		rop.ReqProcess(req)
	} else {
		req.Process()
	}
}

func (req *Req) Process() {
	conn := req.Conn
	srv := conn.Srv
	tc := req.Tc

	if conn.status == Cnew && tc.Id != vt.Thello {
		req.RespondError("expecting hello message")
		return
	}

	switch tc.Id {
	default:
		req.RespondError("unknown message type")

	case vt.Tping:
		if pop, ok := (srv.ops).(PingOp); ok {
			pop.Ping(req)
		} else {
			req.RespondPing()
		}

	case vt.Thello:
		if hop, ok := (srv.ops).(HelloOp); ok {
			hop.Hello(req)
		} else {
			goto unsupported
		}

	case vt.Tgoodbye:
		conn.status = Cnew

	case vt.Tread:
		if rop, ok := (srv.ops).(ReadOp); ok {
			rop.Read(req)
		} else {
			goto unsupported
		}

	case vt.Twrite:
		if wop, ok := (srv.ops).(WriteOp); ok {
			wop.Write(req)
		} else {
			goto unsupported
		}

	case vt.Tsync:
		if sop, ok := (srv.ops).(SyncOp); ok {
			sop.Sync(req)
		} else {
			req.RespondSync()
		}

	}

	return

unsupported:
	req.RespondError("unsupported operation")
	return
}

func (req *Req) Respond() {
	if rop, ok := (req.Conn.Srv.ops).(ReqOps); ok {
		rop.ReqRespond(req)
	}

	if req.Rc.Id == vt.Rhello {
		req.Conn.status = Chello
	}
	req.Conn.reqout <- req
}

func (req *Req) RespondError(ename string) {
	req.Rc.Id = vt.Rerror
	req.Rc.Ename = ename
	req.Respond()
}

func (req *Req) RespondPing() {
	req.Rc.Id = vt.Rping
	req.Respond()
}

func (req *Req) RespondHello(sid string, rcrypto, rcodec uint8) {
	rc := req.Rc
	rc.Id = vt.Rhello
	rc.Sid = sid
	rc.Rcrypto = rcrypto
	rc.Rcodec = rcodec
	req.Respond()
}

func (req *Req) RespondRead(data []byte) {
	rc := req.Rc
	rc.Id = vt.Rread
	rc.Data = data
	req.Respond()
}

func (req *Req) RespondWrite(score vt.Score) {
	req.Rc.Id = vt.Rwrite
	req.Rc.Score = score
	req.Respond()
}

func (req *Req) RespondSync() {
	req.Rc.Id = vt.Rsync
	req.Respond()
}

func (conn *Conn) String() string {
	return conn.Srv.Id + "/" + conn.Id
}

func (srv *Srv) NewConn(c net.Conn) {
	conn := new(Conn)
	conn.status = Cnew
	conn.Srv = srv
	conn.Debuglevel = srv.Debuglevel
	conn.conn = c
	conn.reqout = make(chan *Req, 64)
	conn.done = make(chan bool)
	conn.prev = nil
	conn.Id = c.RemoteAddr().String()
	srv.Lock()
	conn.next = srv.connlist
	srv.connlist = conn
	srv.Unlock()

	if op, ok := (srv.ops).(ConnOps); ok {
		op.ConnOpened(conn)
	}

	if sop, ok := (interface{}(conn)).(StatsOps); ok {
		sop.statsRegister()
	}

	go conn.recv()
	go conn.send()
}

func (conn *Conn) recv() {
	var err os.Error
	var n int

	bufsz := 8 * vt.Maxblock
	buf := make([]byte, bufsz*8)
	srv := conn.Srv
	pos := 0
	for {
		if len(buf) < vt.Maxblock {
		resize:
			b := make([]byte, bufsz)
			copy(b, buf[0:pos])
			buf = b
			b = nil
		}

		n, err = conn.conn.Read(buf[pos:])
		if err != nil || n == 0 {
			goto closed
		}

		nreads := 1
		pos += n
		for pos > 2 {
			sz, _ := vt.Gint16(buf)
			if sz > vt.Maxblock {
				log.Println("bad client connection: ", conn.conn.RemoteAddr())
				conn.conn.Close()
				goto closed
			}
			if pos < int(sz) {
				if len(buf) < int(sz) {
					goto resize
				}

				break
			}

			req := srv.ReqAlloc()
			req.Conn = conn
			csize, err := vt.Unpack(buf, req.Tc)
			if err != nil {
				log.Println(fmt.Sprintf("invalid packet: %v %v", err, buf))
				conn.conn.Close()
				srv.ReqFree(req)
				goto closed
			}

			if conn.Debuglevel > 0 {
				conn.logFcall(req.Tc)
				if conn.Debuglevel&DbgPrintPackets != 0 {
					log.Println(">->", conn.Id, fmt.Sprintf("%x", req.Tc.Pkt))
				}

				if conn.Debuglevel&DbgPrintCalls != 0 {
					log.Println(">>>", conn.Id, req.Tc.String())
				}
			}

			conn.Lock()
			conn.nreqs++
			conn.tsz += uint64(sz)
			conn.npend++
			conn.nreads += nreads
			nreads = 0
			if conn.npend > conn.maxpend {
				conn.maxpend = conn.npend
			}
			conn.Unlock()

			go req.process()
			buf = buf[csize:]
			pos -= csize
		}
	}

closed:
	conn.done <- true
	conn.Srv.Lock()
	srv.nreqs += conn.nreqs
	srv.tsz += conn.tsz
	srv.rsz += conn.rsz
	srv.maxpend += conn.maxpend
	srv.nwrites += conn.nwrites
	srv.nreads += conn.nreads
	if conn.prev != nil {
		conn.prev.next = conn.next
	} else {
		conn.Srv.connlist = conn.next
	}

	if conn.next != nil {
		conn.next.prev = conn.prev
	}
	conn.Srv.Unlock()
	if sop, ok := (interface{}(conn)).(StatsOps); ok {
		sop.statsUnregister()
	}

	if op, ok := (conn.Srv.ops).(ConnOps); ok {
		op.ConnClosed(conn)
	}
}

func (conn *Conn) send() {
	buf := make([]byte, 8*vt.Maxblock)
	pos := 0

	for {
		select {
		case <-conn.done:
			return

		case req := <-conn.reqout:
		again:
			nreqs := 0
			for req != nil {
				req.Rc.Tag = req.Tc.Tag
				n := vt.Pack(buf[pos:], req.Rc)
				if n < 0 {
					break
				}

				if conn.Debuglevel > 0 {
					conn.logFcall(req.Rc)
					if conn.Debuglevel&DbgPrintPackets != 0 {
						log.Println("<-<", conn.Id, fmt.Sprintf("%x", req.Rc.Pkt))
					}

					if conn.Debuglevel&DbgPrintCalls != 0 {
						log.Println("<<<", conn.Id, req.Rc.String())
					}
				}

				pos += n
				nreqs++
				conn.Srv.ReqFree(req)
				select {
				default:
					req = nil
				case req = <-conn.reqout:
				}
			}

			nwrites := 0
			for b := buf[0:pos]; len(b) > 0; {
				n, err := conn.conn.Write(b)
				if err != nil {
					/* just close the socket, will get signal on conn.done */
					log.Println("error while writing")
					conn.conn.Close()
					break
				}
				nwrites++
				b = b[n:]
			}

			conn.Lock()
			conn.rsz += uint64(pos)
			conn.npend -= nreqs
			conn.nwrites += nwrites
			conn.Unlock()
			pos = 0
			if req != nil {
				goto again
			}
		}
	}
}

func (conn *Conn) RemoteAddr() net.Addr {
	return conn.conn.RemoteAddr()
}

func (conn *Conn) LocalAddr() net.Addr {
	return conn.conn.LocalAddr()
}

func (conn *Conn) logFcall(c *vt.Call) {
	if conn.Debuglevel&DbgLogPackets != 0 {
		pkt := make([]byte, len(c.Pkt))
		copy(pkt, c.Pkt)
		conn.Srv.Log.Log(pkt, conn, DbgLogPackets)
	}

	if conn.Debuglevel&DbgLogCalls != 0 {
		f := new(vt.Call)
		*f = *c
		f.Pkt = nil
		conn.Srv.Log.Log(f, conn, DbgLogCalls)
	}
}

func StartListener(network, laddr string, srv *Srv) os.Error {
	l, err := net.Listen(network, laddr)
	if err != nil {
		log.Println("listen fail: ", network, listen, err)
		return err
	}

	listen(l, srv)
	return nil
}

func checkBanner(c net.Conn) bool {
	var i int
	bhdr := "venti-"
	bver := "02"

	buf := make([]byte, len(bhdr)+len(bver)+3)
	n, err := c.Read(buf[0:len(bhdr)])
	if err != nil || n != len(bhdr) || string(buf[0:n]) != bhdr {
		return false
	}

	// read the versions
	for i = 0; i < len(buf)-1; i++ {
		n, err = c.Read(buf[i : i+1])
		if buf[i] == '-' {
			break
		}
	}

	// read the rest
	for {
		n, err = c.Read(buf[i : i+1])
		if err != nil || n != 1 {
			return false
		}

		if buf[i] == '\n' {
			break
		}
	}

	vers := strings.Split(string(buf[0:i]), ":", -1)
	for i = 0; i < len(vers); i++ {
		if vers[i] == bver {
			return true
		}
	}

	return false
}

func listen(l net.Listener, srv *Srv) {
again:
	for {
		c, err := l.Accept()
		if err != nil {
			break
		}

		if !processBanner(c) {
			c.Close()
		}

		srv.NewConn(c)
	}
}

func processBanner(c net.Conn) bool {
	var i int

	n, err := c.Write([]byte(vt.Banner))
	if err!=nil || n!=len(vt.Banner) {
		return false
	}

	buf := make([]byte, 1024)
	for i=0; i<len(buf); i++ {
		n, err := c.Read(buf[i:i+1])
		if err!=nil || n!=1 {
			return false
		}

		if buf[i] == '\n' {
			break
		}
	}

	return vt.CheckBanner(string(buf[0:i]))
}
