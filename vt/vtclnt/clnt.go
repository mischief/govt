// Copyright 2010 The Govt Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vtclnt

import (
	"crypto/sha1"
	"fmt"
	"hash"
	"log"
	"net"
	"sync"
	"govt.googlecode.com/hg/vt"
)

const (
	DbgPrintCalls	= 1 << iota
	DbgPrintPackets
	DbgLogCalls
	DbgLogPackets
)

type StatsOps interface {
	statsRegister()
	statsUnregister()
}

type Clnt struct {
	sync.Mutex
	Debuglevel	int
	Id		string
	Log		*vt.Logger

	conn		net.Conn
	tagpool		*pool
	reqout		chan *Req
	done		chan bool
	reqfirst	*Req
	reqlast		*Req
	err		*vt.Error
	reqchan		chan *Req
	schan		chan hash.Hash
	next, prev	*Clnt

	// stats
	nreqs	int	// number of requests processed
	tsz	uint64	// total size of the T messages received
	rsz	uint64	// total size of the R messages sent
	npend	int	// number of currently pending requests
	maxpend	int	// maximum number of pending requests
	nreads	int	// number of reads from the connection
	nwrites	int	// number of writes to the connection
}

type Req struct {
	sync.Mutex
	Clnt		*Clnt
	Tc, Rc		vt.Call
	Err		*vt.Error
	Done		chan *Req
	tag		uint8
	next, prev	*Req
}

type pool struct {
	sync.Mutex
	need	int
	nchan	chan uint32
	maxid	uint32
	imap	[]byte
}

type ClntList struct {
	sync.Mutex
	list	*Clnt
}

var clnts *ClntList
var DefaultDebuglevel int
var DefaultLogger *vt.Logger

func (clnt *Clnt) Rpcnb(r *Req) *vt.Error {
	clnt.Lock()
	if clnt.err != nil {
		clnt.Unlock()
		return clnt.err
	}

	if clnt.reqlast != nil {
		clnt.reqlast.next = r
	} else {
		clnt.reqfirst = r
	}

	r.prev = clnt.reqlast
	clnt.reqlast = r
	clnt.Unlock()

	clnt.reqout <- r
	return nil
}

func (clnt *Clnt) recv() {
	var err *vt.Error
	var req *Req
	var csz int

	err = nil
	buf := make([]byte, vt.Maxblock*8)
	pos := 0
	for {
		if len(buf) < int(vt.Maxblock) {
			b := make([]byte, vt.Maxblock*8)
			copy(b, buf[0:pos])
			buf = b
			b = nil
		}

		n, oserr := clnt.conn.Read(buf[pos:len(buf)])
		if oserr != nil || n == 0 {
			err = &vt.Error{oserr.String()}
			goto closed
		}

		pos += n
		for pos > 4 {
			sz, _ := vt.Gint16(buf)
			sz += 2
			if sz > vt.Maxblock {
				err = &vt.Error{fmt.Sprintf("bad client connection: %s", clnt.Id)}
				clnt.conn.Close()
				goto closed
			}

			if pos < int(sz) {
				if len(buf) < int(sz) {
					b := make([]byte, vt.Maxblock*8)
					copy(b, buf[0:pos])
					buf = b
					b = nil
				}

				break
			}

			tag, _ := vt.Gint8(buf[3:])
			clnt.Lock()
			for req = clnt.reqfirst; req != nil; req = req.next {
				if req.tag == tag {
					if req.prev != nil {
						req.prev.next = req.next
					} else {
						clnt.reqfirst = req.next
					}

					if req.next != nil {
						req.next.prev = req.prev
					} else {
						clnt.reqlast = req.prev
					}

					break
				}
			}
			clnt.Unlock()

			if req == nil {
				err = &vt.Error{"unexpected response"}
				clnt.conn.Close()
				goto closed
			}

			csz, err = vt.Unpack(buf, &req.Rc)
			if err != nil {
				clnt.conn.Close()
				goto closed
			}

			if clnt.Debuglevel > 0 {
				clnt.logFcall(&req.Rc)
				if clnt.Debuglevel&DbgPrintPackets != 0 {
					log.Println("}-}", clnt.Id, fmt.Sprint(req.Rc.Pkt))
				}

				if clnt.Debuglevel&DbgPrintCalls != 0 {
					log.Println("}}}", clnt.Id, req.Rc.String())
				}
			}

			if req.Tc.Id != req.Rc.Id-1 {
				if req.Rc.Id != vt.Rerror {
					req.Err = &vt.Error{"invalid response"}
				} else {
					if req.Err != nil {
						req.Err = &vt.Error{req.Rc.Ename}
					}
				}
			}

			if req.Done != nil {
				req.Done <- req
			} else {
				clnt.ReqFree(req)
			}

			pos -= csz
			buf = buf[csz:]
		}
	}

closed:
	clnt.done <- true

	/* send error to all pending requests */
	clnt.Lock()
	if clnt.err != nil {
		clnt.err = err
	}

	r := clnt.reqfirst
	clnt.reqfirst = nil
	clnt.reqlast = nil
	clnt.Unlock()

	for ; r != nil; r = r.next {
		r.Err = err
		if r.Done != nil {
			r.Done <- r
		}
	}

	clnts.Lock()
	if clnt == clnts.list {
		clnts.list = clnt.next
	} else {
		var c *Clnt

		for c = clnts.list; c.next != clnt; c = c.next {
		}

		c.next = clnt.next
	}
	clnts.Unlock()
	if sop, ok := (interface{}(clnt)).(StatsOps); ok {
		sop.statsUnregister()
	}
}

func (clnt *Clnt) send() {
	buf := make([]byte, 8*vt.Maxblock)
	pos := 0

	for {
		select {
		case <-clnt.done:
			return

		case req := <-clnt.reqout:
		again:
			nreqs := 0
			for req != nil {
				req.Tc.Tag = req.tag
				n := vt.Pack(buf[pos:], &req.Tc)
				if n < 0 {
					break
				}

				if clnt.Debuglevel > 0 {
					clnt.logFcall(&req.Rc)
					if clnt.Debuglevel&DbgPrintPackets != 0 {
						log.Println("{-{", clnt.Id, fmt.Sprintf("%x", req.Tc.Pkt))
					}

					if clnt.Debuglevel&DbgPrintCalls != 0 {
						log.Println("{{{", clnt.Id, req.Tc.String())
					}
				}

				pos += n
				nreqs++
				clnt.ReqFree(req)
				select {
				default:
					req = nil

				case req = <-clnt.reqout:
				}
			}

			nwrites := 0
			for b := buf[0:pos]; len(b) > 0; {
				n, err := clnt.conn.Write(b)
				if err != nil {
					clnt.Lock()
					clnt.err = &vt.Error{err.String()}
					clnt.Unlock()

					/* just close the socket, will get signal on conn.done */
					log.Println("error while writing")
					clnt.conn.Close()
					break
				}
				nwrites++
				b = b[n:]
			}

			clnt.Lock()
			clnt.rsz += uint64(pos)
			clnt.npend -= nreqs
			clnt.nwrites += nwrites
			clnt.Unlock()
			pos = 0
			if req != nil {
				goto again
			}
		}
	}
}

// Creates and initializes a new Clnt object. Doesn't send any data
// on the wire.
func NewClnt(c net.Conn) *Clnt {
	clnt := new(Clnt)
	clnt.conn = c
	clnt.Debuglevel = DefaultDebuglevel
	clnt.Log = DefaultLogger
	clnt.tagpool = newPool(uint32(255))
	clnt.reqout = make(chan *Req)
	clnt.done = make(chan bool)
	clnt.reqchan = make(chan *Req, 16)
	clnt.schan = make(chan hash.Hash, 32)

	processBanner(c)
	go clnt.recv()
	go clnt.send()

	clnts.Lock()
	clnt.next = clnts.list
	clnts.list = clnt
	clnts.Unlock()

	if sop, ok := (interface{}(clnt)).(StatsOps); ok {
		sop.statsRegister()
	}
	return clnt
}

func Connect(ntype, addr string) (clnt *Clnt, err *vt.Error) {
	c, e := net.Dial(ntype, addr)
	if e != nil {
		return nil, &vt.Error{e.String()}
	}

	clnt = NewClnt(c)
	req := clnt.ReqAlloc()
	req.Done = make(chan *Req)
	tc := req.Tc
	tc.Id = vt.Thello
	tc.Version = "02"
	tc.Uid = "anonymous"
	tc.Strength = 0
	tc.Crypto = make([]byte, 0)
	tc.Codec = tc.Crypto

	err = clnt.Rpcnb(req)
	if err != nil {
		return
	}

	<-req.Done
	if req.Err != nil {
		err = req.Err
	}
	clnt.ReqFree(req)

	return
}

func (clnt *Clnt) ReqAlloc() *Req {
	var req *Req

	select {
	default:
		req = new(Req)
		req.Clnt = clnt
		req.tag = uint8(clnt.tagpool.getId())

	case req = <-clnt.reqchan:
	}

	return req
}

func (clnt *Clnt) ReqFree(req *Req) {
	req.Tc.Clear()
	req.Rc.Clear()
	req.Err = nil
	req.Done = nil
	req.next = nil
	req.prev = nil

	select {
	default:
		clnt.tagpool.putId(uint32(req.tag))

	case clnt.reqchan <- req:
	}
}

func (clnt *Clnt) Getnb(score vt.Score, btype uint8, count uint16, done chan *Req) (err *vt.Error) {
	req := clnt.ReqAlloc()
	req.Done = done
	tc := req.Tc
	tc.Id = vt.Tread
	tc.Score = score
	tc.Btype = btype
	tc.Count = count

	err = clnt.Rpcnb(req)
	if err != nil {
		clnt.ReqFree(req)
	}

	return
}

func (clnt *Clnt) Get(score vt.Score, btype uint8, count uint16) (data []byte, err *vt.Error) {
	done := make(chan *Req)
	err = clnt.Getnb(score, btype, count, done)
	if err != nil {
		return
	}

	req := <-done
	if req.Err != nil {
		err = req.Err
		clnt.ReqFree(req)
		return
	}

	data = req.Rc.Data
	clnt.ReqFree(req)
	return
}

// Put is always async, Sync will make sure all Puts finished before returning
func (clnt *Clnt) Put(btype uint8, data []byte) (score vt.Score, err *vt.Error) {
	req := clnt.ReqAlloc()
	tc := req.Tc
	tc.Id = vt.Twrite
	tc.Btype = btype
	tc.Data = data

	err = clnt.Rpcnb(req)
	if err != nil {
		clnt.ReqFree(req)
	} else {
		score = clnt.calcScore(data)
	}

	return
}

func (clnt *Clnt) Sync() (err *vt.Error) {
	done := make(chan *Req)
	req := clnt.ReqAlloc()
	req.Done = done
	tc := req.Tc
	tc.Id = vt.Tsync
	err = clnt.Rpcnb(req)
	if err != nil {
		clnt.ReqFree(req)
		return
	}

	// set all outstanding Twrites to report when they are done
	clnt.Lock()
	n := 1
	for r := clnt.reqfirst; r != nil; r = r.next {
		if r.Tc.Id == vt.Twrite {
			r.Done = done
			n++
		}
	}
	clnt.Unlock()

	for n > 0 {
		req := <-done
		if req.Err != nil && err != nil {
			err = req.Err
		}

		n--
	}

	return
}

func (clnt *Clnt) logFcall(c *vt.Call) {
	if clnt.Debuglevel&DbgLogPackets != 0 {
		pkt := make([]byte, len(c.Pkt))
		copy(pkt, c.Pkt)
		clnt.Log.Log(pkt, clnt, DbgLogPackets)
	}

	if clnt.Debuglevel&DbgLogCalls != 0 {
		f := new(vt.Call)
		*f = *c
		f.Pkt = nil
		clnt.Log.Log(f, clnt, DbgLogCalls)
	}
}

func (clnt *Clnt) calcScore(data []byte) (ret vt.Score) {
	var s1 hash.Hash

	select {
	default:
		s1 = sha1.New()
	case s1 = <-clnt.schan:
		s1.Reset()
	}

	s1.Write(data)
	ret = s1.Sum()

	select {
	case clnt.schan <- s1:
		break
	default:
	}

	return
}

func processBanner(c net.Conn) bool {
	var i int

	n, err := c.Write([]byte(vt.Banner))
	if err != nil || n != len(vt.Banner) {
		return false
	}

	buf := make([]byte, 1024)
	for i = 0; i < len(buf); i++ {
		n, err := c.Read(buf[i : i+1])
		if err != nil || n != 1 {
			return false
		}

		if buf[i] == '\n' {
			break
		}
	}

	return vt.CheckBanner(string(buf[0:i]))
}

func init() {
	clnts = new(ClntList)
	if sop, ok := (interface{}(clnts)).(StatsOps); ok {
		sop.statsRegister()
	}
}
