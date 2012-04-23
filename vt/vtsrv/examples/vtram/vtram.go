// Copyright 2010 The Govt Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"code.google.com/p/govt/vt"
	"code.google.com/p/govt/vt/vtsrv"
	"crypto/sha1"
	"flag"
	"hash"
	"sync"
)

type Vtram struct {
	vtsrv.Srv
	sync.Mutex
	htbl  map[int]*Block
	schan chan hash.Hash
}

type Block struct {
	btype uint8
	score vt.Score
	data  []byte

	next *Block
}

var addr = flag.String("addr", ":17034", "network address")
var debug = flag.Int("debug", 0, "print debug messages")

func (srv *Vtram) init() {
	srv.htbl = make(map[int]*Block)
	srv.schan = make(chan hash.Hash, 32)
}

func calcHash(score vt.Score) int {
	return int(score[0]<<24) | int(score[1]<<16) | int(score[2]<<8) | int(score[3])
}

func (srv *Vtram) calcScore(data []byte) (ret vt.Score) {
	var s1 hash.Hash

	select {
	default:
		s1 = sha1.New()
	case s1 = <-srv.schan:
		s1.Reset()
	}

	s1.Write(data)
	ret = s1.Sum(nil)
	select {
	case srv.schan <- s1:
		break
	default:
	}
	return
}

func eqscore(s1, s2 vt.Score) bool {
	for i := 0; i < vt.Scoresize; i++ {
		if s1[i] != s2[i] {
			return false
		}
	}

	return true
}

func (srv *Vtram) getBlock(score vt.Score) *Block {
	var b *Block

	h := calcHash(score)
	srv.Lock()
	for b = srv.htbl[h]; b != nil; b = b.next {
		if eqscore(b.score, score) {
			break
		}
	}
	srv.Unlock()
	return b
}

func (srv *Vtram) putBlock(btype uint8, data []byte) *Block {
	var b *Block

	score := srv.calcScore(data)
	h := calcHash(score)

	srv.Lock()
	for b = srv.htbl[h]; b != nil; b = b.next {
		if eqscore(b.score, score) {
			break
		}
	}
	if b == nil {
		b = new(Block)
		b.score = score
		b.btype = btype
		b.data = data
		b.next = srv.htbl[h]
		srv.htbl[h] = b
	}
	srv.Unlock()

	return b
}

func (srv *Vtram) Hello(req *vtsrv.Req) {
	req.RespondHello("anonymous", 0, 0)
}

func (srv *Vtram) Read(req *vtsrv.Req) {
	b := srv.getBlock(req.Tc.Score)
	if b == nil {
		req.RespondError("not found")
	} else {
		n := int(req.Tc.Count)
		if n > len(b.data) {
			n = len(b.data)
		}

		req.RespondRead(b.data[0:n])
	}
}

func (srv *Vtram) Write(req *vtsrv.Req) {
	b := srv.putBlock(req.Tc.Btype, req.Tc.Data)
	req.RespondWrite(b.score)
}

func main() {
	flag.Parse()
	srv := new(Vtram)
	srv.init()
	srv.Debuglevel = *debug
	srv.Start(srv)
	srv.StartStatsServer()
	vtsrv.StartListener("tcp", *addr, &srv.Srv)
}
