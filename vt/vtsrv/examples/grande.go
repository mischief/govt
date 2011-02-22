// Copyright 2010 The Govt Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Based on Eric van Hensbergen's C implementation
// http://bitbucket.org/ericvh/vdiskfs/src/tip/src/cmd/venti/grande.c

package main

import (
	"flag"
	"fmt"
	"hash"
	"http"
	"crypto/sha1"
	"log"
	"os"
	"govt.googlecode.com/hg/vt"
	"govt.googlecode.com/hg/vtsrv"
)

type Grande struct {
	vtsrv.Srv
	topDir string
	schan chan hash.Hash
}

var addr = flag.String("addr", ":17034", "network address")
var debug = flag.Int("debug", 0, "print debug messages")

func eqscore(s1, s2 vt.Score) bool {
	for i := 0; i < vt.Scoresize; i++ {
		if s1[i] != s2[i] {
			return false
		}
	}

	return true
}

func (srv *Grande) Name(s vt.Score) string {
	return fmt.Sprintf("%s/%02x/%02x/%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		srv.topDir, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10],
		s[11], s[12], s[13], s[14], s[15], s[16], s[17], s[18], s[19])
}

func (srv *Grande) init() {
	srv.schan = make(chan hash.Hash, 32)
}

func (srv *Grande) calcScore(data []byte) (ret vt.Score) {
	var s1 hash.Hash

	select {
	default:
		s1 = sha1.New()
	case s1 = <- srv.schan:
		s1.Reset()
	}

	s1.Write(data)
	ret = s1.Sum()
	select {
	case srv.schan <- s1:
		break
	default:
	}
	return
}

func (srv *Grande) Hello(req *vtsrv.Req) {
	req.RespondHello("anonymous", 0, 0)
}

func (srv *Grande) Read(req *vtsrv.Req) {
	var n int

	bname := srv.Name(req.Tc.Score)
	f, err := os.Open(bname, os.O_RDONLY, 0)
	if err!=nil {
error:
		req.RespondError(err.String())
		return
	}

	b := make([]byte, req.Tc.Count)
	n, err = f.Read(b)
	f.Close()
	if err!=nil {
		goto error
	}

	
	req.RespondRead(b[0:n])
}

func (srv *Grande) Write(req *vtsrv.Req) {
	var f *os.File
	var n int

	s := srv.calcScore(req.Tc.Data)
	dname := fmt.Sprintf("%s/%02x/%02x", srv.topDir, s[0], s[1])
	err := os.MkdirAll(dname, 0777)
	if err!=nil {
error:
		req.RespondError(err.String())
		return
	}

	f, err = os.Open(srv.Name(s), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0666)
	if err!=nil {
		goto error
	}

	defer f.Close()
	n, err = f.Write(req.Tc.Data)
	if err!=nil {
		goto error;
	}

	if n!=len(req.Tc.Data) {
		req.RespondError("short write")
		return
	}

	req.RespondWrite(s)
}

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		log.Println("expecting directory name")
		return
	}

	srv := new(Grande)
	srv.init()
	srv.topDir = flag.Arg(0)
	srv.Debuglevel = *debug
	srv.Start(srv)
	go http.ListenAndServe(":6060", nil)
	vtsrv.StartListener("tcp", *addr, &srv.Srv)
}
