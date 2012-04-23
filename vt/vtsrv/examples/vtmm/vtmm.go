// Copyright 2010 The Govt Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Based on Ron Minnich's idea.

package main

import (
	"code.google.com/p/govt/vt"
	"code.google.com/p/govt/vt/vtsrv"
	"crypto/sha1"
	"errors"
	"flag"
	"fmt"
	"hash"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	Magic      = 0x28b4
	HeaderSize = 8 // magic[2] size[2] next[4]
)

type File struct {
	sync.Mutex
	file    *os.File
	size    uint64
	synctip uint64
	tip     uint64
	lastip  uint64 // offset of the last block

	chunksz uint64
	chunks  [][]byte
}

type Vtmap struct {
	vtsrv.Srv
	sync.Mutex

	f     *File
	htbl  map[string][]byte
	schan chan hash.Hash
}

var addr = flag.String("addr", ":17034", "network address")
var debug = flag.Int("debug", 0, "print debug messages")
var align = flag.Int("align", 0, "block alignment")

func (srv *Vtmap) init(fname string) (err error) {
	err = nil
	srv.htbl = make(map[string][]byte, 1<<12)
	srv.schan = make(chan hash.Hash, 32)
	srv.f, err = NewFile(fname)
	if err != nil {
		return
	}

	err = srv.buildHash()
	return
}

func NewFile(fname string) (f *File, err error) {
	var fi os.FileInfo

	f = new(File)
	f.file, err = os.OpenFile(fname, os.O_RDWR, 0)
	if err != nil {
		return
	}

	fi, err = f.file.Stat()
	if err != nil {
		return
	}

	f.size = uint64(fi.Size())
	f.chunksz = 1 * 1024 * 1024 * 1024 // 1GB
	f.chunks = make([][]byte, f.size/f.chunksz+1)
	fd := f.file.Fd()
	for offset, i := uint64(0), 0; offset < f.size; i++ {
		n := f.chunksz
		if offset+uint64(n) > f.size {
			n = uint64(f.size - offset)
		}

		f.chunks[i], err = syscall.Mmap(int(fd), int64(offset), int(n), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
		if err != nil {
			return nil, err
		}

		offset += uint64(n)
	}

	f.tip = 0
	f.synctip = 0
	f.lastip = ^uint64(0)

	return f, nil
}

func (f *File) Sync() error {
	f.Lock()
	offset := f.synctip
	count := f.tip - f.synctip
	f.synctip = f.tip
	f.Unlock()

	for idx, off := int(offset/f.chunksz), int(offset%f.chunksz); count > 0; idx++ {
		if idx > len(f.chunks) {
			return errors.New("invalid sync range")
		}

		buf := f.chunks[idx]
		n := len(buf) - off
		if uint64(n) > count {
			n = int(count)
		}

		start := uintptr(unsafe.Pointer(&buf[off])) &^ (0xfff) // start address needs to be page-aligned
		end := uintptr(unsafe.Pointer(&buf[off+n-1]))
		_, _, e1 := syscall.Syscall(syscall.SYS_MSYNC, start, end-start, uintptr(syscall.MS_SYNC))
		if e1 != 0 {
			return e1
		}

		count -= uint64(n)
		off = 0
	}

	return nil
}

// updates the tip
func (f *File) ReadBlock() ([]byte, error) {
	var sz uint16
	var next uint32

	idx := int(f.tip / f.chunksz)
	off := int(f.tip % f.chunksz)
	buf := f.chunks[idx]

	m, p := vt.Gint16(buf[off:])
	sz, p = vt.Gint16(p)
	next, p = vt.Gint32(p)

	if m != Magic {
		if m == 0 && sz == 0 {
			// end of arena
			return nil, nil
		}

		return nil, errors.New("magic not found")
	}

	f.lastip = f.tip
	f.tip += uint64(next)

	return p[0:sz], nil
}

func (f *File) WriteBlock(data []byte) (ndata []byte, err error) {
	blksz := HeaderSize + len(data)
	idx := int(f.tip / f.chunksz)
	off := int(f.tip % f.chunksz)
	buf := f.chunks[idx]
	if off+blksz >= len(buf) {
		idx++
		if idx >= len(f.chunks) {
			return nil, errors.New("arena full")
		}

		off = 0
		buf = f.chunks[idx]
		f.tip = uint64(idx) * f.chunksz
		if off+blksz >= len(buf) {
			return nil, errors.New("arena full")
		}

		// update the last block's next pointer
		if f.lastip != ^uint64(0) {
			b := f.chunks[f.lastip/f.chunksz]
			_ = vt.Pint16(uint16(f.tip-f.lastip), b[(f.lastip%f.chunksz)+4:])
			f.synctip = f.lastip
		}
	}

	nextoff := f.tip + uint64(blksz)
	if *align > 0 {
		nextoff += uint64(*align) - nextoff%uint64(*align)
	}

	p := vt.Pint16(Magic, buf[off:])
	p = vt.Pint16(uint16(len(data)), p)
	p = vt.Pint32(uint32(nextoff-f.tip), p)
	copy(p, data)
	f.lastip = f.tip
	f.tip = nextoff

	return p[0:len(data)], nil
}

func (srv *Vtmap) buildHash() error {
	nblk := 0
	blksz := uint64(0)
	stime := time.Now()
	for {
		blk, err := srv.f.ReadBlock()
		if err != nil {
			return err
		}

		if blk == nil {
			break
		}

		score := srv.calcScore(blk)
		srv.htbl[string([]byte(score))] = blk
		nblk++
		blksz += uint64(len(blk))
	}
	etime := time.Now()

	srv.f.synctip = srv.f.tip
	fmt.Printf("read %d blocks total %v bytes in %v ms\n", nblk, blksz, (etime.Sub(stime))/1000000)
	fmt.Printf("total space used: %v bytes\n", srv.f.tip)
	return nil
}

func (srv *Vtmap) calcScore(data []byte) (ret vt.Score) {
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

func (srv *Vtmap) Hello(req *vtsrv.Req) {
	req.RespondHello("anonymous", 0, 0)
}

func (srv *Vtmap) Read(req *vtsrv.Req) {
	srv.Lock()
	strscore := string([]byte(req.Tc.Score))
	b := srv.htbl[strscore]
	srv.Unlock()

	if b == nil {
		req.RespondError("not found")
	} else {
		req.RespondRead(b)
	}
}

func (srv *Vtmap) Write(req *vtsrv.Req) {
	score := srv.calcScore(req.Tc.Data)
	strscore := string([]byte(score))
	srv.Lock()
	if srv.htbl[strscore] == nil {
		block, err := srv.f.WriteBlock(req.Tc.Data)
		if err != nil {
			srv.Unlock()
			req.RespondError(err.Error())
			return
		}

		srv.htbl[strscore] = block
	}
	srv.Unlock()
	req.RespondWrite(score)
}

func (srv *Vtmap) Sync(req *vtsrv.Req) {
	srv.f.Sync()
	req.RespondSync()
}

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Printf("expected file name\n")
		return
	}

	srv := new(Vtmap)
	err := srv.init(flag.Arg(0))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	srv.Debuglevel = *debug
	srv.Start(srv)
	srv.StartStatsServer()
	vtsrv.StartListener("tcp", *addr, &srv.Srv)
}
