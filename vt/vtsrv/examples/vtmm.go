// Copyright 2010 The Govt Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Based on Ron Minnich's idea.

package main

import (
	"flag"
	"fmt"
	"hash"
	"http"
	"crypto/sha1"
	"os"
	"sync"
	"syscall"
	"unsafe"
	"govt.googlecode.com/hg/vt"
	"govt.googlecode.com/hg/vtsrv"
)

const (
	Magic      = 0x28b4
	HeaderSize = 24
)

type File struct {
	sync.Mutex
	file    *os.File
	size    uint64
	synctip uint64
	tip     uint64

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

func (srv *Vtmap) init(fname string) (err os.Error) {
	err = nil
	srv.htbl = make(map[string][]byte)
	srv.schan = make(chan hash.Hash, 32)
	srv.f, err = NewFile(fname)
	if err != nil {
		return
	}

	err = srv.buildHash()
	return
}

func NewFile(fname string) (f *File, err os.Error) {
	var errno int
	var fi *os.FileInfo

	f = new(File)
	f.file, err = os.OpenFile(fname, os.O_RDWR, 0)
	if err != nil {
		return
	}

	fi, err = f.file.Stat()
	if err != nil {
		return
	}

	f.size = uint64(fi.Size)
	f.chunksz = 1 * 1024 * 1024 * 1024 // 1GB
	f.chunks = make([][]byte, f.size/f.chunksz+1)
	fd := f.file.Fd()
	for offset, i := uint64(0), 0; offset < f.size; i++ {
		n := f.chunksz
		if offset+uint64(n) > f.size {
			n = uint64(f.size - offset)
		}

		f.chunks[i], errno = syscall.Mmap(fd, int64(offset), int(n), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
		if errno != 0 {
			return nil, os.Errno(errno)
		}

		offset += uint64(n)
	}

	f.tip = 0

	return f, nil
}

func (f *File) Read(offset uint64, count int) []byte {
	idx := int(offset / f.chunksz)
	if idx > len(f.chunks) {
		return nil
	}

	buf := f.chunks[idx]
	off := int(offset % f.chunksz)
	if off+count > len(buf) {
		return nil
	}

	return buf[off : off+count]
}

func (f *File) Write(data []byte, updatetip bool) (offset uint64, err os.Error) {
	f.Lock()
	idx := int(f.tip / f.chunksz)
	off := int(f.tip % f.chunksz)
	buf := f.chunks[idx]
	if off+len(data) > len(buf) {
		idx++
		off = 0
		if idx > len(f.chunks) {
			f.Unlock()
			return 0, os.NewError("arena full")
		}

		buf = f.chunks[idx]
	}

	if updatetip {
		f.tip = uint64(idx)*f.chunksz + uint64(off) + uint64(len(data))
	}
	f.Unlock()

	copy(buf[off:], data)
	offset = (uint64(idx) * f.chunksz) + uint64(off)
	return offset, nil
}

func (f *File) Sync() os.Error {
	f.Lock()
	offset := f.synctip
	count := f.tip - f.synctip
	f.synctip = f.tip
	f.Unlock()

	for idx, off := int(offset/f.chunksz), int(offset%f.chunksz); count > 0; idx++ {
		if idx > len(f.chunks) {
			return os.NewError("invalid sync range")
		}

		buf := f.chunks[idx]
		n := len(buf) - off
		if uint64(n) > count {
			n = int(count)
		}

		start := uintptr(unsafe.Pointer(&buf[off])) &^ (0xfff)
		end := uintptr(unsafe.Pointer(&buf[off+n-1]))
		_, _, e1 := syscall.Syscall(syscall.SYS_MSYNC, start, end-start, uintptr(syscall.MS_SYNC))
		errno := int(e1)
		if errno != 0 {
			return os.NewError(syscall.Errstr(errno))
		}

		count -= uint64(n)
		off = 0
	}

	return nil
}

func (f *File) ReadBlock(offset uint64) (size int, score []byte, data []byte, endoffset uint64, err os.Error) {
	var sz uint16

	if offset%f.chunksz+HeaderSize > f.chunksz {
		offset = (offset/f.chunksz + 1) * f.chunksz
	}

	hdr := f.Read(offset, HeaderSize)
	m, p := vt.Gint16(hdr)
	if m != Magic {
		err = os.NewError("invalid magic")
		return
	}

	sz, p = vt.Gint16(p)
	size = int(sz)
	score = p[0:vt.Scoresize]
	p = p[vt.Scoresize:]
	dataoffset := offset + HeaderSize
	if (dataoffset / f.chunksz) != ((dataoffset + uint64(size)) / f.chunksz) {
		// data starts in the beginning of the next chunk
		dataoffset = (dataoffset/f.chunksz + 1) * f.chunksz
	}

	data = f.Read(dataoffset, size)
	endoffset = dataoffset + uint64(size)
	return
}

func (f *File) WriteBlock(score, data []byte) (ndata []byte, err os.Error) {
	var hdr [HeaderSize]byte
	var offset uint64

	p := vt.Pint16(Magic, hdr[0:])
	p = vt.Pint16(uint16(len(data)), p)
	copy(p[0:vt.Scoresize], score)
	_, err = f.Write(hdr[0:], true)
	if err != nil {
		return
	}

	offset, err = f.Write(data, true)
	if err != nil {
		return
	}

	// marker for end of blocks
	p = vt.Pint16(Magic, hdr[0:])
	_ = vt.Pint16(0, p)
	_, err = f.Write(hdr[0:], false)

	ndata = f.Read(offset, len(data))
	return
}

func (srv *Vtmap) buildHash() os.Error {
	for offset := srv.f.tip; offset < srv.f.size; {
		size, score, block, endoffset, err := srv.f.ReadBlock(offset)
		if err != nil {
			if offset == 0 {
				break
			}

			return err
		}

		if size == 0 {
			break
		}

		srv.htbl[string(score)] = block
		offset = endoffset
		srv.f.tip = offset
	}

	srv.f.synctip = srv.f.tip
	fmt.Printf("%d blocks read\n", len(srv.htbl))
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
	ret = s1.Sum()
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
		n := int(req.Tc.Count)
		if n > len(b) {
			n = len(b)
		}

		req.RespondRead(b[0:n])
	}
}

func (srv *Vtmap) Write(req *vtsrv.Req) {
	score := srv.calcScore(req.Tc.Data)
	srv.Lock()
	strscore := string([]byte(score))
	if srv.htbl[strscore] == nil {
		block, err := srv.f.WriteBlock(score, req.Tc.Data)
		if err != nil {
			srv.Unlock()
			req.RespondError(err.String())
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
	go http.ListenAndServe(":6060", nil)
	vtsrv.StartListener("tcp", *addr, &srv.Srv)
}
