// Copyright 2010 The Govt Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vt

import "strings"

// Venti messages
const (
	Rerror		= 1
	Tping		= 2
	Rping		= 3
	Thello		= 4
	Rhello		= 5
	Tgoodbye	= 6
	Tread		= 12
	Rread		= 13
	Twrite		= 14
	Rwrite		= 15
	Tsync		= 16
	Rsync		= 17
)

// Other constants
const (
	Scoresize	= 20
	Entrysize	= 40
	Maxblock	= 56 * 1024
)

// Block type
const (
	DataBlock	= 0 << 3
	DirBlock	= 1 << 3
	RBlock		= 2 << 3
)

type Call struct {
	Id		byte
	Tag		byte
	Ename		string	// Rerror
	Version		string	// Thello
	Uid		string	// Thello
	Strength	uint8	// Thello
	Crypto		[]byte	// Thello
	Codec		[]byte	// Thello
	Sid		string	// Rhello
	Rcrypto		byte	// Rhello
	Rcodec		byte	// Rhello
	Score		Score	// Tread, Rwrite
	Btype		byte	// Tread, Rwrite
	Count		uint16	// Tread
	Data		[]byte	// Twrite, Rread

	Pkt	[]byte
}

type Score []byte
type Error struct {
	Ename string
}

var Zeroscore = Score{
	0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
	0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
}

var Banner string = "venti-02-govt\n"

func Gint8(buf []byte) (uint8, []byte)	{ return buf[0], buf[1:len(buf)] }

func Gint16(buf []byte) (uint16, []byte) {
	return uint16(buf[1]) | (uint16(buf[0]) << 8), buf[2:len(buf)]
}

func Gint32(buf []byte) (uint32, []byte) {
	return uint32(buf[3]) | (uint32(buf[2]) << 8) | (uint32(buf[1]) << 16) |
		(uint32(buf[0]) << 24),
		buf[4:len(buf)]
}

func Gint48(buf []byte) (uint64, []byte) {
	return uint64(buf[5]) | (uint64(buf[4]) << 8) | (uint64(buf[3]) << 16) |
		uint64(buf[2])<<24 | (uint64(buf[1]) << 32) | (uint64(buf[0]) << 40),
		buf[6:len(buf)]
}

func Gint64(buf []byte) (uint64, []byte) {
	return uint64(buf[7]) | (uint64(buf[6]) << 8) | (uint64(buf[5]) << 16) |
		(uint64(buf[4]) << 24) | (uint64(buf[3]) << 32) | (uint64(buf[2]) << 40) |
		(uint64(buf[1]) << 48) | (uint64(buf[0]) << 56),
		buf[8:len(buf)]
}

func Gstr(buf []byte) (string, []byte) {
	var n uint16

	if buf == nil {
		return "", nil
	}

	n, buf = Gint16(buf)
	if int(n) > len(buf) {
		return "", nil
	}

	return string(buf[0:n]), buf[n:len(buf)]
}

func Gvar(buf []byte) ([]byte, []byte) {
	var n uint8

	if buf == nil {
		return nil, nil
	}

	n, buf = Gint8(buf)
	if int(n) > len(buf) {
		return nil, nil
	}

	return buf[0:n], buf[n:len(buf)]
}

func Gscore(buf []byte) ([]byte, []byte) {
	if len(buf) < Scoresize {
		return nil, nil
	}

	return buf[0:Scoresize], buf[Scoresize:]
}

func Pint8(val uint8, buf []byte) []byte {
	buf[0] = val
	return buf[1:]
}

func Pint16(val uint16, buf []byte) []byte {
	buf[0] = uint8(val >> 8)
	buf[1] = uint8(val)
	return buf[2:]
}

func Pint32(val uint32, buf []byte) []byte {
	buf[0] = uint8(val >> 24)
	buf[1] = uint8(val >> 16)
	buf[2] = uint8(val >> 8)
	buf[3] = uint8(val)
	return buf[4:]
}

func Pint48(val uint64, buf []byte) []byte {
	buf[0] = uint8(val >> 40)
	buf[1] = uint8(val >> 32)
	buf[2] = uint8(val >> 24)
	buf[3] = uint8(val >> 16)
	buf[4] = uint8(val >> 8)
	buf[5] = uint8(val)
	return buf[6:len(buf)]
}

func Pint64(val uint64, buf []byte) []byte {
	buf[0] = uint8(val >> 56)
	buf[1] = uint8(val >> 48)
	buf[2] = uint8(val >> 40)
	buf[3] = uint8(val >> 32)
	buf[4] = uint8(val >> 24)
	buf[5] = uint8(val >> 16)
	buf[6] = uint8(val >> 8)
	buf[7] = uint8(val)
	return buf[8:len(buf)]
}

func Pstr(val string, buf []byte) []byte {
	n := uint16(len(val))
	buf = Pint16(n, buf)
	b := []byte(val)
	copy(buf, b)
	return buf[n:]
}

func Pvar(val []byte, buf []byte) []byte {
	n := uint8(len(val))
	buf = Pint8(n, buf)
	b := []byte(val)
	copy(buf, b)
	return buf[n:]
}

func Pscore(val Score, buf []byte) []byte {
	copy(buf, val)
	return buf[Scoresize:]
}

func (c *Call) Clear() {
	c.Id = 0
	c.Crypto = nil
	c.Codec = nil
	c.Score = nil
	c.Data = nil
	c.Pkt = nil
}

func CheckBanner(banner string) bool {
	if !strings.HasPrefix(banner, "venti-") {
		return false
	}

	ds := strings.SplitN(banner, "-", 3)
	if len(ds) < 3 || ds[0] != "venti" {
		return false
	}

	vs := strings.SplitN(ds[1], ":", -1)
	for i := 0; i < len(vs); i++ {
		if vs[i] == "02" {
			return true
		}
	}

	return false
}
