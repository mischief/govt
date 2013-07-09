// Copyright 2010 The Govt Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vt

//import "log"

const VtCorruptType = 0xFF

const (
	Overrtype = iota
	Ovroottype
	Ovdirtype
	Ovptype0
	Ovptype1
	Ovptype2
	Ovptype3
	Ovptype4
	Ovptype5
	Ovptype6
	Ovptype7
	Ovptype8
	Ovptype9
	Ovdtype
	Ovmaxtype
)

var todisk = [...]uint8{
	Ovdtype,
	Ovptype0,
	Ovptype1,
	Ovptype2,
	Ovptype3,
	Ovptype4,
	Ovptype5,
	Ovptype6,
	Ovdirtype,
	Ovptype0,
	Ovptype1,
	Ovptype2,
	Ovptype3,
	Ovptype4,
	Ovptype5,
	Ovptype6,
	Ovroottype,
}

var fromdisk = [...]uint8{
	VtCorruptType,
	RBlock,
	DirBlock,
	DirBlock + 1,
	DirBlock + 2,
	DirBlock + 3,
	DirBlock + 4,
	DirBlock + 5,
	DirBlock + 6,
	DirBlock + 7,
	VtCorruptType,
	VtCorruptType,
	VtCorruptType,
	DataBlock,
}

var Epacket *Error = &Error{"invalid packet"}
var Eblktype *Error = &Error{"invalid block type"}

func fromDiskType(val uint8) uint8 {
	if int(val) > len(fromdisk) {
		return VtCorruptType
	}

	return fromdisk[val]
}

func toDiskType(val uint8) uint8 {
	if int(val) > len(todisk) {
		return VtCorruptType
	}

	return todisk[val]
}

func PackCall(buf []byte, id uint8, tag uint8, size int) (int, []byte) {
	size += 2 + 1 + 1 // size[2] id[1] tag[1]
	if len(buf) < size {
		return -1, nil
	}

	buf = Pint16(uint16(size-2), buf)
	buf = Pint8(id, buf)
	buf = Pint8(tag, buf)

	return size, buf
}

func PackEmpty(buf []byte, id, tag uint8) int {
	sz, buf := PackCall(buf, id, tag, 0)
	if buf == nil {
		return -1
	}

	return sz
}

func PackTping(buf []byte, tag uint8) int {
	return PackEmpty(buf, Tping, tag)
}

func PackThello(buf []byte, tag uint8, version, uid string, strength uint8, crypto, codec []byte) int {
	sz, buf := PackCall(buf, Thello, tag,
		7+len(version)+len(uid)+len(crypto)+len(codec)) // vesion[s] uid[s] strength[1] crypto[n] codec[n]
	if buf == nil {
		return -1
	}

	buf = Pstr(version, buf)
	buf = Pstr(uid, buf)
	buf = Pint8(strength, buf)
	buf = Pvar(crypto, buf)
	Pvar(codec, buf)

	return sz
}

func PackTgoodbye(buf []byte, tag uint8) int {
	return PackEmpty(buf, Tgoodbye, tag)
}

func PackTread(buf []byte, tag uint8, score Score, btype uint8, count uint16) int {
	sz, buf := PackCall(buf, Tread, tag, Scoresize+1+1+2) // score[20] type[1] pad[1] count[2]
	if buf == nil {
		return -1
	}

	buf = Pscore(score, buf)
	buf = Pint8(toDiskType(btype), buf)
	buf = Pint8(0, buf)
	Pint16(count, buf)

	return sz
}

func PackTwrite(buf []byte, tag uint8, btype uint8, data []byte) int {
	sz, buf := PackCall(buf, Twrite, tag, 1+3+len(data)) // type[1] pad[3] data
	if buf == nil {
		return -1
	}

	buf = Pint8(toDiskType(btype), buf)
	buf = Pint8(0, buf)
	buf = Pint16(0, buf)
	copy(buf, data)

	return sz
}

func PackTsync(buf []byte, tag uint8) int {
	return PackEmpty(buf, Tsync, tag)
}

func PackRerror(buf []byte, tag uint8, ename string) int {
	sz, buf := PackCall(buf, Rerror, tag, len(ename)+2)
	if buf == nil {
		return -1
	}

	Pstr(ename, buf)
	return sz
}

func PackRping(buf []byte, tag uint8) int {
	return PackEmpty(buf, Rping, tag)
}

func PackRhello(buf []byte, tag uint8, sid string, rcrypto, rcodec uint8) int {
	sz, buf := PackCall(buf, Rhello, tag, len(sid)+4)
	if buf == nil {
		return -1
	}

	buf = Pstr(sid, buf)
	buf = Pint8(rcrypto, buf)
	Pint8(rcodec, buf)

	return sz
}

func PackRread(buf []byte, tag uint8, data []byte) int {
	sz, buf := PackCall(buf, Rread, tag, len(data))
	if buf == nil {
		return -1
	}

	copy(buf, data)

	return sz

}

func PackRwrite(buf []byte, tag uint8, score Score) int {
	sz, buf := PackCall(buf, Rwrite, tag, Scoresize)
	if buf == nil {
		return -1
	}

	Pscore(score, buf)
	return sz
}

func PackRsync(buf []byte, tag uint8) int {
	return PackEmpty(buf, Rsync, tag)
}

func Pack(buf []byte, vc *Call) int {
	tag := vc.Tag

	sz := -1
	switch vc.Id {
	case Rerror:
		sz = PackRerror(buf, tag, vc.Ename)

	case Tping:
		sz = PackTping(buf, tag)

	case Rping:
		sz = PackRping(buf, tag)

	case Thello:
		sz = PackThello(buf, tag, vc.Version, vc.Uid, vc.Strength, vc.Crypto, vc.Codec)

	case Rhello:
		sz = PackRhello(buf, tag, vc.Sid, vc.Rcrypto, vc.Rcodec)

	case Tgoodbye:
		sz = PackTgoodbye(buf, tag)

	case Tread:
		sz = PackTread(buf, tag, vc.Score, vc.Btype, vc.Count)

	case Rread:
		sz = PackRread(buf, tag, vc.Data)

	case Twrite:
		sz = PackTwrite(buf, tag, vc.Btype, vc.Data)

	case Rwrite:
		sz = PackRwrite(buf, tag, vc.Score)

	case Tsync:
		sz = PackTsync(buf, tag)

	case Rsync:
		sz = PackRsync(buf, tag)
	}

	if sz > 0 {
		vc.Pkt = buf[0:sz]
	}

	return sz
}

func Unpack(buf []byte, vc *Call) (int, *Error) {
	var sz uint16

	if len(buf) < 4 {
		return 0, nil
	}

	vc.Pkt = buf
	sz, buf = Gint16(buf)
	if (int(sz)) > len(buf) {
		return 0, nil
	}

	vc.Pkt = vc.Pkt[0 : sz+2]
	buf = buf[0:sz]
	vc.Id, buf = Gint8(buf)
	vc.Tag, buf = Gint8(buf)

	switch vc.Id {
	default:
		return 0, Epacket

	case Rerror:
		vc.Ename, buf = Gstr(buf)

	case Thello:
		vc.Version, buf = Gstr(buf)
		vc.Uid, buf = Gstr(buf)
		if buf == nil || len(buf) < 1 {
			return 0, Epacket
		}

		vc.Strength, buf = Gint8(buf)
		vc.Crypto, buf = Gvar(buf)
		vc.Codec, buf = Gvar(buf)

	case Rhello:
		vc.Sid, buf = Gstr(buf)
		if buf == nil || len(buf) < 2 {
			return 0, Epacket
		}

		vc.Rcrypto, buf = Gint8(buf)
		vc.Rcodec, buf = Gint8(buf)

	case Tread:
		vc.Score, buf = Gscore(buf)
		if buf == nil || len(buf) < 4 {
			return 0, Epacket
		}

		vc.Btype, buf = Gint8(buf)
		n := fromDiskType(vc.Btype)
		if n < 0 {
			return 0, Eblktype
		}
		vc.Btype = uint8(n)

		_, buf = Gint8(buf)
		vc.Count, buf = Gint16(buf)

	case Rread:
		vc.Data = buf
		buf = buf[len(buf):]

	case Twrite:
		if len(buf) < 4 {
			return 0, Epacket
		}

		vc.Btype, buf = Gint8(buf)
		n := fromDiskType(vc.Btype)
		if n < 0 {
			return 0, Eblktype
		}
		vc.Btype = uint8(n)
		vc.Data = buf[3:]
		buf = buf[len(buf):]

	case Rwrite:
		vc.Score, buf = Gscore(buf)

	case Tping:
	case Rping:
	case Tgoodbye:
	case Tsync:
	case Rsync:
		// nothing
	}

	if buf == nil || len(buf) > 0 {
		return 0, Epacket
	}

	return int(sz + 2), nil
}
