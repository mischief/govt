// Copyright 2010 The Govt Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vt

import (
	"fmt"
)

func (s Score) String() string {
	ret := ""
	for i := 0; i < Scoresize; i++ {
		ret = fmt.Sprintf("%s%x", ret, s[i])
	}

	return ret
}

func (c *Call) String() string {
	ret := ""

	switch c.Id {
	default:
		ret = fmt.Sprintf("invalid call: %d", c.Id)

	case Rerror:
		ret = fmt.Sprintf("Rerror tag %d '%s'", c.Tag, c.Ename)
	case Tping:
		ret = fmt.Sprintf("Tping tag %d", c.Tag)
	case Rping:
		ret = fmt.Sprintf("Rping tag %d", c.Tag)
	case Thello:
		ret = fmt.Sprintf("Thello tag %d version '%s' uid '%s' strength %d crypto %v codec %v",
			c.Tag, c.Version, c.Uid, c.Strength, c.Crypto, c.Codec)
	case Rhello:
		ret = fmt.Sprintf("Rhello tag %d sid '%s' rcrypto %d rcodec %d", c.Tag, c.Sid, c.Rcrypto, c.Rcodec)
	case Tgoodbye:
		ret = fmt.Sprintf("Tgoodbye tag %d", c.Tag)
	case Tread:
		ret = fmt.Sprintf("Tread tag %d score %v type %d count %d", c.Tag, c.Score, c.Btype, c.Count)
	case Rread:
		b := c.Data
		if len(b) > 32 {
			b = b[0:32]
		}
		ret = fmt.Sprintf("Rread tag %d count %d data %x", c.Tag, len(c.Data), b)
	case Twrite:
		b := c.Data
		if len(b) > 32 {
			b = b[0:32]
		}
		ret = fmt.Sprintf("Twrite tag %d type %d count %d data %x", c.Tag, c.Btype, c.Count, b)
	case Rwrite:
		ret = fmt.Sprintf("Rwrite tag %d score %v", c.Tag, c.Score)
	case Tsync:
		ret = fmt.Sprintf("Tsync tag %d", c.Tag)
	case Rsync:
		ret = fmt.Sprintf("Rsync tag %d", c.Tag)
	}

	return ret
}
