// Copyright 2012 The Govt Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"code.google.com/p/govt/vt"
	"code.google.com/p/govt/vt/vtclnt"
	"flag"
	"fmt"
	"os"
)

var host = flag.String("host", os.Getenv("venti"), "server address")
var debug = flag.Int("debug", 0, "print debug messages")
var vtype = flag.Int("type", vt.DataBlock, "block type")

func usage() {
	fmt.Fprintf(os.Stderr, "usage: vwrite [flags] <datablock\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	flag.Usage = usage
	flag.Parse()
	reader := bufio.NewReader(os.Stdin)
	p, err := reader.ReadBytes('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %s\n", err)
		return
	}
	if *host == "" {
		*host = ":17034"
	}
	clnt, e := vtclnt.Connect("tcp", *host)
	if e != nil {
		fmt.Fprintf(os.Stderr, "vtconnect: %s\n", e.Ename)
		return
	}
        clnt.Debuglevel = *debug
	score, e := clnt.Put(uint8(*vtype), p)
	if e != nil {
		fmt.Fprintf(os.Stderr, "vtwrite: %s\n", e.Ename)
		return
	}
	clnt.Sync()
	//TODO: clnt.Hangup()
	fmt.Printf("%v\n", score)
}
