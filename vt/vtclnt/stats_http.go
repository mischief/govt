// Copyright 2010 The Govt Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package vtclnt

import (
	"code.google.com/p/govt/vt"
	"fmt"
	"io"
	"net/http"
	"sync"
)

var mux sync.RWMutex
var stat map[string]http.Handler

func register(s string, h http.Handler) {
	mux.Lock()
	if stat == nil {
		stat = make(map[string]http.Handler)
	}

	if h == nil {
		delete(stat, s)
	} else {
		stat[s] = h
	}
	mux.Unlock()
}

func (clnt *Clnt) ServeHTTP(c http.ResponseWriter, r *http.Request) {
	io.WriteString(c, fmt.Sprintf("<html><body><h1>Client %s</h1>", clnt.Id))
	defer io.WriteString(c, "</body></html>")

	// fcalls
	if clnt.Debuglevel&DbgLogCalls != 0 {
		fs := clnt.Log.Filter(clnt, DbgLogCalls)
		io.WriteString(c, fmt.Sprintf("<h2>Last %d Venti messages</h2>", len(fs)))
		for _, l := range fs {
			fc := l.Data.(*vt.Call)
			if fc.Id != 0 {
				io.WriteString(c, fmt.Sprintf("<br>%s", fc))
			}
		}
	}
}

func (clnts *ClntList) ServeHTTP(c http.ResponseWriter, r *http.Request) {
	io.WriteString(c, fmt.Sprintf("<html><body>"))
	defer io.WriteString(c, "</body></html>")

	clnts.Lock()
	if clnts.list == nil {
		io.WriteString(c, "no clients")
	}

	for clnt := clnts.list; clnt != nil; clnt = clnt.next {
		io.WriteString(c, fmt.Sprintf("<a href='/govt/clnt/%s'>%s</a><br>", clnt.Id, clnt.Id))
	}
	clnts.Unlock()
}

func (clnt *Clnt) statsRegister() {
	register("/govt/clnt/"+clnt.Id, clnt)
}

func (clnt *Clnt) statsUnregister() {
	register("/govt/clnt/"+clnt.Id, nil)
}

func (c *ClntList) statsRegister() {
	register("/govt/clnt", c)
}

func (c *ClntList) statsUnregister() {
	register("/govt/clnt", nil)
}
