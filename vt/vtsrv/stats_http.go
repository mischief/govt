// Copyright 2010 The Govt Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package vtsrv

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

func (srv *Srv) statsRegister() {
	register("/govt/srv/"+srv.Id, srv)
}

func (srv *Srv) statsUnregister() {
	register("/govt/srv/"+srv.Id, nil)
}

func (srv *Srv) ServeHTTP(c http.ResponseWriter, r *http.Request) {
	io.WriteString(c, fmt.Sprintf("<html><body><h1>Server %s</h1>", srv.Id))
	defer io.WriteString(c, "</body></html>")

	// connections
	io.WriteString(c, "<h2>Connections</h2><p>")
	srv.Lock()
	if srv.connlist == nil {
		io.WriteString(c, "none")
	}

	nreqs := srv.nreqs
	tsz := srv.tsz
	rsz := srv.rsz
	maxpend := srv.maxpend
	nreads := srv.nreads
	nwrites := srv.nwrites

	for conn := srv.connlist; conn != nil; conn = conn.next {
		io.WriteString(c, fmt.Sprintf("<a href='/govt/srv/%s/conn/%s'>%s</a><br>", srv.Id, conn.Id, conn.Id))

		conn.Lock()
		nreqs += conn.nreqs
		tsz += conn.tsz
		rsz += conn.rsz
		maxpend += conn.maxpend
		nreads += conn.nreads
		nwrites += conn.nwrites
		conn.Unlock()
	}
	srv.Unlock()

	io.WriteString(c, "<h2>Statistics</h2>\n")
	io.WriteString(c, fmt.Sprintf("<p>Number of processed requests: %d", nreqs))
	io.WriteString(c, fmt.Sprintf("<br>Sent %v bytes", rsz))
	io.WriteString(c, fmt.Sprintf("<br>Received %v bytes", tsz))
	io.WriteString(c, fmt.Sprintf("<br>Max pending requests: %d", maxpend))
	io.WriteString(c, fmt.Sprintf("<br>Number of reads: %d", nreads))
	io.WriteString(c, fmt.Sprintf("<br>Number of writes: %d", nwrites))
}

func (conn *Conn) statsRegister() {
	register("/govt/srv/"+conn.Srv.Id+"/conn/"+conn.Id, conn)
}

func (conn *Conn) statsUnregister() {
	register("/govt/srv/"+conn.Srv.Id+"/conn/"+conn.Id, nil)
}

func (conn *Conn) ServeHTTP(c http.ResponseWriter, r *http.Request) {
	io.WriteString(c, fmt.Sprintf("<html><body><h1>Connection %s/%s</h1>", conn.Srv.Id, conn.Id))
	defer io.WriteString(c, "</body></html>")

	// statistics
	conn.Lock()
	io.WriteString(c, fmt.Sprintf("<p>Number of processed requests: %d", conn.nreqs))
	io.WriteString(c, fmt.Sprintf("<br>Sent %v bytes", conn.rsz))
	io.WriteString(c, fmt.Sprintf("<br>Received %v bytes", conn.tsz))
	io.WriteString(c, fmt.Sprintf("<br>Pending requests: %d max %d", conn.npend, conn.maxpend))
	io.WriteString(c, fmt.Sprintf("<br>Number of reads: %d", conn.nreads))
	io.WriteString(c, fmt.Sprintf("<br>Number of writes: %d", conn.nwrites))
	conn.Unlock()

	// fcalls
	if conn.Debuglevel&DbgLogCalls != 0 {
		fs := conn.Srv.Log.Filter(conn, DbgLogCalls)
		io.WriteString(c, fmt.Sprintf("<h2>Last %d Venti messages</h2>", len(fs)))
		for i, l := range fs {
			vc := l.Data.(*vt.Call)
			if vc.Id == 0 {
				continue
			}

			lbl := ""
			if vc.Id%2 == 0 {
				// try to find the response for the T message
				for j := i + 1; j < len(fs); j++ {
					rc := fs[j].Data.(*vt.Call)
					if rc.Tag == vc.Tag {
						lbl = fmt.Sprintf("<a href='#fc%d'>&#10164;</a>", j)
						break
					}
				}
			} else {
				// try to find the request for the R message
				for j := i - 1; j >= 0; j-- {
					tc := fs[j].Data.(*vt.Call)
					if tc.Tag == vc.Tag {
						lbl = fmt.Sprintf("<a href='#fc%d'>&#10166;</a>", j)
						break
					}
				}
			}

			io.WriteString(c, fmt.Sprintf("<br id='fc%d'>%d: %s%s", i, i, vc, lbl))
		}
	}
}

func StatsHandler(c http.ResponseWriter, r *http.Request) {
        mux.RLock()
        if v, ok := stat[r.URL.Path]; ok {
                v.ServeHTTP(c, r)
        } else if r.URL.Path == "/govt/" {
                io.WriteString(c, fmt.Sprintf("<html><body><br><h1>On offer: </h1><br>"))
                for v := range stat {
                        io.WriteString(c, fmt.Sprintf("<a href='%s'>%s</a><br>", v, v))
                }
                io.WriteString(c, "</body></html>")
        }
        mux.RUnlock()
}

// StartStatsServer initializes and starts an http server displaying useful debugging
// information about the available servers, the clients connected to them and 
// statistics about the data transferred on each connection. It listens by default on
// port :6060 and serves subdirectories under /govt/
//
// If StartStatsServer isn't called the interface is not initialized. The StartStatsServer
// function can be called at any time. Information about the available servers is kept up-to-date.
func (srv *Srv) StartStatsServer() {
        http.HandleFunc("/govt/", StatsHandler)
        go http.ListenAndServe(":6060", nil)
}
