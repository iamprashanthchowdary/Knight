// Package sentinel is Knight's anti-reconnaissance tripwire. It listens on a
// set of TRAP PORTS -- ports your real service never uses (e.g. 23, 3306,
// 6379). A legitimate user has no reason to ever touch them, so any completed
// TCP connection to a trap port is, by definition, a port scanner
// (nmap -sT / -sV / -A all complete the handshake). The connecting IP is
// banned immediately and, via the ban hook, dropped at the kernel firewall --
// which also blinds the rest of a stealth (-sS) sweep from that IP.
//
// Honest limitation: a pure SYN scan (-sS) never completes the TCP handshake,
// so accept() never fires and userspace cannot see it. Catching bare SYNs is
// the kernel's job -- see deploy/nftables.conf.example, which rate-limits and
// traps those and feeds the same ban set.
package sentinel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"knight/internal/guard"
)

// Sentinel owns the trap-port listeners.
type Sentinel struct {
	ports  []int
	bl     *guard.Blocklist
	log    *slog.Logger
	banFor time.Duration
}

// New creates a Sentinel that bans offenders for banFor.
func New(ports []int, bl *guard.Blocklist, log *slog.Logger, banFor time.Duration) *Sentinel {
	return &Sentinel{ports: ports, bl: bl, log: log, banFor: banFor}
}

// Run opens every trap port and serves until ctx is cancelled. Ports that fail
// to bind (already in use, privileged without permission) are logged and
// skipped -- a missing trap must never stop the guard from starting.
func (s *Sentinel) Run(ctx context.Context) {
	var listeners []net.Listener
	for _, p := range s.ports {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
		if err != nil {
			s.log.Warn("sentinel: cannot bind trap port", "port", p, "err", err)
			continue
		}
		listeners = append(listeners, ln)
		s.log.Info("sentinel: trap port armed", "port", p)
		go s.serve(ln, p)
	}
	<-ctx.Done()
	for _, ln := range listeners {
		_ = ln.Close()
	}
}

func (s *Sentinel) serve(ln net.Listener, port int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed on shutdown
		}
		ip := remoteIP(conn)
		// Close immediately: give version probes (-sV) nothing to fingerprint.
		_ = conn.Close()
		if ip == "" || s.bl.Blocked(ip) {
			continue
		}
		s.bl.Block(ip, fmt.Sprintf("sentinel: trap port %d", port), s.banFor)
		s.log.Warn("sentinel: port scan detected, ip banned",
			"ip", ip, "trap_port", port, "ban", s.banFor.String())
	}
}

func remoteIP(c net.Conn) string {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return ""
	}
	return host
}
