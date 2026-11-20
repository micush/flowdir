package main

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func TestDatagramDestinationIsReported(t *testing.T) {
	for _, c := range []struct{ network, bind, to string }{{"udp4", "0.0.0.0:0", "127.0.0.1"}, {"udp6", "[::]:0", "::1"}} {
		lc := net.ListenConfig{Control: flowListenControl}
		pc, err := lc.ListenPacket(context.Background(), c.network, c.bind)
		if err != nil {
			t.Logf("%s: %v (skipped)", c.network, err)
			continue
		}
		u := pc.(*net.UDPConn)
		port := u.LocalAddr().(*net.UDPAddr).Port
		cl, err := net.Dial(c.network, net.JoinHostPort(c.to, strconv.Itoa(port)))
		if err != nil {
			pc.Close()
			t.Logf("%s: %v (skipped)", c.network, err)
			continue
		}
		cl.Write([]byte("hello"))
		u.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf, oob := make([]byte, 100), make([]byte, 256)
		n, oobn, _, _, err := u.ReadMsgUDPAddrPort(buf, oob)
		cl.Close()
		pc.Close()
		if err != nil || n != 5 {
			t.Errorf("%s: read %d %v", c.network, n, err)
			continue
		}
		if got := pktinfoDst(oob[:oobn]); got != netip.MustParseAddr(c.to) {
			t.Errorf("%s: destination %v, want %s", c.network, got, c.to)
		}
	}
	if pktinfoDst(nil).IsValid() || pktinfoDst([]byte{1, 2, 3}).IsValid() {
		t.Error("a destination from nothing")
	}
}

func TestExporterRemembersWhereItSends(t *testing.T) {
	s := newTestFlowSvc()
	s.exporters = map[netip.Addr]*flowExporter{}
	exp := netip.MustParseAddr("192.0.2.7")
	now := time.Now()
	s.noteExporter(exp, netip.MustParseAddr("10.9.9.1"), []byte{0, 9, 0, 0}, 1, now)
	s.noteExporter(exp, netip.MustParseAddr("10.9.9.2"), []byte{0, 9, 0, 0}, 1, now)
	s.noteExporter(exp, netip.Addr{}, []byte{0, 9, 0, 0}, 1, now) // not known: nothing added
	got := s.Exporters()
	if len(got) != 1 || len(got[0].To) != 2 || got[0].To[0] != "10.9.9.1" || got[0].To[1] != "10.9.9.2" {
		t.Fatalf("exporters: %+v", got)
	}
	// an old destination is not reported
	s.mu.Lock()
	s.exporters[exp].To[netip.MustParseAddr("10.9.9.1")] = now.Add(-time.Hour)
	s.mu.Unlock()
	if got := s.Exporters(); len(got[0].To) != 1 || got[0].To[0] != "10.9.9.2" {
		t.Errorf("an hour-old destination is still reported: %+v", got[0].To)
	}
}

func TestTopologySquareLimitIsASetting(t *testing.T) {
	dc := newDaemonConfig()
	dc.Settings.TopologySquaresAbove = 5001
	if err := dc.Validate(); err == nil {
		t.Error("5001 was accepted")
	}
	dc.Settings.TopologySquaresAbove = 50
	if err := dc.Validate(); err != nil {
		t.Errorf("50: %v", err)
	}
}

func TestExporterHostIsTheFirstLabelOfItsReverseName(t *testing.T) {
	s := newTestFlowSvc()
	s.exporters = map[netip.Addr]*flowExporter{}
	a, b := netip.MustParseAddr("192.168.5.1"), netip.MustParseAddr("192.168.5.2")
	s.noteExporter(a, netip.Addr{}, []byte{0, 9, 0, 0}, 1, time.Now())
	s.noteExporter(b, netip.Addr{}, []byte{0, 9, 0, 0}, 1, time.Now())
	s.dns.mu.Lock()
	s.dns.m[a] = dnsEnt{"Sw1.Example.com.", time.Now()}
	s.dns.m[b] = dnsEnt{"", time.Now()} // looked up: no name
	s.dns.mu.Unlock()
	got := s.Exporters()
	if len(got) != 2 || got[0].Host != "Sw1" || got[1].Host != "" {
		t.Errorf("hosts: %+v", got)
	}
	for in, want := range map[string]string{"sw1.example.com": "sw1", "sw1": "sw1", "a.b.": "a", "": ""} {
		if g := hostPart(in); g != want {
			t.Errorf("hostPart(%q) = %q, want %q", in, g, want)
		}
	}
}
