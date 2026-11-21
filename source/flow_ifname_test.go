package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestInterfaceNamesFromOptions(t *testing.T) {
	c := newFlowTemplates()
	var learned []FlowIfName
	c.OnLearnIfName = func(n FlowIfName) { learned = append(learned, n) }
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")

	// IPFIX options template 300: scope ingressInterface (10, 4 bytes), interfaceName (82, variable)
	tp := []byte{1, 44, 0, 2, 0, 1, 0, 10, 0, 4, 0, 82, 0xFF, 0xFF}
	c.readTemplates(a, 1, tp, true, true)
	rec := func(idx uint32, name string) []byte {
		r := binary.BigEndian.AppendUint32(nil, idx)
		return append(append(r, byte(len(name))), name...)
	}
	data := append(rec(6, "wan1"), rec(3, "lan")...)
	c.readOptionData(c.get(a, 1, 300), data)
	if got := c.ifName(a, 6); got != "wan1" {
		t.Fatalf("a if 6 = %q", got)
	}
	if got := c.ifName(a, 3); got != "lan" {
		t.Fatalf("a if 3 = %q", got)
	}
	if got := c.ifName(b, 6); got != "" {
		t.Fatalf("b if 6 = %q, want none: names are per exporter", got)
	}

	// NetFlow v9 options template 400: scope interface (2, 4 bytes), IF_NAME (82, 8 bytes, padded)
	tv := []byte{1, 144, 0, 4, 0, 4, 0, 2, 0, 4, 0, 82, 0, 8}
	c.readTemplates(b, 1, tv, true, false)
	r := binary.BigEndian.AppendUint32(nil, 6)
	r = append(r, "eth0\x00\x00\x00\x00"...)
	c.readOptionData(c.get(b, 1, 400), r)
	if got := c.ifName(b, 6); got != "eth0" {
		t.Fatalf("b if 6 = %q", got)
	}
	if got := c.ifName(a, 6); got != "wan1" {
		t.Fatalf("a if 6 changed to %q", got)
	}
	if len(learned) != 3 {
		t.Fatalf("learned %d, want 3", len(learned))
	}
	c.readOptionData(c.get(a, 1, 300), rec(6, "wan1")) // the same again: nothing new
	if len(learned) != 3 {
		t.Fatalf("a repeat was learned again")
	}
	d := newFlowTemplates()
	d.ImportIfNames(c.SnapshotIfNames())
	if d.ifName(b, 6) != "eth0" || d.ifName(a, 3) != "lan" {
		t.Fatal("import lost names")
	}
}
