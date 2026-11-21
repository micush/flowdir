package main

import (
	"net/netip"
	"strings"
)

// Interface names.  An exporter may announce, in an options record, the names of its interfaces: the interface number (field 10 or 14,
// or the scope "interface" of NetFlow v9) and interfaceName (82) or interfaceDescription (83).  Those are kept per exporter and
// interface number, so "if 6" of one exporter and "if 6" of another have each their own name, and an exporter that sends none keeps
// the number.  Nothing is asked of the exporter and nothing has to be set up.

const (
	maxIfNamesTotal = 50000
	maxIfNameLen    = 64
)

// FlowIfName is the name an exporter gave one of its interfaces.
type FlowIfName struct {
	Exporter netip.Addr `json:"exporter"`
	Index    uint32     `json:"index"`
	Name     string     `json:"name"`
}

type ifnKey struct {
	exp netip.Addr
	idx uint32
}

// putIfName keeps a name; true when it is new or changed.
func (c *flowTemplates) putIfName(exp netip.Addr, idx uint32, name string) bool {
	if idx == 0 || name == "" {
		return false
	}
	k := ifnKey{exp, idx}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ifn == nil {
		c.ifn = map[ifnKey]string{}
	}
	if v, ok := c.ifn[k]; ok && v == name {
		return false
	}
	if _, ok := c.ifn[k]; !ok && len(c.ifn) >= maxIfNamesTotal {
		return false
	}
	c.ifn[k] = name
	return true
}

// ifName is the name exp gave interface idx ("" when it gave none).
func (c *flowTemplates) ifName(exp netip.Addr, idx uint32) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ifn[ifnKey{exp, idx}]
}

// SnapshotIfNames is every interface name, for a node that has just started and for the file.
func (c *flowTemplates) SnapshotIfNames() []FlowIfName {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]FlowIfName, 0, len(c.ifn))
	for k, v := range c.ifn {
		out = append(out, FlowIfName{k.exp, k.idx, v})
	}
	return out
}

// ImportIfNames takes names a peer learned.  It does not call OnLearnIfName, so a replica does not echo them back.
func (c *flowTemplates) ImportIfNames(ns []FlowIfName) {
	for _, n := range ns {
		if n.Exporter.IsValid() {
			c.putIfName(n.Exporter, n.Index, cleanIfName(n.Name))
		}
	}
}

// cleanIfName cuts the padding and anything that is not printable, and the length.
func cleanIfName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimRight(s, "\x00 "))
	s = strings.TrimSpace(s)
	if len(s) > maxIfNameLen {
		s = s[:maxIfNameLen]
	}
	return s
}

// readIfNames takes the interface names out of one options data set; false when the template has none.
func (c *flowTemplates) readIfNames(t *FlowTemplate, body []byte) bool {
	idxAt, nameAt, descAt := -1, -1, -1
	for i, f := range t.Fields {
		if f.Ent != 0 {
			continue
		}
		switch {
		case (f.ID == 10 || f.ID == 14) && idxAt < 0, !t.IPFIX && i < t.Scope && f.ID == 2 && idxAt < 0:
			idxAt = i
		case f.ID == 82:
			nameAt = i
		case f.ID == 83:
			descAt = i
		}
	}
	if idxAt < 0 || (nameAt < 0 && descAt < 0) {
		return false
	}
	fixed := recLen(t)
	for len(body) > 0 {
		rec := body
		if fixed > 0 {
			if len(body) < fixed {
				break
			}
			rec, body = body[:fixed], body[fixed:]
		}
		var idx uint32
		var name, desc string
		for i, f := range t.Fields {
			v, rest, ok := fieldBytes(rec, f)
			if !ok {
				return true
			}
			rec = rest
			switch i {
			case idxAt:
				idx = uint32(beUint(v))
			case nameAt:
				name = cleanIfName(string(v))
			case descAt:
				desc = cleanIfName(string(v))
			}
		}
		if fixed == 0 {
			body = rec
		}
		if name == "" {
			name = desc
		}
		if c.putIfName(t.Exporter, idx, name) && c.OnLearnIfName != nil {
			c.OnLearnIfName(FlowIfName{t.Exporter, idx, name})
		}
	}
	return true
}
