package main

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"
)

// Flow export decoders: NetFlow v5, NetFlow v9, IPFIX and sFlow v5, standard library only.
//
// Everything that comes off the wire is hostile: every read is bounds-checked, a datagram can create only a bounded number of
// templates, and a decoder never panics (flow_decode_test.go feeds it random and truncated input).
//
// A NetFlow v9 or IPFIX data record cannot be read without the template its exporter sent earlier.  The templates live in a
// flowTemplates cache that the cluster layer replicates (flow_cluster.go), so when an exporter's packets move to another node
// (the VIP moved, the anycast path changed) that node can read them at once instead of waiting for the next template refresh.

// FlowRec is one decoded flow, with sampling already applied (Bytes and Packets are estimates of the real traffic).
type FlowRec struct {
	Exporter netip.Addr
	Src, Dst netip.Addr
	SrcPort  uint16
	DstPort  uint16
	Proto    uint8
	TCPFlags uint8
	Tos      uint8
	InIf     uint32
	OutIf    uint32
	SrcAS    uint32
	DstAS    uint32
	Bytes    uint64
	Packets  uint64
	Time     time.Time // when the flow ended, as far as the exporter says; the receive time if it says nothing usable
}

const (
	maxTemplatesPerExporter = 512
	maxTemplatesTotal       = 20000
	maxTemplateFields       = 256
	maxRatesTotal           = 20000
)

var errShort = errors.New("flow: truncated packet")

// FlowField is one field of a template (an IPFIX information element or a NetFlow v9 field type).
type FlowField struct {
	ID  uint16 `json:"id"`
	Len uint16 `json:"len"` // 0xFFFF: variable length (IPFIX)
	Ent uint32 `json:"ent,omitempty"`
}

// FlowTemplate is a template as an exporter sent it.
type FlowTemplate struct {
	Exporter netip.Addr  `json:"exporter"`
	Domain   uint32      `json:"domain"`
	ID       uint16      `json:"id"`
	Options  bool        `json:"options,omitempty"`
	Scope    int         `json:"scope,omitempty"` // number of leading scope fields of an options template
	IPFIX    bool        `json:"ipfix,omitempty"`
	Fields   []FlowField `json:"fields"`
}

// FlowRate is a sampling interval an exporter announced in an options record.
type FlowRate struct {
	Exporter netip.Addr `json:"exporter"`
	Domain   uint32     `json:"domain"`
	Rate     uint32     `json:"rate"`
}

type tmplKey struct {
	exp netip.Addr
	dom uint32
	id  uint16
}

type rateKey struct {
	exp netip.Addr
	dom uint32
}

// flowTemplates is the template and sampling-rate cache.
type flowTemplates struct {
	mu    sync.RWMutex
	t     map[tmplKey]*FlowTemplate
	perEx map[netip.Addr]int
	rates map[rateKey]uint32
	// OnLearn is called, without the lock held, for a template or rate that is new or changed (the cluster replicates it).
	OnLearn func(*FlowTemplate, *FlowRate)
}

func newFlowTemplates() *flowTemplates {
	return &flowTemplates{t: map[tmplKey]*FlowTemplate{}, perEx: map[netip.Addr]int{}, rates: map[rateKey]uint32{}}
}

func sameFields(a, b []FlowField) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// put stores a template; it reports whether it is new or changed, and false when a limit refused it.
func (c *flowTemplates) put(t *FlowTemplate) (changed, ok bool) {
	k := tmplKey{t.Exporter, t.Domain, t.ID}
	c.mu.Lock()
	defer c.mu.Unlock()
	old := c.t[k]
	if old != nil {
		if old.Options == t.Options && old.Scope == t.Scope && sameFields(old.Fields, t.Fields) {
			return false, true
		}
	} else {
		if c.perEx[t.Exporter] >= maxTemplatesPerExporter || len(c.t) >= maxTemplatesTotal {
			return false, false
		}
		c.perEx[t.Exporter]++
	}
	c.t[k] = t
	return true, true
}

func (c *flowTemplates) get(exp netip.Addr, dom uint32, id uint16) *FlowTemplate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.t[tmplKey{exp, dom, id}]
}

func (c *flowTemplates) putRate(exp netip.Addr, dom, rate uint32) (changed bool) {
	if rate == 0 {
		return false
	}
	k := rateKey{exp, dom}
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.rates[k]; ok && v == rate {
		return false
	}
	if _, ok := c.rates[k]; !ok && len(c.rates) >= maxRatesTotal {
		return false
	}
	c.rates[k] = rate
	return true
}

func (c *flowTemplates) rate(exp netip.Addr, dom uint32) uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if r := c.rates[rateKey{exp, dom}]; r > 1 {
		return uint64(r)
	}
	return 1
}

// rateAny is the sampling rate of any observation domain of exp (what a listing of exporters shows).
func (c *flowTemplates) rateAny(exp netip.Addr) uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for k, v := range c.rates {
		if k.exp == exp {
			return v
		}
	}
	return 0
}

// Snapshot is everything in the cache, for a node that has just started.
func (c *flowTemplates) Snapshot() ([]*FlowTemplate, []FlowRate) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ts := make([]*FlowTemplate, 0, len(c.t))
	for _, t := range c.t {
		ts = append(ts, t)
	}
	rs := make([]FlowRate, 0, len(c.rates))
	for k, v := range c.rates {
		rs = append(rs, FlowRate{k.exp, k.dom, v})
	}
	return ts, rs
}

// Import takes templates and rates a peer learned.  It does not call OnLearn, so a replica does not echo them back.
func (c *flowTemplates) Import(ts []*FlowTemplate, rs []FlowRate) {
	for _, t := range ts {
		if t == nil || !t.Exporter.IsValid() || len(t.Fields) == 0 || len(t.Fields) > maxTemplateFields {
			continue
		}
		c.put(t)
	}
	for _, r := range rs {
		if r.Exporter.IsValid() {
			c.putRate(r.Exporter, r.Domain, r.Rate)
		}
	}
}

func (c *flowTemplates) learn(t *FlowTemplate, r *FlowRate) {
	if c.OnLearn != nil {
		c.OnLearn(t, r)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────

// beUint reads a big-endian unsigned number of 1 to 8 bytes (the length the template says; exporters shrink counters).
func beUint(b []byte) uint64 {
	if len(b) > 8 {
		b = b[len(b)-8:]
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

func addrOf(b []byte) netip.Addr {
	switch len(b) {
	case 4:
		return netip.AddrFrom4([4]byte(b))
	case 16:
		return netip.AddrFrom16([16]byte(b)).Unmap()
	}
	return netip.Addr{}
}

// DecodeFlow reads one datagram from exporter exp.  now is the receive time.  hint is the port family ("sflow" or "") used
// only when the first bytes do not tell.
func (c *flowTemplates) DecodeFlow(exp netip.Addr, b []byte, now time.Time) ([]FlowRec, error) {
	exp = exp.Unmap()
	if len(b) < 4 {
		return nil, errShort
	}
	if b[0] == 0 && b[1] == 0 { // sFlow's version is a 32-bit 5; NetFlow's is a 16-bit number that is not 0
		return c.decodeSFlow(exp, b, now)
	}
	switch binary.BigEndian.Uint16(b) {
	case 5:
		return decodeV5(exp, b, now)
	case 9:
		return c.decodeV9IPFIX(exp, b, now, false)
	case 10:
		return c.decodeV9IPFIX(exp, b, now, true)
	}
	return nil, errors.New("flow: unknown export format")
}

// ── NetFlow v5 ───────────────────────────────────────────────────────────────────────────────────────────────────

func decodeV5(exp netip.Addr, b []byte, now time.Time) ([]FlowRec, error) {
	if len(b) < 24 {
		return nil, errShort
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	uptime := binary.BigEndian.Uint32(b[4:])
	secs := binary.BigEndian.Uint32(b[8:])
	rate := uint64(binary.BigEndian.Uint16(b[22:]) & 0x3fff)
	if rate == 0 {
		rate = 1
	}
	if n > 30 || len(b) < 24+n*48 {
		return nil, errShort
	}
	out := make([]FlowRec, 0, n)
	for i := 0; i < n; i++ {
		r := b[24+i*48 : 24+(i+1)*48]
		last := binary.BigEndian.Uint32(r[28:])
		f := FlowRec{
			Exporter: exp,
			Src:      netip.AddrFrom4([4]byte(r[0:4])), Dst: netip.AddrFrom4([4]byte(r[4:8])),
			InIf: uint32(binary.BigEndian.Uint16(r[12:])), OutIf: uint32(binary.BigEndian.Uint16(r[14:])),
			Packets: uint64(binary.BigEndian.Uint32(r[16:])) * rate, Bytes: uint64(binary.BigEndian.Uint32(r[20:])) * rate,
			SrcPort: binary.BigEndian.Uint16(r[32:]), DstPort: binary.BigEndian.Uint16(r[34:]),
			TCPFlags: r[37], Proto: r[38], Tos: r[39],
			SrcAS: uint32(binary.BigEndian.Uint16(r[40:])), DstAS: uint32(binary.BigEndian.Uint16(r[42:])),
		}
		f.Time = sysUptimeTime(now, time.Unix(int64(secs), 0), uptime, last)
		out = append(out, f)
	}
	return out, nil
}

// sysUptimeTime turns a "last switched" uptime value into a wall-clock time, or the receive time when that is not believable.
func sysUptimeTime(now, export time.Time, uptime, at uint32) time.Time {
	t := export.Add(-time.Duration(int32(uptime-at)) * time.Millisecond)
	return believable(now, t)
}

// believable keeps t when it is within an hour of the receive time (exporters with a wrong clock would otherwise file their
// flows in the past or the future).
func believable(now, t time.Time) time.Time {
	if d := now.Sub(t); d > time.Hour || d < -time.Hour {
		return now
	}
	return t
}

// ── NetFlow v9 and IPFIX ─────────────────────────────────────────────────────────────────────────────────────────

func (c *flowTemplates) decodeV9IPFIX(exp netip.Addr, b []byte, now time.Time, ipfix bool) ([]FlowRec, error) {
	var dom uint32
	var export time.Time
	var uptime uint32
	var off int
	if ipfix {
		if len(b) < 16 {
			return nil, errShort
		}
		total := int(binary.BigEndian.Uint16(b[2:]))
		if total < 16 || total > len(b) {
			return nil, errShort
		}
		b = b[:total]
		export = time.Unix(int64(binary.BigEndian.Uint32(b[4:])), 0)
		dom = binary.BigEndian.Uint32(b[12:])
		off = 16
	} else {
		if len(b) < 20 {
			return nil, errShort
		}
		uptime = binary.BigEndian.Uint32(b[4:])
		export = time.Unix(int64(binary.BigEndian.Uint32(b[8:])), 0)
		dom = binary.BigEndian.Uint32(b[16:])
		off = 20
	}
	var out []FlowRec
	for off+4 <= len(b) {
		id := binary.BigEndian.Uint16(b[off:])
		l := int(binary.BigEndian.Uint16(b[off+2:]))
		if l < 4 || off+l > len(b) {
			return out, errShort
		}
		body := b[off+4 : off+l]
		off += l
		switch {
		case (!ipfix && id == 0) || (ipfix && id == 2):
			c.readTemplates(exp, dom, body, false, ipfix)
		case (!ipfix && id == 1) || (ipfix && id == 3):
			c.readTemplates(exp, dom, body, true, ipfix)
		case id >= 256:
			t := c.get(exp, dom, id)
			if t == nil {
				flowStats.noTemplate.Add(1)
				continue
			}
			if t.Options {
				c.readOptionData(t, body)
				continue
			}
			out = c.readData(out, exp, dom, t, body, now, export, uptime)
		}
	}
	return out, nil
}

func (c *flowTemplates) readTemplates(exp netip.Addr, dom uint32, b []byte, options, ipfix bool) {
	for len(b) >= 4 {
		var t FlowTemplate
		t.Exporter, t.Domain, t.Options, t.IPFIX = exp, dom, options, ipfix
		t.ID = binary.BigEndian.Uint16(b)
		var nfields, nscope int
		if options {
			if ipfix { // template id, field count, scope field count
				if len(b) < 6 {
					return
				}
				nfields, nscope = int(binary.BigEndian.Uint16(b[2:])), int(binary.BigEndian.Uint16(b[4:]))
				b = b[6:]
			} else { // v9: template id, scope length (bytes), option length (bytes)
				if len(b) < 6 {
					return
				}
				sl, ol := int(binary.BigEndian.Uint16(b[2:])), int(binary.BigEndian.Uint16(b[4:]))
				nscope, nfields = sl/4, sl/4+ol/4
				b = b[6:]
			}
		} else {
			nfields = int(binary.BigEndian.Uint16(b[2:]))
			b = b[4:]
		}
		if t.ID < 256 || nfields == 0 || nfields > maxTemplateFields || nscope > nfields {
			return
		}
		t.Scope = nscope
		for i := 0; i < nfields; i++ {
			if len(b) < 4 {
				return
			}
			f := FlowField{ID: binary.BigEndian.Uint16(b), Len: binary.BigEndian.Uint16(b[2:])}
			b = b[4:]
			if ipfix && f.ID&0x8000 != 0 { // enterprise element: the number follows
				if len(b) < 4 {
					return
				}
				f.ID &^= 0x8000
				f.Ent = binary.BigEndian.Uint32(b)
				b = b[4:]
			}
			t.Fields = append(t.Fields, f)
		}
		changed, ok := c.put(&t)
		if ok && changed {
			tc := t
			c.learn(&tc, nil)
		}
	}
}

// fieldBytes cuts the next field's bytes out of rec; variable-length fields carry their length first.
func fieldBytes(rec []byte, f FlowField) (val, rest []byte, ok bool) {
	n := int(f.Len)
	if f.Len == 0xFFFF {
		if len(rec) < 1 {
			return nil, nil, false
		}
		n = int(rec[0])
		rec = rec[1:]
		if n == 255 {
			if len(rec) < 2 {
				return nil, nil, false
			}
			n = int(binary.BigEndian.Uint16(rec))
			rec = rec[2:]
		}
	}
	if n > len(rec) {
		return nil, nil, false
	}
	return rec[:n], rec[n:], true
}

// recLen is the length of one record when it is the same for all (no variable-length field), else 0.
func recLen(t *FlowTemplate) int {
	n := 0
	for _, f := range t.Fields {
		if f.Len == 0xFFFF {
			return 0
		}
		n += int(f.Len)
	}
	return n
}

func (c *flowTemplates) readData(out []FlowRec, exp netip.Addr, dom uint32, t *FlowTemplate, body []byte, now, export time.Time, uptime uint32) []FlowRec {
	fixed := recLen(t)
	if fixed == 0 && !hasVar(t) {
		return out
	}
	rate := c.rate(exp, dom)
	for len(body) > 0 {
		if fixed > 0 && len(body) < fixed { // padding
			break
		}
		var f FlowRec
		f.Exporter = exp
		var endMs, endUp uint64
		var haveMs, haveUp bool
		rec := body
		ok := true
		for _, fld := range t.Fields {
			var v []byte
			v, rec, ok = fieldBytes(rec, fld)
			if !ok {
				break
			}
			if fld.Ent != 0 {
				continue
			}
			switch fld.ID {
			case 1, 85: // octetDeltaCount, octetTotalCount
				f.Bytes = beUint(v)
			case 2, 86:
				f.Packets = beUint(v)
			case 4:
				f.Proto = uint8(beUint(v))
			case 5:
				f.Tos = uint8(beUint(v))
			case 6:
				f.TCPFlags = uint8(beUint(v))
			case 7:
				f.SrcPort = uint16(beUint(v))
			case 11:
				f.DstPort = uint16(beUint(v))
			case 8, 27:
				f.Src = addrOf(v)
			case 12, 28:
				f.Dst = addrOf(v)
			case 10:
				f.InIf = uint32(beUint(v))
			case 14:
				f.OutIf = uint32(beUint(v))
			case 16:
				f.SrcAS = uint32(beUint(v))
			case 17:
				f.DstAS = uint32(beUint(v))
			case 21: // lastSwitched (v9: uptime milliseconds)
				endUp, haveUp = beUint(v), true
			case 153: // flowEndMilliseconds
				endMs, haveMs = beUint(v), true
			case 151: // flowEndSeconds
				endMs, haveMs = beUint(v)*1000, true
			}
		}
		if !ok {
			break
		}
		switch {
		case haveMs && endMs > 0:
			f.Time = believable(now, time.UnixMilli(int64(endMs)))
		case haveUp && !t.IPFIX:
			f.Time = sysUptimeTime(now, export, uptime, uint32(endUp))
		default:
			f.Time = now
		}
		if f.Packets == 0 && f.Bytes > 0 {
			f.Packets = 1
		}
		f.Bytes *= rate
		f.Packets *= rate
		if f.Src.IsValid() || f.Dst.IsValid() {
			out = append(out, f)
		}
		consumed := len(body) - len(rec)
		if consumed <= 0 {
			break
		}
		body = rec
	}
	return out
}

func hasVar(t *FlowTemplate) bool {
	for _, f := range t.Fields {
		if f.Len == 0xFFFF {
			return true
		}
	}
	return false
}

// readOptionData picks the sampling interval out of an options record (field 34 samplingInterval, 305 samplingPacketInterval,
// 50 flowSamplerRandomInterval).  The rate is taken to hold for the whole observation domain, which is what exporters mean.
func (c *flowTemplates) readOptionData(t *FlowTemplate, body []byte) {
	fixed := recLen(t)
	if fixed == 0 {
		return
	}
	for len(body) >= fixed {
		rec := body[:fixed]
		body = body[fixed:]
		for _, f := range t.Fields {
			v := rec[:f.Len]
			rec = rec[f.Len:]
			if f.Ent == 0 && (f.ID == 34 || f.ID == 305 || f.ID == 50) {
				if r := uint32(beUint(v)); r > 1 && r < 1<<24 {
					if c.putRate(t.Exporter, t.Domain, r) {
						c.learn(nil, &FlowRate{t.Exporter, t.Domain, r})
					}
				}
			}
		}
	}
}

// ── sFlow v5 ─────────────────────────────────────────────────────────────────────────────────────────────────────

func (c *flowTemplates) decodeSFlow(exp netip.Addr, b []byte, now time.Time) ([]FlowRec, error) {
	r := &sfReader{b: b}
	if r.u32() != 5 {
		return nil, errors.New("flow: sFlow version is not 5")
	}
	switch r.u32() { // agent address type
	case 1:
		r.skip(4)
	case 2:
		r.skip(16)
	default:
		return nil, errors.New("flow: sFlow agent address")
	}
	r.skip(12) // sub agent, sequence, uptime
	n := r.u32()
	if r.err {
		return nil, errShort
	}
	var out []FlowRec
	for i := uint32(0); i < n && !r.err; i++ {
		typ, l := r.u32(), int(r.u32())
		body := r.take(l)
		if r.err {
			break
		}
		if typ == 1 || typ == 3 {
			out = sfFlowSample(out, exp, typ == 3, body, now)
		}
	}
	return out, nil
}

type sfReader struct {
	b   []byte
	err bool
}

func (r *sfReader) take(n int) []byte {
	if n < 0 || n > len(r.b) {
		r.err = true
		r.b = nil
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
func (r *sfReader) skip(n int) { r.take(n) }
func (r *sfReader) u32() uint32 {
	v := r.take(4)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v)
}

func sfFlowSample(out []FlowRec, exp netip.Addr, expanded bool, b []byte, now time.Time) []FlowRec {
	r := &sfReader{b: b}
	r.skip(4) // sequence
	if expanded {
		r.skip(8) // source id type and index
	} else {
		r.skip(4)
	}
	rate := uint64(r.u32())
	r.skip(8) // pool, drops
	var in, outIf uint32
	if expanded {
		r.skip(4)
		in = r.u32()
		r.skip(4)
		outIf = r.u32()
	} else {
		in, outIf = r.u32(), r.u32()
	}
	nrec := r.u32()
	if r.err {
		return out
	}
	if rate == 0 {
		rate = 1
	}
	for i := uint32(0); i < nrec && !r.err; i++ {
		tag, l := r.u32(), int(r.u32())
		body := r.take(l)
		if r.err {
			break
		}
		if tag != 1 { // raw packet header
			continue
		}
		rr := &sfReader{b: body}
		proto := rr.u32()
		frame := rr.u32()
		rr.skip(4)
		hl := int(rr.u32())
		hdr := rr.take(hl)
		if rr.err || proto != 1 {
			continue
		}
		f, ok := parseEthernet(hdr)
		if !ok {
			continue
		}
		f.Exporter = exp
		f.InIf, f.OutIf = in&0x3fffffff, outIf&0x3fffffff
		f.Bytes = uint64(frame) * rate
		f.Packets = rate
		f.Time = now
		out = append(out, f)
	}
	return out
}

// parseEthernet reads the addresses, protocol and ports out of a sampled frame header.
func parseEthernet(h []byte) (FlowRec, bool) {
	var f FlowRec
	if len(h) < 14 {
		return f, false
	}
	et := binary.BigEndian.Uint16(h[12:])
	h = h[14:]
	for et == 0x8100 || et == 0x88a8 { // VLAN tags
		if len(h) < 4 {
			return f, false
		}
		et = binary.BigEndian.Uint16(h[2:])
		h = h[4:]
	}
	var l4 []byte
	switch et {
	case 0x0800:
		if len(h) < 20 {
			return f, false
		}
		ihl := int(h[0]&0x0f) * 4
		if h[0]>>4 != 4 || ihl < 20 || len(h) < ihl {
			return f, false
		}
		f.Tos, f.Proto = h[1], h[9]
		f.Src, f.Dst = addrOf(h[12:16]), addrOf(h[16:20])
		if binary.BigEndian.Uint16(h[6:])&0x1fff == 0 { // not a later fragment
			l4 = h[ihl:]
		}
	case 0x86dd:
		if len(h) < 40 {
			return f, false
		}
		f.Tos = uint8(binary.BigEndian.Uint16(h) >> 4)
		f.Proto = h[6]
		f.Src, f.Dst = addrOf(h[8:24]), addrOf(h[24:40])
		l4 = h[40:]
	default:
		return f, false
	}
	if (f.Proto == 6 || f.Proto == 17) && len(l4) >= 4 {
		f.SrcPort, f.DstPort = binary.BigEndian.Uint16(l4), binary.BigEndian.Uint16(l4[2:])
		if f.Proto == 6 && len(l4) >= 14 {
			f.TCPFlags = l4[13]
		}
	}
	return f, true
}
