package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

var (
	tExp   = netip.MustParseAddr("192.0.2.1")
	tNow   = time.Unix(1_800_000_000, 0)
	tHostA = netip.MustParseAddr("10.0.0.5")
	tHostB = netip.MustParseAddr("203.0.113.9")
)

func be16(b *bytes.Buffer, v uint16) { binary.Write(b, binary.BigEndian, v) }
func be32(b *bytes.Buffer, v uint32) { binary.Write(b, binary.BigEndian, v) }

func v5Packet(rate uint16) []byte {
	var b bytes.Buffer
	be16(&b, 5)
	be16(&b, 1)
	be32(&b, 100000)               // uptime ms
	be32(&b, uint32(tNow.Unix()))  // secs
	be32(&b, 0)                    // nsecs
	be32(&b, 0)                    // seq
	b.Write([]byte{0, 0})          // engine
	be16(&b, rate)                 // sampling
	b.Write(tHostA.AsSlice())      // src
	b.Write(tHostB.AsSlice())      // dst
	b.Write([]byte{0, 0, 0, 0})    // nexthop
	be16(&b, 3)                    // in
	be16(&b, 4)                    // out
	be32(&b, 10)                   // pkts
	be32(&b, 12000)                // bytes
	be32(&b, 90000)                // first
	be32(&b, 99000)                // last
	be16(&b, 51234)                // sport
	be16(&b, 443)                  // dport
	b.Write([]byte{0, 0x1b, 6, 0}) // pad, flags, proto, tos
	be16(&b, 64512)                // src as
	be16(&b, 15169)                // dst as
	b.Write([]byte{24, 24, 0, 0})  // masks, pad
	return b.Bytes()
}

func TestDecodeV5(t *testing.T) {
	c := newFlowTemplates()
	recs, err := c.DecodeFlow(tExp, v5Packet(0), tNow)
	if err != nil || len(recs) != 1 {
		t.Fatalf("v5: %v %v", recs, err)
	}
	r := recs[0]
	if r.Src != tHostA || r.Dst != tHostB || r.DstPort != 443 || r.Proto != 6 || r.Bytes != 12000 || r.Packets != 10 || r.InIf != 3 || r.OutIf != 4 || r.SrcAS != 64512 || r.DstAS != 15169 {
		t.Errorf("v5 record: %+v", r)
	}
	if d := tNow.Sub(r.Time); d < 0 || d > 5*time.Second { // last switched is 1 s before the export
		t.Errorf("v5 time %v vs %v", r.Time, tNow)
	}
	recs, _ = c.DecodeFlow(tExp, v5Packet(100), tNow) // sampled 1 in 100
	if recs[0].Bytes != 1_200_000 || recs[0].Packets != 1000 {
		t.Errorf("v5 sampled: %+v", recs[0])
	}
}

// v9Template: id 256, src4 dst4 sport dport proto bytes(4) pkts(4) in out lastswitched
func v9TemplateSet() []byte {
	var s bytes.Buffer
	be16(&s, 0) // flowset id: template
	fields := [][2]uint16{{8, 4}, {12, 4}, {7, 2}, {11, 2}, {4, 1}, {1, 4}, {2, 4}, {10, 2}, {14, 2}, {21, 4}}
	be16(&s, uint16(4+4+4*len(fields)))
	be16(&s, 256)
	be16(&s, uint16(len(fields)))
	for _, f := range fields {
		be16(&s, f[0])
		be16(&s, f[1])
	}
	return s.Bytes()
}

func v9DataSet() []byte {
	var s bytes.Buffer
	be16(&s, 256)
	be16(&s, 4+2*(4+4+2+2+1+4+4+2+2+4)+0)
	for i := 0; i < 2; i++ {
		s.Write(tHostA.AsSlice())
		s.Write(tHostB.AsSlice())
		be16(&s, 40000)
		be16(&s, 53)
		s.WriteByte(17)
		be32(&s, 500)
		be32(&s, 2)
		be16(&s, 7)
		be16(&s, 8)
		be32(&s, 99000)
	}
	return s.Bytes()
}

func v9Header(sets ...[]byte) []byte {
	var b bytes.Buffer
	be16(&b, 9)
	be16(&b, uint16(len(sets)))
	be32(&b, 100000)
	be32(&b, uint32(tNow.Unix()))
	be32(&b, 1)
	be32(&b, 77) // source id
	for _, s := range sets {
		b.Write(s)
	}
	return b.Bytes()
}

func TestDecodeV9TemplateThenData(t *testing.T) {
	c := newFlowTemplates()
	var learned int
	c.OnLearn = func(*FlowTemplate, *FlowRate) { learned++ }
	// data before its template is counted and skipped
	before := flowStats.noTemplate.Load()
	recs, _ := c.DecodeFlow(tExp, v9Header(v9DataSet()), tNow)
	if len(recs) != 0 || flowStats.noTemplate.Load() != before+1 {
		t.Fatalf("data without a template: %d records", len(recs))
	}
	recs, err := c.DecodeFlow(tExp, v9Header(v9TemplateSet(), v9DataSet()), tNow)
	if err != nil || len(recs) != 2 || learned != 1 {
		t.Fatalf("v9: %v %v learned=%d", recs, err, learned)
	}
	if r := recs[0]; r.DstPort != 53 || r.Proto != 17 || r.Bytes != 500 || r.InIf != 7 || r.OutIf != 8 {
		t.Errorf("v9 record %+v", r)
	}
	// the same template again changes nothing and is not announced again
	c.DecodeFlow(tExp, v9Header(v9TemplateSet()), tNow)
	if learned != 1 {
		t.Errorf("an unchanged template was learned again")
	}
	// another exporter has its own templates
	if recs, _ := c.DecodeFlow(netip.MustParseAddr("192.0.2.2"), v9Header(v9DataSet()), tNow); len(recs) != 0 {
		t.Errorf("templates leaked between exporters")
	}
}

// A node that got the templates from a peer reads the data at once: the point of the cluster replication.
func TestTemplatesImportedFromPeer(t *testing.T) {
	a, b := newFlowTemplates(), newFlowTemplates()
	a.OnLearn = func(tm *FlowTemplate, r *FlowRate) {
		b.Import([]*FlowTemplate{tm}, nil)
	}
	a.DecodeFlow(tExp, v9Header(v9TemplateSet()), tNow)
	recs, _ := b.DecodeFlow(tExp, v9Header(v9DataSet()), tNow)
	if len(recs) != 2 {
		t.Fatalf("a node with replicated templates read %d records", len(recs))
	}
	// and a pull (snapshot) gives a fresh node the same
	c := newFlowTemplates()
	ts, rs := a.Snapshot()
	c.Import(ts, rs)
	if recs, _ := c.DecodeFlow(tExp, v9Header(v9DataSet()), tNow); len(recs) != 2 {
		t.Fatalf("snapshot import: %d records", len(recs))
	}
}

func TestDecodeV9OptionsSampling(t *testing.T) {
	var opt bytes.Buffer
	be16(&opt, 1) // options template flowset
	be16(&opt, 4+6+4+4)
	be16(&opt, 300) // template id
	be16(&opt, 4)   // scope length
	be16(&opt, 4)   // option length
	be16(&opt, 1)   // scope type system
	be16(&opt, 4)
	be16(&opt, 34) // SAMPLING_INTERVAL
	be16(&opt, 4)
	var data bytes.Buffer
	be16(&data, 300)
	be16(&data, 4+8)
	be32(&data, 0)
	be32(&data, 10)
	c := newFlowTemplates()
	var got *FlowRate
	c.OnLearn = func(_ *FlowTemplate, r *FlowRate) {
		if r != nil {
			got = r
		}
	}
	c.DecodeFlow(tExp, v9Header(opt.Bytes(), data.Bytes()), tNow)
	if got == nil || got.Rate != 10 {
		t.Fatalf("sampling rate not learned: %+v", got)
	}
	recs, _ := c.DecodeFlow(tExp, v9Header(v9TemplateSet(), v9DataSet()), tNow)
	if len(recs) != 2 || recs[0].Bytes != 5000 || recs[0].Packets != 20 {
		t.Errorf("rate not applied: %+v", recs)
	}
}

func ipfixMessage(sets ...[]byte) []byte {
	var body bytes.Buffer
	for _, s := range sets {
		body.Write(s)
	}
	var b bytes.Buffer
	be16(&b, 10)
	be16(&b, uint16(16+body.Len()))
	be32(&b, uint32(tNow.Unix()))
	be32(&b, 1)
	be32(&b, 5)
	b.Write(body.Bytes())
	return b.Bytes()
}

func TestDecodeIPFIXVariableAndEnterprise(t *testing.T) {
	// template 400: srcIPv6(27,16) dstIPv6(28,16) octetDelta(1,8) pktDelta(2,8) proto(4,1) enterprise(1234/99, 2) varlen string(82,0xFFFF) flowEndMs(153,8)
	var ts bytes.Buffer
	be16(&ts, 2)
	fields := []struct {
		id, l uint16
		ent   uint32
	}{{27, 16, 0}, {28, 16, 0}, {1, 8, 0}, {2, 8, 0}, {4, 1, 0}, {99, 2, 1234}, {82, 0xFFFF, 0}, {153, 8, 0}}
	n := 4 + 4
	for _, f := range fields {
		n += 4
		if f.ent != 0 {
			n += 4
		}
	}
	be16(&ts, uint16(n))
	be16(&ts, 400)
	be16(&ts, uint16(len(fields)))
	for _, f := range fields {
		if f.ent != 0 {
			be16(&ts, f.id|0x8000)
		} else {
			be16(&ts, f.id)
		}
		be16(&ts, f.l)
		if f.ent != 0 {
			be32(&ts, f.ent)
		}
	}
	src := netip.MustParseAddr("2001:db8::1")
	dst := netip.MustParseAddr("2001:db8::2")
	var ds bytes.Buffer
	rec := func(name string) {
		ds.Write(src.AsSlice())
		ds.Write(dst.AsSlice())
		binary.Write(&ds, binary.BigEndian, uint64(9000))
		binary.Write(&ds, binary.BigEndian, uint64(6))
		ds.WriteByte(6)
		be16(&ds, 0xBEEF)
		ds.WriteByte(byte(len(name)))
		ds.WriteString(name)
		binary.Write(&ds, binary.BigEndian, uint64(tNow.UnixMilli()-2000))
	}
	rec("eth0")
	rec("a-longer-interface-name")
	var data bytes.Buffer
	be16(&data, 400)
	be16(&data, uint16(4+ds.Len()))
	data.Write(ds.Bytes())
	c := newFlowTemplates()
	recs, err := c.DecodeFlow(tExp, ipfixMessage(ts.Bytes(), data.Bytes()), tNow)
	if err != nil || len(recs) != 2 {
		t.Fatalf("ipfix: %v %v", recs, err)
	}
	if recs[1].Src != src || recs[1].Dst != dst || recs[1].Bytes != 9000 || recs[1].Proto != 6 {
		t.Errorf("ipfix record %+v", recs[1])
	}
	if d := tNow.Sub(recs[0].Time); d < time.Second || d > 3*time.Second {
		t.Errorf("flowEndMilliseconds not used: %v", recs[0].Time)
	}
}

func sflowDatagram(frameLen uint32, rate uint32) []byte {
	// ethernet + ipv4 + tcp header, 54 bytes
	var h bytes.Buffer
	h.Write(make([]byte, 12))
	be16(&h, 0x0800)
	h.Write([]byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0})
	h.Write(tHostA.AsSlice())
	h.Write(tHostB.AsSlice())
	be16(&h, 50000)
	be16(&h, 22)
	h.Write(make([]byte, 8))
	h.WriteByte(0x50)
	h.WriteByte(0x18) // flags at offset 13 of the tcp header
	h.Write(make([]byte, 6))
	var rec bytes.Buffer
	be32(&rec, 1) // ethernet
	be32(&rec, frameLen)
	be32(&rec, 0)
	be32(&rec, uint32(h.Len()))
	rec.Write(h.Bytes())
	for rec.Len()%4 != 0 {
		rec.WriteByte(0)
	}
	var smp bytes.Buffer
	be32(&smp, 1)    // seq
	be32(&smp, 0x11) // source id
	be32(&smp, rate)
	be32(&smp, 1000)
	be32(&smp, 0)
	be32(&smp, 0x00000005) // in
	be32(&smp, 0x00000006) // out
	be32(&smp, 1)          // records
	be32(&smp, 1)          // tag: raw packet header
	be32(&smp, uint32(rec.Len()))
	smp.Write(rec.Bytes())
	var d bytes.Buffer
	be32(&d, 5)
	be32(&d, 1)
	d.Write([]byte{192, 0, 2, 1})
	be32(&d, 0)
	be32(&d, 1)
	be32(&d, 1000)
	be32(&d, 1) // samples
	be32(&d, 1) // flow sample
	be32(&d, uint32(smp.Len()))
	d.Write(smp.Bytes())
	return d.Bytes()
}

func TestDecodeSFlow(t *testing.T) {
	c := newFlowTemplates()
	recs, err := c.DecodeFlow(tExp, sflowDatagram(1500, 512), tNow)
	if err != nil || len(recs) != 1 {
		t.Fatalf("sflow: %v %v", recs, err)
	}
	r := recs[0]
	if r.Src != tHostA || r.Dst != tHostB || r.DstPort != 22 || r.SrcPort != 50000 || r.Proto != 6 || r.TCPFlags != 0x18 {
		t.Errorf("sflow record %+v", r)
	}
	if r.Bytes != 1500*512 || r.Packets != 512 || r.InIf != 5 || r.OutIf != 6 {
		t.Errorf("sflow scaling %+v", r)
	}
}

// Nothing a network sends may crash the collector: every prefix of every valid packet, and random bytes, are safe.
func TestDecodersNeverPanic(t *testing.T) {
	seeds := [][]byte{v5Packet(0), v9Header(v9TemplateSet(), v9DataSet()), sflowDatagram(100, 10), ipfixMessage(v9TemplateSet(), v9DataSet())}
	c := newFlowTemplates()
	c.DecodeFlow(tExp, seeds[1], tNow)
	for _, s := range seeds {
		for i := 0; i <= len(s); i++ {
			c.DecodeFlow(tExp, s[:i], tNow)
		}
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		s := append([]byte(nil), seeds[rng.Intn(len(seeds))]...)
		for j := 0; j < 1+rng.Intn(6); j++ {
			s[rng.Intn(len(s))] = byte(rng.Intn(256))
		}
		c.DecodeFlow(tExp, s, tNow)
	}
	for i := 0; i < 5000; i++ {
		b := make([]byte, rng.Intn(200))
		rng.Read(b)
		c.DecodeFlow(tExp, b, tNow)
	}
}

func TestTemplateLimits(t *testing.T) {
	c := newFlowTemplates()
	for i := 0; i < maxTemplatesPerExporter+50; i++ {
		c.put(&FlowTemplate{Exporter: tExp, ID: uint16(256 + i), Fields: []FlowField{{1, 4, 0}}})
	}
	if n := c.perEx[tExp]; n != maxTemplatesPerExporter {
		t.Errorf("an exporter holds %d templates, limit %d", n, maxTemplatesPerExporter)
	}
}

// ── store and query ──────────────────────────────────────────────────────────────────────────────────────────────

func testStore(dir string) *flowStore {
	s := newFlowStore(dir, FlowConfig{})
	s.now = func() time.Time { return tNow }
	return s
}

func rec(src, dst string, sp, dp uint16, proto uint8, bytes_ uint64, at time.Time) FlowRec {
	return FlowRec{Exporter: tExp, Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst), SrcPort: sp, DstPort: dp, Proto: proto, Bytes: bytes_, Packets: bytes_ / 100, InIf: 1, OutIf: 2, Time: at}
}

func TestNormPorts(t *testing.T) {
	cases := []struct {
		sp, dp, wsp, wdp uint16
		proto            uint8
	}{{51234, 443, 0, 443, 6}, {443, 51234, 443, 0, 6}, {22, 80, 22, 80, 6}, {40000, 40001, 40000, 0, 17}, {5000, 5000, 0, 5000, 6}, {1, 2, 0, 0, 1}}
	for _, c := range cases {
		f := FlowRec{SrcPort: c.sp, DstPort: c.dp, Proto: c.proto}
		if sp, dp := normPorts(&f); sp != c.wsp || dp != c.wdp {
			t.Errorf("normPorts(%d,%d,p%d) = %d,%d want %d,%d", c.sp, c.dp, c.proto, sp, dp, c.wsp, c.wdp)
		}
	}
}

func TestStoreQueryGroupFilter(t *testing.T) {
	s := testStore("")
	at := tNow.Add(-10 * time.Minute)
	// many client ports to one server collapse into one key
	for p := uint16(40000); p < 40100; p++ {
		s.Add(rec("10.0.0.5", "203.0.113.9", p, 443, 6, 1000, at))
	}
	s.Add(rec("10.0.0.6", "203.0.113.9", 40000, 443, 6, 5000, at))
	s.Add(rec("10.0.0.5", "198.51.100.1", 40000, 53, 17, 200, at))
	if _, _, keys := s.Keys(); keys != 3 {
		t.Fatalf("keys: %d, want 3 (client ports must not make keys)", keys)
	}
	q := FlowQuery{From: tNow.Add(-time.Hour).Unix(), To: tNow.Unix(), By: "host", Limit: 10}
	a := s.Query(q)
	if a.Total.Bytes != 100_000+5000+200 || a.Total.Flows != 102 {
		t.Errorf("total %+v", a.Total)
	}
	if a.Rows[0].Key["host"] != "203.0.113.9" || a.Rows[0].Bytes != 105_000 {
		t.Errorf("top host: %+v", a.Rows[0])
	}
	q.By = "service"
	a = s.Query(q)
	if a.Rows[0].Key["port"] != "443" || a.Rows[0].Key["proto"] != "6" || a.Rows[0].Bytes != 105_000 {
		t.Errorf("top service: %+v", a.Rows[0])
	}
	q.By = "conversation"
	q.Filter = FlowFilter{Hosts: []netip.Prefix{netip.MustParsePrefix("10.0.0.6/32")}}
	a = s.Query(q)
	if len(a.Rows) != 1 || a.Rows[0].Bytes != 5000 || a.Total.Bytes != 5000 {
		t.Errorf("filtered: %+v total %+v", a.Rows, a.Total)
	}
	q.Filter = FlowFilter{Ports: []uint16{53}}
	q.By = "interface"
	a = s.Query(q)
	if len(a.Rows) != 2 || a.Rows[0].Key["ifindex"] == "" {
		t.Errorf("interface rows: %+v", a.Rows)
	}
	// outside the range: nothing
	q = FlowQuery{From: tNow.Add(-5 * time.Minute).Unix(), To: tNow.Unix(), By: "host"}
	if a := s.Query(q); a.Total.Flows != 0 {
		t.Errorf("range: %+v", a.Total)
	}
}

func TestStoreOverflow(t *testing.T) {
	s := testStore("")
	s.SetConfig(FlowConfig{MaxKeys: 10})
	at := tNow.Add(-time.Minute)
	for i := 0; i < 100; i++ {
		s.Add(rec("10.0.0.5", netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}).String(), 40000, 443, 6, 100, at))
	}
	_, _, keys := s.Keys()
	if keys > 11 { // 10 keys and the per-exporter "other"
		t.Errorf("a bucket grew to %d keys with a limit of 10", keys)
	}
	a := s.Query(FlowQuery{From: tNow.Add(-time.Hour).Unix(), To: tNow.Unix(), By: "protocol"})
	if a.Total.Bytes != 10_000 {
		t.Errorf("overflowed flows are lost: total %d", a.Total.Bytes)
	}
}

func TestStoreCompactAndPersist(t *testing.T) {
	dir := t.TempDir()
	s := testStore(dir)
	s.SetConfig(FlowConfig{HourTopK: 5})
	base := tNow.Add(-3 * time.Hour).Truncate(time.Hour)
	for i := 0; i < 20; i++ {
		s.Add(rec("10.0.0.5", netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}).String(), 40000, 443, 6, uint64(1000*(i+1)), base.Add(time.Duration(i)*time.Minute)))
	}
	s.Maintain()
	s.mu.RLock()
	hb := s.hour[base.Unix()]
	s.mu.RUnlock()
	if hb == nil || len(hb.M) > 6 || hb.Trunc != 15 {
		t.Fatalf("hour bucket: %+v", hb)
	}
	var want uint64 = 1000 * 20 * 21 / 2
	q := FlowQuery{From: base.Unix(), To: base.Unix() + 3600, By: "dst", Limit: 3}
	a := s.Query(q)
	if a.Resolved != "hour" || !a.Approx || a.Total.Bytes != want {
		t.Errorf("hour query: res=%s approx=%v total=%d want %d", a.Resolved, a.Approx, a.Total.Bytes, want)
	}
	if a.Rows[0].Key["dst"] != "198.51.100.19" {
		t.Errorf("top after truncation: %+v", a.Rows[0])
	}
	if a.Other.Bytes != 120000 || a.Other.Flows != 15 { // the 15 smallest (1000..15000) were folded, and are not a row
		t.Errorf("folded keys: %+v", a.Other)
	}
	s.flushAll()
	s.Close()
	// a new process reads it back
	s2 := testStore(dir)
	s2.Load()
	a2 := s2.Query(q)
	if a2.Total.Bytes != want || a2.Rows[0].Key["dst"] != "198.51.100.19" {
		t.Errorf("after a restart: %+v", a2.Total)
	}
	// minute data came back too: a query for one minute is exact
	a3 := s2.Query(FlowQuery{From: base.Unix(), To: base.Unix() + 60, By: "dst"})
	if a3.Total.Bytes != 1000 || a3.Resolved != "minute" {
		t.Errorf("minute after restart: %+v res=%s", a3.Total, a3.Resolved)
	}
}

func TestMergeAnswersAddsUp(t *testing.T) {
	q := FlowQuery{By: "host", Limit: 2}
	row := func(h string, b uint64) FlowRow {
		return FlowRow{Key: map[string]string{"host": h}, Bytes: b, Flows: 1}
	}
	a := FlowAnswer{Rows: []FlowRow{row("a", 100), row("b", 50), row("c", 10)}, Total: FlowRow{Bytes: 160, Flows: 3}}
	b := FlowAnswer{Rows: []FlowRow{row("b", 80), row("c", 5), row("d", 1)}, Total: FlowRow{Bytes: 86, Flows: 3}, Approx: true}
	m := mergeFlowAnswers([]FlowAnswer{a, b}, q)
	if len(m.Rows) != 2 || m.Rows[0].Key["host"] != "b" || m.Rows[0].Bytes != 130 || m.Rows[1].Key["host"] != "a" {
		t.Errorf("merged rows: %+v", m.Rows)
	}
	if m.Total.Bytes != 246 || m.Total.Flows != 6 || !m.Approx {
		t.Errorf("merged total: %+v", m)
	}
}

func TestSeries(t *testing.T) {
	s := testStore("")
	for i := 0; i < 30; i++ {
		s.Add(rec("10.0.0.5", "203.0.113.9", 40000, 443, 6, 1000, tNow.Add(-time.Duration(i)*time.Minute)))
	}
	a := s.Query(FlowQuery{From: tNow.Add(-time.Hour).Unix(), To: tNow.Unix() + 60, By: "service", Step: 600})
	if len(a.Series) < 2 || a.Series[0].Key != nil {
		t.Fatalf("series: %+v", a.Series)
	}
	var sum uint64
	for _, p := range a.Series[0].Points {
		sum += p.Bytes
	}
	if sum != 30_000 {
		t.Errorf("series total %d", sum)
	}
}

func TestQueryValidate(t *testing.T) {
	bad := []FlowQuery{{From: 10, To: 5}, {From: 0, To: 4000 * 86400}, {From: 0, To: 3600, By: "nonsense"}, {From: 0, To: 3600, Metric: "x"}, {From: 0, To: 86400 * 300, Step: 60}}
	for i, q := range bad {
		if q.Validate() == nil {
			t.Errorf("query %d was accepted: %+v", i, q)
		}
	}
	good := FlowQuery{From: 0, To: 3600, By: "src", Step: 60}
	if err := good.Validate(); err != nil {
		t.Error(err)
	}
}

func TestFlowConfigValidate(t *testing.T) {
	if (&FlowConfig{NetFlowPort: 70000}).Validate() == nil {
		t.Error("port 70000")
	}
	if err := (&FlowConfig{Enabled: true, MaxKeys: 1000}).Validate(); err != nil {
		t.Error(err)
	}
}

// ── through the MCP endpoint ────────────────────────────────────────────────────────────────────────────────────

func newTestFlowSvc() *flowService {
	s := &flowService{store: testStore(""), tmpls: newFlowTemplates(), expNets: []flowExpNet{{p: netip.PrefixFrom(tExp, tExp.BitLen()), name: "core-sw1"}}, dns: newFlowDNS()}
	s.store.now = time.Now
	return s
}

func TestMCPFlowTools(t *testing.T) {
	old := flowSvc
	defer func() { flowSvc = old }()
	flowSvc = newTestFlowSvc()
	at := time.Now().Add(-3 * time.Minute)
	for p := uint16(40000); p < 40010; p++ {
		flowSvc.store.Add(rec("10.0.0.5", "203.0.113.9", p, 443, 6, 1_000_000, at))
	}
	flowSvc.store.Add(rec("10.0.0.6", "198.51.100.1", 40000, 53, 17, 2000, at))
	_, post := mcpEnv(t, "127.0.0.0/8 ro")

	_, m := post(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	have := strings.Join(toolNames(t, m), ",")
	for _, n := range []string{"flow_top", "flow_timeseries", "flow_exporters", "flow_status"} {
		if !strings.Contains(have, n) {
			t.Errorf("%s is not offered: %s", n, have)
		}
	}
	_, m = post(mcpCall("flow_top", `{"by":"service","range":"1h"}`))
	txt, isErr := toolResult(t, m)
	if isErr || !strings.Contains(txt, `"port":"443"`) || !strings.Contains(txt, `"proto":"tcp"`) || !strings.Contains(txt, `"port":"https"`) {
		t.Fatalf("flow_top by service: %v %s", isErr, txt)
	}
	// filters, with a name for the exporter
	_, m = post(mcpCall("flow_top", `{"by":"conversation","exporter":"core-sw1","port":"dns","range":"1h"}`))
	txt, isErr = toolResult(t, m)
	if isErr || !strings.Contains(txt, `"flows":1`) || strings.Contains(txt, "203.0.113.9") {
		t.Errorf("filtered flow_top: %v %s", isErr, txt)
	}
	// a bad argument is an answer the caller can act on, not a crash
	_, m = post(mcpCall("flow_top", `{"by":"nonsense"}`))
	if txt, isErr = toolResult(t, m); !isErr || !strings.Contains(txt, "by:") {
		t.Errorf("bad by: %v %s", isErr, txt)
	}
	_, m = post(mcpCall("flow_top", `{"exporter":"no-such-device"}`))
	if txt, isErr = toolResult(t, m); !isErr || !strings.Contains(txt, "not the name of an exporter") {
		t.Errorf("unknown exporter: %v %s", isErr, txt)
	}
	_, m = post(mcpCall("flow_timeseries", `{"by":"host","range":"1h","step":"5m"}`))
	if txt, isErr = toolResult(t, m); isErr || !strings.Contains(txt, `"series"`) || !strings.Contains(txt, `"points"`) {
		t.Errorf("flow_timeseries: %v %s", isErr, txt)
	}
	_, m = post(mcpCall("flow_status", `{}`))
	if txt, isErr = toolResult(t, m); isErr || !strings.Contains(txt, `"nodes"`) {
		t.Errorf("flow_status: %v %s", isErr, txt)
	}
}

// ── throughput ───────────────────────────────────────────────────────────────────────────────────────────────────

func BenchmarkStoreAdd(b *testing.B) {
	s := testStore("")
	s.now = time.Now
	recs := make([]FlowRec, 4096)
	for i := range recs {
		recs[i] = rec("10.0.0.5", netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}).String(), 40000, uint16(1+i%900), 6, 1500, time.Now())
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Add(recs[i&4095])
	}
}

func BenchmarkDecodeV9AndStore(b *testing.B) {
	c := newFlowTemplates()
	c.DecodeFlow(tExp, v9Header(v9TemplateSet()), tNow)
	pk := v9Header(v9DataSet())
	s := testStore("")
	s.now = func() time.Time { return tNow }
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recs, _ := c.DecodeFlow(tExp, pk, tNow)
		for j := range recs {
			s.Add(recs[j])
		}
	}
}

// ── flow_dir ─────────────────────────────────────────────────────────────────────────────────────────────────────

func TestFlowDirValidate(t *testing.T) {
	for _, bad := range []string{"relative/path", "flow", "/", "//", "/a\x00b"} {
		if validFlowDir(bad) == nil {
			t.Errorf("flow_dir %q was accepted", bad)
		}
	}
	for _, ok := range []string{"", "/data/flow", "/var/lib/flowdir/flow/"} {
		if err := validFlowDir(ok); err != nil {
			t.Errorf("flow_dir %q: %v", ok, err)
		}
	}
	dc := newDaemonConfig()
	dc.FlowDir = "nope"
	if dc.Validate() == nil {
		t.Error("a relative flow_dir passed the configuration check")
	}
}

func TestFlowDirIsUsed(t *testing.T) {
	base := t.TempDir()
	dc := newDaemonConfig()
	dc.Groups = nil
	dc.FlowDir = filepath.Join(base, "elsewhere", "rollups")
	sup := NewSupervisor(context.Background(), dc)
	s := newFlowService(sup, &Mgmt{stateDir: filepath.Join(base, "state")})
	if s.store.dir != dc.FlowDir {
		t.Fatalf("the store is in %q, want %q", s.store.dir, dc.FlowDir)
	}
	s.store.Load() // makes the folder
	at := time.Now().Add(-10 * time.Minute)
	s.store.Add(rec("10.0.0.5", "203.0.113.9", 40000, 443, 6, 1000, at))
	s.store.flushAll()
	s.store.Close()
	ents, _ := os.ReadDir(dc.FlowDir)
	if len(ents) != 1 || !strings.HasPrefix(ents[0].Name(), "m-") {
		t.Errorf("files in %s: %v", dc.FlowDir, ents)
	}
	if _, err := os.Stat(filepath.Join(base, "state", "flow")); err == nil {
		t.Error("the default folder was made too")
	}
	if st := s.Status(); st.Dir != dc.FlowDir || st.DirError != "" {
		t.Errorf("status: %q %q", st.Dir, st.DirError)
	}
	// with none set it is "flow" in the state directory
	dc2 := newDaemonConfig()
	dc2.Groups = nil
	s2 := newFlowService(NewSupervisor(context.Background(), dc2), &Mgmt{stateDir: "/var/lib/x"})
	if s2.store.dir != "/var/lib/x/flow" {
		t.Errorf("default folder %q", s2.store.dir)
	}
}

// A folder that cannot be made does not stop the collector: it keeps the rollups in memory and says why.
func TestFlowDirUnusable(t *testing.T) {
	base := t.TempDir()
	blocker := filepath.Join(base, "file")
	os.WriteFile(blocker, []byte("x"), 0o600)
	dc := newDaemonConfig()
	dc.Groups = nil
	dc.FlowDir = filepath.Join(blocker, "sub") // under a regular file
	s := newFlowService(NewSupervisor(context.Background(), dc), &Mgmt{stateDir: base})
	s.store.Load()
	s.store.Add(rec("10.0.0.5", "203.0.113.9", 40000, 443, 6, 1000, time.Now()))
	s.store.Maintain()
	a := s.store.Query(FlowQuery{From: time.Now().Add(-time.Hour).Unix(), To: time.Now().Unix() + 60, By: "protocol"})
	if a.Total.Flows != 1 {
		t.Errorf("flows are lost when the folder is not usable: %+v", a.Total)
	}
	if st := s.Status(); st.Dir != "" || st.DirError == "" {
		t.Errorf("status should say why there is no disk: %q %q", st.Dir, st.DirError)
	}
}

// ── the cap on the folder ────────────────────────────────────────────────────────────────────────────────────────

func seedFlowFile(t *testing.T, dir, name string, size int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func TestFlowDirCapIsFIFO(t *testing.T) {
	dir := t.TempDir()
	s := testStore(dir)
	s.volSize = func(string) (uint64, error) { return 1000_000, nil } // a 1 MB volume
	s.SetCap(50, 0)                                                   // 50% = 500 000 bytes
	base := tNow.Unix() - 7200
	// 8 files of 100 000 bytes, oldest first: hourly and minute files mixed
	names := []string{
		fmt.Sprintf("h-%d.gob", base),
		fmt.Sprintf("m-%d-1.gob", base+3600),
		fmt.Sprintf("m-%d-2.gob", base+3600+600),
		fmt.Sprintf("m-%d-3.gob", base+3600+1200),
		fmt.Sprintf("m-%d-4.gob", base+3600+1800),
		fmt.Sprintf("m-%d-5.gob", base+3600+2400),
		fmt.Sprintf("m-%d-6.gob", base+3600+3000),
		fmt.Sprintf("m-%d-7.gob", base+3600+3300),
	}
	for _, n := range names {
		seedFlowFile(t, dir, n, 100_000)
	}
	seedFlowFile(t, dir, "notes.txt", 400_000) // not ours: never counted, never touched
	s.curFile = names[7]
	s.mu.Lock()
	s.enforceCapLocked(tNow)
	s.mu.Unlock()
	left := dirNames(t, dir)
	want := append([]string{"notes.txt"}, names[3:]...) // the three oldest went
	sort.Strings(want)
	if strings.Join(left, ",") != strings.Join(want, ",") {
		t.Errorf("left %v\nwant %v", left, want)
	}
	if s.dirBytes != 500_000 || s.capBytes != 500_000 || s.capped != 3 {
		t.Errorf("accounting: bytes %d cap %d removed %d", s.dirBytes, s.capBytes, s.capped)
	}
	// under the cap: nothing more goes
	s.mu.Lock()
	s.enforceCapLocked(tNow)
	s.mu.Unlock()
	if len(dirNames(t, dir)) != len(want) {
		t.Errorf("a folder within its cap lost files: %v", dirNames(t, dir))
	}
}

func TestFlowDirCapDefaultsAndAbsolute(t *testing.T) {
	dir := t.TempDir()
	s := testStore(dir)
	s.volSize = func(string) (uint64, error) { return 10_000_000, nil }
	s.mu.Lock()
	if c, ok := s.capLocked(); !ok || c != 9_000_000 {
		t.Errorf("default cap %d %v, want 90%% of the volume", c, ok)
	}
	s.mu.Unlock()
	s.SetCap(0, 3) // 3 MB beats the percentage
	s.mu.Lock()
	if c, _ := s.capLocked(); c != 3<<20 {
		t.Errorf("absolute cap %d", c)
	}
	s.mu.Unlock()
	// a cap too small for even the file being written keeps that file
	cur := fmt.Sprintf("m-%d-1.gob", tNow.Unix())
	seedFlowFile(t, dir, cur, 2<<20)
	seedFlowFile(t, dir, fmt.Sprintf("m-%d-0.gob", tNow.Unix()-300), 2<<20)
	s.SetCap(0, 1)
	s.curFile = cur
	s.mu.Lock()
	s.enforceCapLocked(tNow)
	s.mu.Unlock()
	if got := dirNames(t, dir); len(got) != 1 || got[0] != cur {
		t.Errorf("the file being written must stay: %v", got)
	}
}

func TestFlowDirCapUnknownVolume(t *testing.T) {
	dir := t.TempDir()
	s := testStore(dir)
	s.volSize = func(string) (uint64, error) { return 0, os.ErrInvalid }
	seedFlowFile(t, dir, fmt.Sprintf("m-%d-1.gob", tNow.Unix()-100), 1000)
	s.mu.Lock()
	s.enforceCapLocked(tNow)
	s.mu.Unlock()
	if len(dirNames(t, dir)) != 1 {
		t.Error("with the volume's size unknown and no size set, nothing may be deleted")
	}
	s.SetCap(0, 1) // an absolute cap still works
	s.mu.Lock()
	if _, ok := s.capLocked(); !ok {
		t.Error("an absolute cap needs no volume size")
	}
	s.mu.Unlock()
}

func TestFlowCapValidate(t *testing.T) {
	for _, bad := range []int{101, -1} {
		if (&FlowConfig{DirMaxPercent: bad}).Validate() == nil {
			t.Errorf("dir cap %d was accepted", bad)
		}
		if (&FlowConfig{MemMaxPercent: bad}).Validate() == nil {
			t.Errorf("mem cap %d was accepted", bad)
		}
	}
	if err := (&FlowConfig{DirMaxPercent: 80, MemMaxPercent: 80}).Validate(); err != nil {
		t.Error(err)
	}
}

func TestVolumeSizeIsReal(t *testing.T) {
	n, err := volumeSize(t.TempDir())
	if err != nil || n < 1<<20 {
		t.Errorf("volumeSize: %d %v", n, err)
	}
}

func memTestBucket(n int) *flowBucket {
	b := &flowBucket{M: map[flowKey]flowVal{}}
	for i := 0; i < n; i++ {
		b.M[flowKey{SPort: uint16(i)}] = flowVal{Bytes: 1}
	}
	return b
}

func TestFlowMemCapIsFIFO(t *testing.T) {
	s := testStore("")
	s.memTotal = func() uint64 { return 1 << 30 }
	base := tNow.Unix() / 3600 * 3600
	// an hourly bucket for 3 hours ago and 10 minute buckets of the current hour, each of 100 keys
	s.hour[base-3*3600] = memTestBucket(100)
	for i := 0; i < 10; i++ {
		s.min[base+int64(i)*60] = memTestBucket(100)
	}
	per := uint64(flowBucketBytes + 100*flowKeyBytes)
	s.SetMemCap(0, 0)
	s.mu.Lock()
	s.enforceMemLocked(tNow)
	s.mu.Unlock()
	if len(s.min) != 10 || len(s.hour) != 1 || s.memCap != (1<<30)/100*90 {
		t.Fatalf("a store within the default 90%% lost buckets or got the wrong cap: %d min %d hour cap %d", len(s.min), len(s.hour), s.memCap)
	}
	// room for 6 buckets: the hourly one (oldest) goes first, then the oldest minutes; the newest minute stays
	s.memTotal = func() uint64 { return (per*6 + per/2) * 2 } // 50% of this is six and a half buckets
	s.SetMemCap(50, 0)
	s.mu.Lock()
	s.enforceMemLocked(tNow)
	s.mu.Unlock()
	if len(s.hour) != 0 || len(s.min) != 6 || s.memDropped != 5 {
		t.Fatalf("after the cap: %d min %d hour dropped %d", len(s.min), len(s.hour), s.memDropped)
	}
	for i := 4; i < 10; i++ {
		if s.min[base+int64(i)*60] == nil {
			t.Errorf("minute %d should have stayed", i)
		}
	}
	// an absolute cap far too small still keeps the newest minute
	s.SetMemCap(0, 1)
	s.memMB = 1
	s.min[base+9*60] = memTestBucket(10000)
	s.mu.Lock()
	s.enforceMemLocked(tNow)
	s.mu.Unlock()
	if len(s.min) != 1 || s.min[base+9*60] == nil {
		t.Errorf("the newest minute must survive: %d buckets", len(s.min))
	}
}

func TestFlowMemCapLoadKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	s := testStore(dir)
	s.Add(rec("10.1.1.1", "10.2.2.2", 50000, 443, 6, 1000, tNow))
	s.flushAll()
	s.Close()
	s2 := testStore(dir)
	s2.memTotal = func() uint64 { return 1 << 30 }
	s2.SetMemCap(0, 0)
	s2.Load()
	if mn, hr, _ := s2.Keys(); mn+hr == 0 {
		t.Errorf("history was not read back")
	}
	s3 := testStore(dir)
	s3.memTotal = func() uint64 { return 1 << 30 }
	s3.SetMemCap(0, 0)
	s3.memMB = 0
	s3.memPct = 0
	s3.memTotal = func() uint64 { return 100 } // a cap of 95 bytes: nothing fits
	s3.Load()
	if mn, hr, _ := s3.Keys(); mn+hr > 1 {
		t.Errorf("a load over the cap read on past the first file: %d %d", mn, hr)
	}
}

// askNodes does what Report does for stores standing in for nodes: the digest round, the losers, the query, the merge.
func askNodes(q FlowQuery, nodes ...*flowStore) FlowAnswer {
	if dedupes(q) {
		var ds []FlowDigest
		for _, n := range nodes {
			ds = append(ds, n.Digest(q))
		}
		q.Losers = chooseLosers(ds)
	}
	var parts []FlowAnswer
	for _, n := range nodes {
		parts = append(parts, n.Query(q))
	}
	a := mergeFlowAnswers(parts, q)
	a.Deduped = dedupes(q)
	return a
}

func TestFlowDedupeCountsASharedFlowOnce(t *testing.T) {
	s := testStore("")
	at := tNow.Add(-2 * time.Minute)
	sw := func(n int) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("10.9.0.%d", n)) }
	// the same flow seen by four switches (the first sees a bit less: it dropped a few samples), and one flow seen by one
	for i := 1; i <= 4; i++ {
		r := rec("10.1.1.1", "10.2.2.2", 50000, 443, 6, 100000, at)
		r.Exporter = sw(i)
		if i == 1 {
			r.Bytes = 90000
		}
		s.Add(r)
	}
	solo := rec("10.1.1.9", "10.2.2.2", 50000, 22, 6, 5000, at)
	solo.Exporter = sw(3)
	s.Add(solo)
	q := FlowQuery{From: at.Unix() - 60, To: tNow.Unix() + 60, By: "conversation"}
	a := askNodes(q, s)
	if a.Total.Bytes != 105000 || !a.Deduped {
		t.Errorf("deduped total %d, want 105000 (%v)", a.Total.Bytes, a.Deduped)
	}
	if len(a.Rows) != 2 || a.Rows[0].Bytes != 100000 {
		t.Errorf("rows %+v", a.Rows)
	}
	q.NoDedupe = true
	if a := askNodes(q, s); a.Total.Bytes != 395000 || a.Deduped {
		t.Errorf("off: total %d, want 395000", a.Total.Bytes)
	}
	// per-device views are never deduplicated
	q.NoDedupe = false
	q.By = "exporter"
	a = askNodes(q, s)
	if len(a.Rows) != 4 || a.Total.Bytes != 395000 || a.Deduped {
		t.Errorf("by exporter: %d rows, total %d", len(a.Rows), a.Total.Bytes)
	}
	// a filter to one exporter sees just that exporter
	q.By = "conversation"
	q.Filter.Exporters = []netip.Prefix{netip.PrefixFrom(sw(1), sw(1).BitLen())}
	if a := askNodes(q, s); a.Total.Bytes != 90000 {
		t.Errorf("one exporter: %d", a.Total.Bytes)
	}
	// the winner is picked among the flows the filter lets through
	q.Filter = FlowFilter{Ports: []uint16{443}}
	if a := askNodes(q, s); a.Total.Bytes != 100000 {
		t.Errorf("port filter: %d", a.Total.Bytes)
	}
	// the setting: on unless turned off
	var c FlowConfig
	if !c.dedupe() {
		t.Error("dedupe must default to on")
	}
	off := false
	c.Dedupe = &off
	if c.dedupe() || c.clone().dedupe() {
		t.Error("dedupe=false was lost")
	}
}

// With anycast the exporters of one path land on different nodes: they are still weighed against each other.
func TestFlowDedupeAcrossNodes(t *testing.T) {
	at := tNow.Add(-2 * time.Minute)
	n1, n2, n3 := testStore(""), testStore(""), testStore("")
	add := func(s *flowStore, exp string, dport uint16, bytes uint64) {
		r := rec("10.1.1.1", "10.2.2.2", 50000, dport, 6, bytes, at)
		r.Exporter = netip.MustParseAddr(exp)
		s.Add(r)
	}
	add(n1, "10.9.0.1", 443, 80000)  // the same flow on three nodes
	add(n2, "10.9.0.2", 443, 100000) // the biggest report: this one counts
	add(n3, "10.9.0.3", 443, 70000)
	add(n1, "10.9.0.1", 22, 5000) // flows only one node saw
	add(n3, "10.9.0.3", 53, 700)
	q := FlowQuery{From: at.Unix() - 60, To: tNow.Unix() + 60, By: "service"}
	a := askNodes(q, n1, n2, n3)
	if a.Total.Bytes != 105700 {
		t.Errorf("total across nodes %d, want 105700", a.Total.Bytes)
	}
	q.NoDedupe = true
	if a := askNodes(q, n1, n2, n3); a.Total.Bytes != 255700 {
		t.Errorf("off: %d", a.Total.Bytes)
	}
	// one exporter whose packets moved from one node to another is one exporter, not two
	m1, m2 := testStore(""), testStore("")
	add(m1, "10.9.0.7", 443, 60000)
	add(m2, "10.9.0.7", 443, 50000)
	add(m2, "10.9.0.8", 443, 90000)
	q.NoDedupe = false
	if a := askNodes(q, m1, m2); a.Total.Bytes != 110000 { // 10.9.0.7 counted 110000 in all and beats 10.9.0.8
		t.Errorf("a moved exporter: %d, want 110000", a.Total.Bytes)
	}
	// the digest is bounded
	big := testStore("")
	for i := 0; i < 50; i++ {
		big.Add(rec("10.1.1.1", "10.2.2.2", 50000, uint16(1000+i), 6, 1000, at))
	}
	if d := big.Digest(q); len(d.Ents) != 50 || d.Cut {
		t.Errorf("digest %d cut %v", len(d.Ents), d.Cut)
	}
}

func TestFlowFilterExpressions(t *testing.T) {
	s := newTestFlowSvc()
	at := time.Now().Add(-2 * time.Minute)
	add := func(src, dst string, dport uint16, proto uint8, b uint64) {
		s.store.Add(rec(src, dst, 50000, dport, proto, b, at))
	}
	add("10.1.1.1", "203.0.113.9", 443, 6, 1000)
	add("10.1.1.1", "8.8.8.8", 53, 17, 200)
	add("10.1.2.2", "203.0.113.9", 443, 6, 4000)
	add("10.2.3.3", "198.51.100.1", 22, 6, 30000)
	add("10.2.3.3", "10.1.1.1", 445, 6, 500000)
	total := func(expr string) uint64 {
		q, err := s.parseFlowQuery(url.Values{"filter": {expr}, "range": {"15m"}}, false)
		if err != nil {
			t.Fatalf("%q: %v", expr, err)
		}
		// the same trip a peer's copy makes
		b, _ := json.Marshal(q)
		var q2 FlowQuery
		if err := json.Unmarshal(b, &q2); err != nil || q2.Validate() != nil {
			t.Fatalf("%q: lost on the wire: %v %v", expr, err, q2.Validate())
		}
		return s.store.Query(q2).Total.Bytes
	}
	for _, c := range []struct {
		expr string
		want uint64
	}{
		{"port=443", 5000},
		{"port=443 AND host=10.1.1.1", 1000},
		{"port=443 host=10.1.1.1", 1000}, // side by side is AND
		{"port=443 OR port=53", 5200},
		{"port=443,53", 5200},
		{"!port=443", 530200},
		{"NOT port=443 AND !port=445", 30200},
		{"host=10.1.1.1 AND !port=53", 501000},
		{"(src=10.1.0.0/16 OR dst=10.1.0.0/16) AND port=443", 5000},
		{"src=10.1.0.0/16 OR dst=10.1.0.0/16 AND port=443", 5200}, // AND binds tighter than OR: src=10.1.0.0/16, or (dst=10.1.0.0/16 and port=443)
		{"10.2.3.3", 530000},                                      // a bare address is a host
		{"!(host=10.1.1.1 OR host=10.2.3.3)", 4000},
		{"proto=udp", 200},
		{"443", 5000},              // a bare number is a port
		{"443 AND 10.1.1.1", 1000}, // and an address a host
		{"!443 AND !445", 30200},
		{"53,443", 5200},
		{"0", 535200}, // the ephemeral side of a flow is stored as port 0 (normPorts), so port 0 matches nearly every flow
		{"port=https and !host=10.1.2.2", 1000},
		{"port=443 && !host=10.1.2.2", 1000},
	} {
		if got := total(c.expr); got != c.want {
			t.Errorf("%q: %d bytes, want %d", c.expr, got, c.want)
		}
	}
	for _, bad := range []string{"port=", "foo=1", "(port=443", "port=443)", "AND port=443", "port=443 AND", "!", "bogus", "host=nope.invalid.x", "65536", "70000"} {
		if _, err := s.parseFlowExpr(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	// the nesting and size are bounded: a peer or a caller cannot send a tree the other end chokes on
	if _, err := s.parseFlowExpr(strings.Repeat("(", 200) + "port=1" + strings.Repeat(")", 200)); err == nil {
		t.Error("200 brackets deep was accepted")
	}
	if _, err := s.parseFlowExpr(strings.Repeat("port=1 OR ", 300) + "port=2"); err != nil {
		// parsed, but Validate refuses the size
		t.Log("parse:", err)
	}
	q := FlowQuery{From: 1, To: 100, Filter: FlowFilter{Expr: &FlowExpr{Op: "bogus"}}}
	if q.Validate() == nil {
		t.Error("a tree with an unknown operator was accepted")
	}
	// it goes with the dedupe digest as well: the winner is picked among the flows the filter lets through
	if d := s.store.Digest(FlowQuery{From: at.Unix() - 60, To: time.Now().Unix() + 60, Filter: FlowFilter{Expr: &FlowExpr{Op: "term", Term: &FlowFilter{Ports: []uint16{22}}}}}); len(d.Ents) != 1 {
		t.Errorf("digest under an expression: %d entries", len(d.Ents))
	}
}

// ── exporters: a name and an address, a network or a host name ─────────────────────────────────────────────

func TestFlowExporterValidate(t *testing.T) {
	ok := []FlowExporterCfg{{Name: "sw1", Address: "10.0.0.1"}, {Name: "net", Address: "10.9.0.0/16"}, {Name: "v6", Address: "2001:db8::1"},
		{Name: "v6net", Address: "2001:db8::/32"}, {Name: "fqdn", Address: "sw1.example.com"}, {Name: "off", Address: "10.0.0.9", Disabled: true}}
	if err := (&FlowConfig{Exporters: ok}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]FlowExporterCfg{
		{{Name: "", Address: "10.0.0.1"}},
		{{Name: "x", Address: ""}},
		{{Name: "x", Address: "10.0.0.1/99"}},
		{{Name: "x", Address: "not an address"}},
		{{Name: "x", Address: "10.0.0.1"}, {Name: "X", Address: "10.0.0.2"}}, // the name is unique, case ignored
	} {
		if (&FlowConfig{Exporters: bad}).Validate() == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
}

func TestFlowExporterAllowedAndNamed(t *testing.T) {
	dc := newDaemonConfig()
	dc.Settings.Flow = &FlowConfig{Exporters: []FlowExporterCfg{
		{Name: "core", Address: "10.9.0.1"},
		{Name: "branches", Address: "10.20.0.0/16"},
		{Name: "branch7", Address: "10.20.7.0/24"},
		{Name: "v6", Address: "2001:db8::/32"},
		{Name: "paused", Address: "10.50.0.1", Disabled: true},
		{Name: "fw", Address: "fw.example.com"},
	}}
	s := &flowService{sup: &Supervisor{dc: dc}, expDNS: map[string][]netip.Prefix{"fw.example.com": {netip.MustParsePrefix("192.0.2.77/32")}}}
	s.syncExporters()
	for addr, want := range map[string]string{
		"10.9.0.1": "core", "10.20.1.1": "branches", "10.20.7.9": "branch7", // the narrowest network names it
		"2001:db8::5": "v6", "192.0.2.77": "fw", // a host name stands for what it resolved to
		"10.9.0.2": "", "10.50.0.1": "", "203.0.113.1": "", // not listed, disabled
	} {
		a := netip.MustParseAddr(addr)
		if got := s.exporterName(a); got != want {
			t.Errorf("%s is %q, want %q", addr, got, want)
		}
		if s.allowed(a) != (want != "") {
			t.Errorf("%s allowed = %v", addr, s.allowed(a))
		}
	}
	// the same address mapped into IPv6 is the IPv4 one
	if !s.allowed(netip.MustParseAddr("::ffff:10.9.0.1").Unmap()) {
		t.Error("a v4-mapped address is not the v4 address")
	}
	// the exporter= filter takes the name, an address or a network
	for val, n := range map[string]int{"core": 1, "BRANCHES": 1, "10.9.0.1": 1, "10.20.0.0/16": 1, "core,fw": 2} {
		ps, err := s.exporterTerm(val)
		if err != nil || len(ps) != n {
			t.Errorf("exporter=%s: %v %v", val, ps, err)
		}
	}
	if _, err := s.exporterTerm("nope"); err == nil {
		t.Error("an unknown exporter name was accepted")
	}
	// a configuration change takes effect at the next sync
	dc.Settings.Flow = &FlowConfig{}
	s.syncExporters()
	if s.allowed(netip.MustParseAddr("10.9.0.1")) {
		t.Error("an exporter that was removed is still accepted")
	}
}
