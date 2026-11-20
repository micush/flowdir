package main

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// What a node collected is still there after any number of restarts, including the flows added to a minute that a restart read back and the
// flows that come late for a minute already written.
func TestMinutesSurviveRestarts(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Truncate(time.Minute).Add(-10 * time.Minute)
	clock := base.Add(30 * time.Second)
	add := func(s *flowStore, at time.Time, n int) {
		for i := 0; i < n; i++ {
			s.Add(FlowRec{Time: at, Exporter: netip.MustParseAddr("192.0.2.1"), Src: netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), Dst: netip.MustParseAddr("198.51.100.1"),
				SrcPort: 1000, DstPort: 80, Proto: 6, Bytes: 100, Packets: 1})
		}
	}
	open := func() *flowStore {
		s := newFlowStore(dir, FlowConfig{})
		s.now = func() time.Time { return clock }
		s.Load()
		return s
	}
	stop := func(s *flowStore) { s.Maintain(); s.flushAll(); s.Close() }
	total := func(s *flowStore) uint64 {
		return s.Query(FlowQuery{From: base.Unix(), To: base.Add(10 * time.Minute).Unix(), Metric: "bytes"}).Total.Bytes
	}
	s := open()
	add(s, base.Add(5*time.Second), 3) // minute 0
	stop(s)
	s = open() // restart one: the same minute gets more
	add(s, base.Add(40*time.Second), 2)
	clock = base.Add(5 * time.Minute) // minute 0 is closed and written by Maintain
	s.Maintain()
	add(s, base.Add(50*time.Second), 4) // a late flow for the written minute
	stop(s)
	s = open() // restart two
	if got := total(s); got != 900 {
		t.Fatalf("after two restarts: %d bytes, want 900", got)
	}
	stop(s)
}

func TestChartHoverSetting(t *testing.T) {
	var on, off FlowConfig
	if err := json.Unmarshal([]byte(`{"enabled":true}`), &on); err != nil || on.ChartHover != nil {
		t.Fatalf("absent should stay nil: %v %v", err, on.ChartHover)
	}
	if err := json.Unmarshal([]byte(`{"enabled":true,"chart_hover":false}`), &off); err != nil || off.ChartHover == nil || *off.ChartHover {
		t.Fatalf("false not read: %v", err)
	}
	b, _ := json.Marshal(on)
	if strings.Contains(string(b), "chart_hover") {
		t.Fatalf("the default must not be written: %s", b)
	}
}
