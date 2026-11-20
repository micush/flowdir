package main

import "testing"

func BenchmarkReportHost300h(b *testing.B) {
	s := newTestFlowSvc().store
	from, to := fillHours(s, 300, 20000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Query(FlowQuery{From: from, To: to, By: "host", NoDedupe: true, Limit: 20})
	}
}

func BenchmarkReportService300hCached(b *testing.B) {
	s := newTestFlowSvc().store
	from, to := fillHours(s, 300, 20000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Query(FlowQuery{From: from, To: to, By: "service", NoDedupe: true, Limit: 20})
	}
}

func BenchmarkReportServiceUncached300h(b *testing.B) {
	s := newTestFlowSvc().store
	from, to := fillHours(s, 300, 20000)
	old := qcache
	qcache = nil
	defer func() { qcache = old }()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Query(FlowQuery{From: from, To: to, By: "service", NoDedupe: true, Limit: 20})
	}
}

func BenchmarkReportHost300hFirstRun(b *testing.B) {
	s := newTestFlowSvc().store
	from, to := fillHours(s, 300, 20000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		qcache = &queryCache{m: map[qcacheSlot]*qcacheEnt{}, budget: 2000000}
		s.Query(FlowQuery{From: from, To: to, By: "host", NoDedupe: true, Limit: 20})
	}
}

func BenchmarkReportConv300hCachedRun(b *testing.B) {
	s := newTestFlowSvc().store
	from, to := fillHours(s, 300, 20000)
	qcache = &queryCache{m: map[qcacheSlot]*qcacheEnt{}, budget: 2000000}
	s.Query(FlowQuery{From: from, To: to, By: "conversation", NoDedupe: true, Limit: 20})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Query(FlowQuery{From: from, To: to, By: "conversation", NoDedupe: true, Limit: 20})
	}
}
