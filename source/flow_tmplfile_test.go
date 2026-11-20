package main

import (
	"net/netip"
	"testing"
)

func TestTemplatesSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	exp := netip.MustParseAddr("192.0.2.9")
	a := &flowService{store: newFlowStore(dir, FlowConfig{}), tmpls: newFlowTemplates()}
	a.tmpls.OnLearn = func(*FlowTemplate, *FlowRate) { a.tmplDirty.Store(true) }
	a.tmpls.Import([]*FlowTemplate{{Exporter: exp, Domain: 1, ID: 256, Fields: []FlowField{{ID: 8, Len: 4}}}}, []FlowRate{{Exporter: exp, Domain: 1, Rate: 100}})
	a.tmplDirty.Store(true)
	a.saveTemplates()
	b := &flowService{store: newFlowStore(dir, FlowConfig{}), tmpls: newFlowTemplates()}
	b.loadTemplates()
	if b.tmpls.get(exp, 1, 256) == nil {
		t.Fatal("template not loaded after a restart")
	}
	if b.tmpls.rate(exp, 1) != 100 {
		t.Fatal("rate not loaded after a restart")
	}
}
