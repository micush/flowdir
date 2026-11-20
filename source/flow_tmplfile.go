package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// The templates and sampling rates exporters sent are kept in templates.json beside the flow files, so a restart does not lose them.  Without
// them, NetFlow v9 and IPFIX data records cannot be read until the exporter sends its templates again (many wait 10 to 30 minutes between
// sends), and those flows are lost: the chart shows holes after every restart.

type flowTmplFile struct {
	Templates []*FlowTemplate `json:"templates"`
	Rates     []FlowRate      `json:"rates"`
}

func (s *flowService) tmplPath() string {
	if s.store == nil || s.store.dir == "" {
		return ""
	}
	return filepath.Join(s.store.dir, "templates.json")
}

func (s *flowService) loadTemplates() {
	p := s.tmplPath()
	if p == "" {
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var f flowTmplFile
	if json.Unmarshal(b, &f) != nil {
		return
	}
	s.tmpls.Import(f.Templates, f.Rates)
	infof("flow: loaded %d templates from %s", len(f.Templates), p)
}

func (s *flowService) saveTemplates() {
	p := s.tmplPath()
	if p == "" || !s.tmplDirty.Swap(false) {
		return
	}
	ts, rs := s.tmpls.Snapshot()
	b, err := json.Marshal(flowTmplFile{Templates: ts, Rates: rs})
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(p), 0o750)
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o640) != nil || os.Rename(tmp, p) != nil {
		s.tmplDirty.Store(true)
	}
}
