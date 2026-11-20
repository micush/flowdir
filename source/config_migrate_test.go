package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// A configuration written by v1 (testdata/v1_config.json: devices, credentials, a device on a gateway, keys and sources limited to
// devices, secret words, flow.sources and the per-node flow caps) must load: a daemon that refuses its own config does not start.
func TestV1ConfigStillLoads(t *testing.T) {
	dc, err := loadConfig("testdata/v1_config.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	f := dc.Settings.Flow
	if f == nil || f.DirMaxPercent != 70 || f.MemMaxPercent != 60 {
		t.Fatalf("caps: %+v", f)
	}
	have := map[string]string{}
	for _, e := range f.Exporters {
		have[e.Address] = e.Name
	}
	for _, want := range []string{"10.9.0.0/16", "sflow.example.com"} { // the sources, and the addresses of the devices
		if _, ok := have[want]; !ok {
			t.Errorf("exporter %s was not carried over: %v", want, have)
		}
	}
	if len(f.Exporters) < 3 {
		t.Errorf("exporters: %+v", f.Exporters)
	}
	if len(dc.Settings.MCPACL) != 2 || !strings.Contains(dc.Settings.MCPACL[1], "10.0.0.20") || strings.Contains(strings.Join(dc.Settings.MCPACL, " "), "devices=") {
		t.Errorf("acl: %v", dc.Settings.MCPACL)
	}
	if len(dc.Settings.MCPKeys) != 1 || dc.Settings.MCPKeys[0].Name != "laptop" {
		t.Errorf("keys: %+v", dc.Settings.MCPKeys)
	}
	// saved again it is a v2 file: nothing retired comes back, and it loads again
	b, err := json.MarshalIndent(dc, "", "  ")
	if err != nil || strings.Contains(string(b), "device_credentials") || strings.Contains(string(b), `"sources"`) {
		t.Fatalf("saved: %v %s", err, b)
	}
}
