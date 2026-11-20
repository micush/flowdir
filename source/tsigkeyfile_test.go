package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTSIGKeyFileRefusesTraversal(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "k.key")
	if err := os.WriteFile(f, []byte(`key "k" { algorithm hmac-sha256; secret "AAAA"; };`), 0o600); err != nil {
		t.Fatal(err)
	}
	if p, ok := tsigKeyFile(f); !ok || p != f {
		t.Fatalf("a plain file path must be accepted, got %q %v", p, ok)
	}
	for _, bad := range []string{dir + "/sub/../k.key", dir + "/../" + filepath.Base(dir) + "/k.key", f + "\x00", dir, filepath.Join(dir, "nope")} {
		if _, ok := tsigKeyFile(bad); ok {
			t.Errorf("%q must not count as a key file", bad)
		}
	}
}
