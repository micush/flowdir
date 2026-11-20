package main

import (
	"bytes"
	"encoding/gob"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLZRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	rnd := make([]byte, 5000)
	rng.Read(rnd)
	cases := map[string][]byte{
		"empty":      {},
		"one byte":   {1},
		"short":      []byte("abcdefg"),
		"zeros":      make([]byte, 100000),
		"repeat":     bytes.Repeat([]byte("flowdir "), 9000),
		"random":     rnd,
		"mixed":      append(append(bytes.Repeat([]byte{1, 2, 3, 4, 5}, 300), rnd...), bytes.Repeat([]byte("xyz"), 2000)...),
		"long match": append(bytes.Repeat([]byte{9}, 70000), 1, 2, 3),
	}
	for n, in := range cases {
		out, err := lzDecompress(lzCompress(in), len(in))
		if err != nil || !bytes.Equal(out, in) {
			t.Errorf("%s: round trip failed (err %v)", n, err)
		}
	}
	for i := 0; i < 300; i++ { // random sizes of semi-repetitive data
		b := make([]byte, rng.Intn(20000))
		for j := range b {
			b[j] = byte(rng.Intn(1 + i%9))
		}
		if out, err := lzDecompress(lzCompress(b), len(b)); err != nil || !bytes.Equal(out, b) {
			t.Fatalf("random case %d (len %d) failed: %v", i, len(b), err)
		}
	}
}

func TestLZDamageIsAnErrorNotAPanic(t *testing.T) {
	in := bytes.Repeat([]byte("0123456789abcdef"), 500)
	c := lzCompress(in)
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 2000; i++ {
		d := append([]byte(nil), c...)
		for k := 0; k < 1+rng.Intn(4); k++ {
			d[rng.Intn(len(d))] ^= byte(1 + rng.Intn(255))
		}
		if i%5 == 0 {
			d = d[:rng.Intn(len(d))]
		}
		lzDecompress(d, len(in)) // must not panic
	}
	if _, err := lzDecompress(c, len(in)+1); err == nil {
		t.Error("a wrong size was accepted")
	}
}

func testRecs() []flowFileRec {
	var recs []flowFileRec
	for m := 0; m < 3; m++ {
		r := flowFileRec{TS: 1700000000 + int64(m)*60, Trunc: m}
		for i := 0; i < 200; i++ {
			k := flowKey{Exp: netip.MustParseAddr("10.0.0.1"), Src: netip.AddrFrom4([4]byte{10, 0, byte(m), byte(i)}), Dst: netip.MustParseAddr("198.51.100.7"), DPort: 443, Proto: 6, InIf: 1, OutIf: 2}
			r.Entries = append(r.Entries, flowEntry{k, flowVal{uint64(i * 1000), uint64(i), 1}})
		}
		recs = append(recs, r)
	}
	return recs
}

func readAll(b []byte) []flowFileRec {
	var got []flowFileRec
	readFlowRecs(bytes.NewReader(b), func(r flowFileRec) { got = append(got, r) })
	return got
}

func sameRecs(a, b []flowFileRec) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].TS != b[i].TS || a[i].Trunc != b[i].Trunc || len(a[i].Entries) != len(b[i].Entries) {
			return false
		}
		for j := range a[i].Entries {
			if a[i].Entries[j] != b[i].Entries[j] {
				return false
			}
		}
	}
	return true
}

func TestFlowFilesCompressedPlainAndTorn(t *testing.T) {
	recs := testRecs()
	var comp, plain bytes.Buffer
	comp.WriteString(flowMagic)
	enc := gob.NewEncoder(&plain)
	for _, r := range recs {
		fr, err := lzFrame(r)
		if err != nil {
			t.Fatal(err)
		}
		comp.Write(fr)
		enc.Encode(r)
	}
	if !sameRecs(readAll(comp.Bytes()), recs) {
		t.Error("a compressed file did not read back")
	}
	if !sameRecs(readAll(plain.Bytes()), recs) {
		t.Error("a plain gob file written before compression did not read back")
	}
	if comp.Len() >= plain.Len() {
		t.Errorf("compressed %d bytes, plain %d: nothing saved", comp.Len(), plain.Len())
	}
	// the daemon killed mid-write: the complete records before the cut are kept, nothing panics
	for _, cut := range []int{comp.Len() - 1, comp.Len() - 40, comp.Len() / 2, 6, 2, 0} {
		got := readAll(comp.Bytes()[:cut])
		if !sameRecs(got, recs[:len(got)]) {
			t.Errorf("cut at %d: the records read are not a prefix of the written ones", cut)
		}
	}
	// a flipped byte inside a frame ends the file there (the checksum), earlier records are kept
	bad := append([]byte(nil), comp.Bytes()...)
	bad[len(bad)-10] ^= 0xff
	if got := readAll(bad); len(got) != 2 || !sameRecs(got, recs[:2]) {
		t.Errorf("damaged last frame: read %d records", len(got))
	}
}

func TestWriteGobFileIsCompressedAndReadable(t *testing.T) {
	dir := t.TempDir()
	b := &flowBucket{TS: 1700000000, M: map[flowKey]flowVal{}}
	for _, r := range testRecs()[0].Entries {
		b.M[r.K] = r.V
	}
	p := filepath.Join(dir, "h-1700000000.gob")
	if err := writeGobFile(p, bucketRec(b)); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if !bytes.HasPrefix(raw, []byte(flowMagic)) {
		t.Error("the hourly file is not in the compressed format")
	}
	got := readAll(raw)
	if len(got) != 1 || len(got[0].Entries) != len(b.M) {
		t.Errorf("read back %d records", len(got))
	}
	if _, err := os.Stat(p + ".tmp"); err == nil {
		t.Error("the temporary file was left behind")
	}
}

func TestLargeRecordIsPackedInBlocks(t *testing.T) {
	r := flowFileRec{TS: 1700000000}
	for i := 0; i < 60000; i++ { // well over two blocks of gob
		k := flowKey{Exp: netip.MustParseAddr("10.0.0.1"), Src: netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), Dst: netip.MustParseAddr("2001:db8::1"), DPort: uint16(i % 1000), Proto: 6, InIf: 1, OutIf: 2}
		r.Entries = append(r.Entries, flowEntry{k, flowVal{uint64(i) * 7, uint64(i), 1}})
	}
	fr, err := lzFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	if fr[3]&0x80 == 0 {
		t.Fatal("a record of several MB was not packed in blocks")
	}
	file := append([]byte(flowMagic), fr...)
	small, _ := lzFrame(testRecs()[0])
	file = append(file, small...) // a block frame and a plain frame in one file
	got := readAll(file)
	if len(got) != 2 || !sameRecs(got[:1], []flowFileRec{r}) {
		t.Fatalf("read back %d records", len(got))
	}
	if !sameRecs(readAll(file[:len(file)-len(small)-5]), nil) {
		t.Error("a cut block frame was not dropped whole")
	}
	bad := append([]byte(nil), file...)
	bad[len(flowMagic)+12+8+30] ^= 0xff // inside the first block
	if g := readAll(bad); len(g) != 0 {
		t.Errorf("a damaged block was accepted (%d records)", len(g))
	}
}

func TestStoreWritesOffTheLockAndCloseWaits(t *testing.T) {
	dir := t.TempDir()
	s := testStore(dir)
	base := tNow.Add(-3 * time.Hour).Truncate(time.Hour)
	for i := 0; i < 30; i++ {
		s.Add(rec("10.0.0.5", "198.51.100.9", 40000, 443, 6, 1000, base.Add(time.Duration(i)*time.Minute)))
	}
	s.mu.Lock() // the collector holds the lock while the writer is busy: neither may wait for the other
	for i := 0; i < 3*flowWriteQueue; i++ {
		s.persistMinuteLocked(&flowBucket{TS: base.Unix() + int64(i)*60, M: map[flowKey]flowVal{{Exp: tExp}: {1, 1, 1}}})
	}
	s.mu.Unlock()
	s.Close()
	n := 0
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		n += len(readAll(b))
	}
	if n != 3*flowWriteQueue {
		t.Errorf("%d records on disk after Close, want %d", n, 3*flowWriteQueue)
	}
}
