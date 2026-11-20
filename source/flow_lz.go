package main

// A small LZ4-style block codec and the framing of the rollup files.
//
// A file of the flow state directory is the magic below followed by frames:
//
//	rawLen u32 | compLen u32 | crc32(raw) u32 | compLen bytes
//
// and every frame holds one gob-encoded record.  A record over two blocks (1 MB) is cut into 512 KB blocks that are packed on
// several cores at once; its frame has the top bit of rawLen set and holds  bRaw u32 | bComp u32 | bytes  for every block.  A file without the magic is the older plain gob stream and is still read.
// A frame that is cut short (the daemon was killed while writing) or does not match its checksum ends the file, as the
// torn end of a plain gob stream did.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"hash/crc32"
	"io"
	"runtime"
	"sync"
)

const flowMagic = "\x00FD1"

const (
	flowMaxFrame = 1 << 30
	lzBlock      = 512 << 10 // a long record is packed in blocks of this size; the match window is 64 KB, so a block boundary costs next to nothing
	lzBlocksFlag = 1 << 31
)

var lzTables = sync.Pool{New: func() any { return new([1 << 16]int32) }} // a frame claiming more than this is damage, not data

// lzCompress packs src into LZ4 block format (greedy matching, 64 KB window).
func lzCompress(src []byte) []byte {
	dst := make([]byte, 0, len(src)/2+64)
	ht := lzTables.Get().(*[1 << 16]int32)
	defer lzTables.Put(ht)
	for i := range ht {
		ht[i] = -1
	}
	putLen := func(r int) {
		for ; r >= 255; r -= 255 {
			dst = append(dst, 255)
		}
		dst = append(dst, byte(r))
	}
	emit := func(lit []byte, off, mlen int) {
		tok := byte(0)
		if len(lit) >= 15 {
			tok = 15 << 4
		} else {
			tok = byte(len(lit)) << 4
		}
		ml := mlen - 4
		if mlen > 0 {
			if ml >= 15 {
				tok |= 15
			} else {
				tok |= byte(ml)
			}
		}
		dst = append(dst, tok)
		if len(lit) >= 15 {
			putLen(len(lit) - 15)
		}
		dst = append(dst, lit...)
		if mlen > 0 {
			dst = append(dst, byte(off), byte(off>>8))
			if ml >= 15 {
				putLen(ml - 15)
			}
		}
	}
	n, anchor, i := len(src), 0, 0
	for i+8 <= n {
		cur := binary.LittleEndian.Uint32(src[i:])
		h := (cur * 2654435761) >> 16
		ref := int(ht[h])
		ht[h] = int32(i)
		if ref >= 0 && i-ref < 65536 && binary.LittleEndian.Uint32(src[ref:]) == cur {
			m := 4
			for i+m < n-4 && src[ref+m] == src[i+m] {
				m++
			}
			emit(src[anchor:i], i-ref, m)
			i += m
			anchor = i
			continue
		}
		i++
	}
	emit(src[anchor:], 0, 0)
	return dst
}

var errLZ = errors.New("flow: damaged compressed block")

// lzDecompress unpacks a block into exactly size bytes; damaged input is an error, never a panic.
func lzDecompress(src []byte, size int) ([]byte, error) {
	dst := make([]byte, 0, size)
	i := 0
	getLen := func(v int) (int, bool) {
		for {
			if i >= len(src) {
				return 0, false
			}
			b := int(src[i])
			i++
			v += b
			if v > size {
				return 0, false
			}
			if b != 255 {
				return v, true
			}
		}
	}
	for i < len(src) {
		tok := src[i]
		i++
		ll := int(tok >> 4)
		if ll == 15 {
			var ok bool
			if ll, ok = getLen(ll); !ok {
				return nil, errLZ
			}
		}
		if i+ll > len(src) || len(dst)+ll > size {
			return nil, errLZ
		}
		dst = append(dst, src[i:i+ll]...)
		i += ll
		if i >= len(src) {
			break
		}
		if i+2 > len(src) {
			return nil, errLZ
		}
		off := int(src[i]) | int(src[i+1])<<8
		i += 2
		ml := int(tok & 15)
		if ml == 15 {
			var ok bool
			if ml, ok = getLen(ml); !ok {
				return nil, errLZ
			}
		}
		ml += 4
		if off == 0 || off > len(dst) || len(dst)+ml > size {
			return nil, errLZ
		}
		p := len(dst) - off
		for k := 0; k < ml; k++ {
			dst = append(dst, dst[p+k])
		}
	}
	if len(dst) != size {
		return nil, errLZ
	}
	return dst, nil
}

// lzFrame gob-encodes v and returns the frame to append to a file.  A record of more than two blocks is packed on up to
// GOMAXPROCS cores.
func lzFrame(v any) ([]byte, error) {
	var raw bytes.Buffer
	if err := gob.NewEncoder(&raw).Encode(v); err != nil {
		return nil, err
	}
	src := raw.Bytes()
	if len(src) <= 2*lzBlock {
		c := lzCompress(src)
		out := make([]byte, 12, 12+len(c))
		binary.LittleEndian.PutUint32(out[0:], uint32(len(src)))
		binary.LittleEndian.PutUint32(out[4:], uint32(len(c)))
		binary.LittleEndian.PutUint32(out[8:], crc32.ChecksumIEEE(src))
		return append(out, c...), nil
	}
	nb := (len(src) + lzBlock - 1) / lzBlock
	parts := make([][]byte, nb)
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.GOMAXPROCS(0))
	for i := 0; i < nb; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer func() { <-sem; wg.Done() }()
			lo, hi := i*lzBlock, min((i+1)*lzBlock, len(src))
			parts[i] = lzCompress(src[lo:hi])
		}(i)
	}
	wg.Wait()
	total := 0
	for _, p := range parts {
		total += 8 + len(p)
	}
	out := make([]byte, 12, 12+total)
	binary.LittleEndian.PutUint32(out[0:], uint32(len(src))|lzBlocksFlag)
	binary.LittleEndian.PutUint32(out[4:], uint32(total))
	binary.LittleEndian.PutUint32(out[8:], crc32.ChecksumIEEE(src))
	for i, p := range parts {
		var h [8]byte
		binary.LittleEndian.PutUint32(h[0:], uint32(min(lzBlock, len(src)-i*lzBlock)))
		binary.LittleEndian.PutUint32(h[4:], uint32(len(p)))
		out = append(append(out, h[:]...), p...)
	}
	return out, nil
}

// lzUnframe returns the raw bytes of a frame's payload.
func lzUnframe(rawLen uint32, comp []byte) ([]byte, error) {
	if rawLen&lzBlocksFlag == 0 {
		return lzDecompress(comp, int(rawLen))
	}
	size := int(rawLen &^ lzBlocksFlag)
	out := make([]byte, 0, size)
	for len(comp) > 0 {
		if len(comp) < 8 {
			return nil, errLZ
		}
		br, bc := int(binary.LittleEndian.Uint32(comp[0:])), int(binary.LittleEndian.Uint32(comp[4:]))
		comp = comp[8:]
		if bc > len(comp) || br > lzBlock || len(out)+br > size {
			return nil, errLZ
		}
		blk, err := lzDecompress(comp[:bc], br)
		if err != nil {
			return nil, err
		}
		out = append(out, blk...)
		comp = comp[bc:]
	}
	if len(out) != size {
		return nil, errLZ
	}
	return out, nil
}

// readFlowRecs calls fn for every record of a state file, compressed or plain; it stops at the torn end of a file.
func readFlowRecs(r io.Reader, fn func(flowFileRec)) {
	br := bufio.NewReaderSize(r, 1<<16)
	if head, _ := br.Peek(len(flowMagic)); string(head) != flowMagic {
		dec := gob.NewDecoder(br) // the plain stream written before compression
		for {
			var rec flowFileRec
			if err := dec.Decode(&rec); err != nil {
				return
			}
			fn(rec)
		}
	}
	br.Discard(len(flowMagic))
	var hdr [12]byte
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return
		}
		rawLen, compLen := binary.LittleEndian.Uint32(hdr[0:]), binary.LittleEndian.Uint32(hdr[4:])
		if rawLen&^lzBlocksFlag > flowMaxFrame || compLen > flowMaxFrame {
			return
		}
		comp := make([]byte, compLen)
		if _, err := io.ReadFull(br, comp); err != nil {
			return
		}
		raw, err := lzUnframe(rawLen, comp)
		if err != nil || crc32.ChecksumIEEE(raw) != binary.LittleEndian.Uint32(hdr[8:]) {
			return
		}
		var rec flowFileRec
		if gob.NewDecoder(bytes.NewReader(raw)).Decode(&rec) != nil {
			return
		}
		fn(rec)
	}
}
