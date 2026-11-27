package gui

import (
	"bytes"
	"encoding/binary"
	"image/color"
	"image/png"
	"math"
	"os"
	"testing"
)

func TestLogoImage(t *testing.T) {
	img := LogoImage(64)
	if img.Bounds().Dx() != 64 {
		t.Fatal(img.Bounds())
	}
	corner := img.NRGBAAt(0, 0)
	if corner.A != 0 {
		t.Fatalf("corner alpha %d", corner.A)
	}
	mid := img.NRGBAAt(32, 32)
	if mid.A < 200 || mid.R < mid.B {
		t.Fatalf("center %+v", mid)
	}
}

// TestLogoImageSizes checks the whole icon family: transparent corners, an
// ember interior, a bright white monogram, and a white-pixel centroid that is
// optically centered on the 64x64 master grid.
func TestLogoImageSizes(t *testing.T) {
	sizes := []int{16, 20, 24, 32, 40, 48, 64, 128, 256}
	for _, size := range sizes {
		img := LogoImage(size)
		if got := img.Bounds().Dx(); got != size {
			t.Fatalf("size %d: bounds %v", size, img.Bounds())
		}
		if a := img.NRGBAAt(0, 0).A; a != 0 {
			t.Fatalf("size %d: corner alpha %d", size, a)
		}

		var ember, white, whitish int
		var sx, sy float64
		for y := 0; y < size; y++ {
			for x := 0; x < size; x++ {
				p := img.NRGBAAt(x, y)
				if p.A > 200 && int(p.R)-int(p.B) >= 40 && p.R >= 150 {
					ember++
				}
				if isWhite(p) {
					white++
				}
				// "Whitish" includes anti-aliased monogram edges: any channel
				// above the ember's brightest component means white dominates.
				if p.A > 200 && p.R > 120 && p.G > 120 && p.B > 120 {
					whitish++
					sx += float64(x)
					sy += float64(y)
				}
			}
		}
		if ember == 0 {
			t.Fatalf("size %d: no ember interior pixel", size)
		}
		if white < size*size/100 {
			t.Fatalf("size %d: only %d bright white pixels", size, white)
		}

		// Centroid measured on the 64x64 master grid.
		cx := sx / float64(whitish) * 64 / float64(size)
		cy := sy / float64(whitish) * 64 / float64(size)
		if math.Abs(cx-32) > 2.5 || math.Abs(cy-32) > 2.5 {
			t.Fatalf("size %d: white centroid (%.2f, %.2f) on 64 grid, want (32, 32) ±2.5", size, cx, cy)
		}
	}
}

func isWhite(p color.NRGBA) bool {
	return p.A > 200 && p.R > 200 && p.G > 200 && p.B > 200
}

// TestLogoICO verifies the multi-size Windows icon: all nine standard sizes,
// 32-bit DIBs for legacy sizes and a PNG-compressed 256px entry.
func TestLogoICO(t *testing.T) {
	data, err := os.ReadFile("../../winres/ashgate.ico")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 6 {
		t.Fatalf("ico too short: %d bytes", len(data))
	}
	if r := binary.LittleEndian.Uint16(data[0:]); r != 0 {
		t.Fatalf("reserved %d", r)
	}
	if typ := binary.LittleEndian.Uint16(data[2:]); typ != 1 {
		t.Fatalf("type %d, want 1 (icon)", typ)
	}
	count := int(binary.LittleEndian.Uint16(data[4:]))
	if count != 9 {
		t.Fatalf("entry count %d, want 9", count)
	}
	want := []int{16, 20, 24, 32, 40, 48, 64, 128, 256}
	seen := map[int]bool{}
	png256 := false
	for i := 0; i < count; i++ {
		off := 6 + i*16
		if off+16 > len(data) {
			t.Fatalf("entry %d truncated", i)
		}
		e := data[off : off+16]
		w, h := int(e[0]), int(e[1])
		if w == 0 {
			w = 256
		}
		if h == 0 {
			h = 256
		}
		if w != h {
			t.Fatalf("entry %d not square: %dx%d", i, w, h)
		}
		if planes := binary.LittleEndian.Uint16(e[4:]); planes != 1 {
			t.Fatalf("entry %d planes %d", i, planes)
		}
		if bpp := binary.LittleEndian.Uint16(e[6:]); bpp != 32 {
			t.Fatalf("entry %d bit count %d", i, bpp)
		}
		bytesInRes := int(binary.LittleEndian.Uint32(e[8:]))
		imgOff := int(binary.LittleEndian.Uint32(e[12:]))
		if imgOff+bytesInRes > len(data) {
			t.Fatalf("entry %d payload [%d:%d] out of range %d", i, imgOff, imgOff+bytesInRes, len(data))
		}
		seen[w] = true
		payload := data[imgOff : imgOff+bytesInRes]
		if w == 256 {
			if !bytes.HasPrefix(payload, []byte("\x89PNG\r\n\x1a\n")) {
				t.Fatalf("256 entry is not PNG: % x", payload[:8])
			}
			if _, err := png.Decode(bytes.NewReader(payload)); err != nil {
				t.Fatalf("256 entry PNG decode: %v", err)
			}
			png256 = true
			continue
		}
		if len(payload) < 40 {
			t.Fatalf("entry %d DIB too short: %d", i, len(payload))
		}
		hdr := binary.LittleEndian.Uint32(payload[0:])
		dw := int32(binary.LittleEndian.Uint32(payload[4:]))
		dh := int32(binary.LittleEndian.Uint32(payload[8:]))
		bits := binary.LittleEndian.Uint16(payload[14:])
		comp := binary.LittleEndian.Uint32(payload[16:])
		if hdr != 40 || dw != int32(w) || dh != int32(2*w) || bits != 32 || comp != 0 {
			t.Fatalf("entry %d bad DIB header: size=%d w=%d h=%d bits=%d comp=%d", i, hdr, dw, dh, bits, comp)
		}
		wantLen := 40 + w*w*4 + ((w+31)/32)*4*w
		if len(payload) != wantLen {
			t.Fatalf("entry %d payload %d, want %d", i, len(payload), wantLen)
		}
	}
	for _, s := range want {
		if !seen[s] {
			t.Fatalf("icon is missing size %d", s)
		}
	}
	if !png256 {
		t.Fatal("icon has no PNG-compressed 256px entry")
	}
}

// TestLogoAssets verifies the embedded raster assets decode as valid PNGs of
// the expected dimensions.
func TestLogoAssets(t *testing.T) {
	cases := []struct {
		path string
		size int
	}{
		{"ui/favicon.png", 32},
		{"../../winres/icon.png", 256},
	}
	for _, c := range cases {
		data, err := os.ReadFile(c.path)
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		img, err := png.Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		if b := img.Bounds(); b.Dx() != c.size || b.Dy() != c.size {
			t.Fatalf("%s: bounds %v, want %dx%d", c.path, b, c.size, c.size)
		}
	}
}
