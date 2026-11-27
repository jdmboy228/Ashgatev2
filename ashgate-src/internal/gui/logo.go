package gui

import (
	"image"
	"image/color"
	"math"
)

// LogoImage rasterizes the Ashgate mark: an ember gate with a traffic arrow.
//
// The master geometry lives on a 64x64 grid and is supersampled 4x4 per output
// pixel. Optical bounds are [14.9..49.1] x [12.6..51.4], centered on (32, 32),
// so the mark stays balanced from the 16px tray icon up to the 256px tile.
// Below 24px (16px and 20px tray/titlebar icons), the arch widens and the
// stroke thins slightly so the gate, arrow shaft, and chevron wings keep crisp
// ember gaps between them instead of merging into a cross.
func LogoImage(size int) *image.NRGBA {
	if size < 8 {
		size = 8
	}
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	const ss = 4
	n := float64(ss * ss)

	geom := logoGeometry(size)
	// Fluent lighting is only worth it once there are enough pixels; the inner
	// rim fades out by 24px so the 16px tray icon stays crisp.
	var sheen, rim, shadow float64
	if size >= 32 {
		sheen = 0.14
		shadow = 0.20
	}
	if size > 24 {
		rim = 0.16 * clamp((float64(size)-24)/8, 0, 1)
	}

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					px := (float64(x) + (float64(sx)+0.5)/float64(ss)) * 64 / float64(size)
					py := (float64(y) + (float64(sy)+0.5)/float64(ss)) * 64 / float64(size)
					sr, sg, sb, sa := logoSample(px, py, geom, sheen, rim, shadow)
					r += sr * sa
					g += sg * sa
					b += sb * sa
					a += sa
				}
			}
			a /= n
			if a <= 0 {
				continue
			}
			img.SetNRGBA(x, y, color.NRGBA{
				R: toByte((r / n) / a),
				G: toByte((g / n) / a),
				B: toByte((b / n) / a),
				A: toByte(a),
			})
		}
	}
	return img
}

type logoGeom struct {
	half      float64
	archCX    float64
	archCY    float64
	archR     float64
	leftEndY  float64
	rightEndY float64
	arrowX1   float64
	arrowX2   float64
	arrowY    float64
	wingX     float64
	wingDY    float64
}

// logoGeometry returns the 64x64 monogram geometry for size. At 24px and above
// it uses the exact canonical proportions; below 24px it smoothly transitions
// to an open-aperture, pixel-aligned 16px layout so the gate and entering arrow
// remain unmistakably distinct in the Windows tray and titlebar.
func logoGeometry(size int) logoGeom {
	base := logoGeom{
		half:      strokeHalfWidth(size),
		archCX:    33.0,
		archCY:    28.7,
		archR:     13.0,
		leftEndY:  30.5,
		rightEndY: 48.3,
		arrowX1:   18.0,
		arrowX2:   36.0,
		arrowY:    41.5,
		wingX:     29.5,
		wingDY:    6.8,
	}
	if size >= 24 {
		return base
	}
	// t=1 at <=16px, t=0 at 24px.
	t := clamp((24-float64(size))/8, 0, 1)
	small := logoGeom{
		half:      2.75,
		archCX:    33.0,
		archCY:    29.0,
		archR:     16.0,
		leftEndY:  29.0,
		rightEndY: 51.0,
		arrowX1:   15.0,
		arrowX2:   37.0,
		arrowY:    43.0,
		wingX:     29.5,
		wingDY:    7.5,
	}
	return logoGeom{
		half:      mix(base.half, small.half, t),
		archCX:    mix(base.archCX, small.archCX, t),
		archCY:    mix(base.archCY, small.archCY, t),
		archR:     mix(base.archR, small.archR, t),
		leftEndY:  mix(base.leftEndY, small.leftEndY, t),
		rightEndY: mix(base.rightEndY, small.rightEndY, t),
		arrowX1:   mix(base.arrowX1, small.arrowX1, t),
		arrowX2:   mix(base.arrowX2, small.arrowX2, t),
		arrowY:    mix(base.arrowY, small.arrowY, t),
		wingX:     mix(base.wingX, small.wingX, t),
		wingDY:    mix(base.wingDY, small.wingDY, t),
	}
}

// strokeHalfWidth is half the white stroke width on the 64 grid for 24px and
// above: 3.27 at 24px tapering to 3.1 (6.2 wide) at 28px and above.
func strokeHalfWidth(size int) float64 {
	if size <= 16 {
		return 3.6
	}
	if size >= 28 {
		return 3.1
	}
	return 3.6 - (float64(size)-16)/24
}

// logoSample shades one supersample point (binary coverage; the 4x4 grid
// provides the anti-aliasing). Keeping coverage binary makes the rounded
// corners exactly transparent instead of leaving a faint AA sliver.
func logoSample(px, py float64, g logoGeom, sheen, rim, shadow float64) (r, gCol, b, a float64) {
	sd := sdRound(px, py, 64, 64, 15)
	if sd > 0 {
		return 0, 0, 0, 0
	}
	r, gCol, b = ember(px, py)
	if sheen > 0 {
		// Top sheen: 14% white at the top edge, gone by y=30.
		s := sheen * clamp((30-py)/30, 0, 1)
		r, gCol, b = mix(r, 1, s), mix(gCol, 1, s), mix(b, 1, s)
	}
	if rim > 0 && math.Abs(sd+1.0) <= 0.5 {
		// Inner rim stroke centered 1.0 inside the squircle edge.
		r, gCol, b = mix(r, 1, rim), mix(gCol, 1, rim), mix(b, 1, rim)
	}
	a = 1
	if shadow > 0 {
		// Soft monogram elevation: #6B1505 at 20%, nudged down 1.5 units.
		ds := monogramDist(px, py-1.5, g)
		sa := shadow * smooth((g.half+1.5-ds)/1.5)
		r, gCol, b, a = over(r, gCol, b, a, 0x6B/255.0, 0x15/255.0, 0x05/255.0, sa)
	}
	if monogramDist(px, py, g) <= g.half {
		r, gCol, b, a = 1, 1, 1, 1
	}
	return r, gCol, b, a
}

// emberStops is the three-stop diagonal gradient (t, r, g, b).
var emberStops = [3][4]float64{
	{0.00, 0xFF, 0xA0, 0x5A},
	{0.48, 0xFF, 0x6B, 0x35},
	{1.00, 0xD8, 0x35, 0x1C},
}

func ember(px, py float64) (r, g, b float64) {
	const ax, ay, bx, by = 4.0, 2.0, 60.0, 62.0
	dx, dy := bx-ax, by-ay
	t := clamp(((px-ax)*dx+(py-ay)*dy)/(dx*dx+dy*dy), 0, 1)
	i := 0
	for i < len(emberStops)-2 && t > emberStops[i+1][0] {
		i++
	}
	s0, s1 := emberStops[i], emberStops[i+1]
	f := 0.0
	if s1[0] > s0[0] {
		f = (t - s0[0]) / (s1[0] - s0[0])
	}
	return mix(s0[1], s1[1], f) / 255, mix(s0[2], s1[2], f) / 255, mix(s0[3], s1[3], f) / 255
}

// monogramDist is the distance to the white gate + arrow centerlines.
func monogramDist(px, py float64, g logoGeom) float64 {
	d := archDist(px, py, g)
	d = math.Min(d, distSeg(px, py, g.arrowX1, g.arrowY, g.arrowX2, g.arrowY))                // arrow shaft
	d = math.Min(d, distSeg(px, py, g.wingX, g.arrowY-g.wingDY, g.arrowX2, g.arrowY))         // upper wing
	d = math.Min(d, distSeg(px, py, g.arrowX2, g.arrowY, g.wingX, g.arrowY+g.wingDY))         // lower wing
	return d
}

// archDist is the gate: a semicircular crown on two pillars, with the left
// pillar breached so the arrow can enter.
func archDist(px, py float64, g logoGeom) float64 {
	lx, rx := g.archCX-g.archR, g.archCX+g.archR
	d := distSeg(px, py, lx, g.archCY, lx, g.leftEndY) // breached left pillar
	d = math.Min(d, distSeg(px, py, rx, g.archCY, rx, g.rightEndY))
	return math.Min(d, arcDist(px, py, g))
}

func arcDist(px, py float64, g logoGeom) float64 {
	dx, dy := px-g.archCX, py-g.archCY
	if dy <= 0 {
		return math.Abs(math.Hypot(dx, dy) - g.archR)
	}
	return math.Min(math.Hypot(px-(g.archCX-g.archR), py-g.archCY), math.Hypot(px-(g.archCX+g.archR), py-g.archCY))
}

func distSeg(px, py, x1, y1, x2, y2 float64) float64 {
	vx, vy := x2-x1, y2-y1
	wx, wy := px-x1, py-y1
	c := vx*vx + vy*vy
	t := 0.0
	if c > 0 {
		t = clamp((wx*vx+wy*vy)/c, 0, 1)
	}
	return math.Hypot(px-(x1+t*vx), py-(y1+t*vy))
}

func sdRound(px, py, w, h, rad float64) float64 {
	qx := math.Abs(px-w/2) - (w/2 - rad)
	qy := math.Abs(py-h/2) - (h/2 - rad)
	ox, oy := math.Max(qx, 0), math.Max(qy, 0)
	return math.Hypot(ox, oy) + math.Min(math.Max(qx, qy), 0) - rad
}

func over(dr, dg, db, da, sr, sg, sb, sa float64) (float64, float64, float64, float64) {
	outA := sa + da*(1-sa)
	if outA <= 0 {
		return 0, 0, 0, 0
	}
	return (sr*sa + dr*da*(1-sa)) / outA, (sg*sa + dg*da*(1-sa)) / outA, (sb*sa + db*da*(1-sa)) / outA, outA
}

func mix(a, b, t float64) float64 { return a + (b-a)*t }

func smooth(v float64) float64 { return clamp(v, 0, 1) }

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func toByte(v float64) uint8 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 255
	}
	return uint8(v*255 + 0.5)
}
