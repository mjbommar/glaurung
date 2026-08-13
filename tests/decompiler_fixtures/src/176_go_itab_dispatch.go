// 176_go_itab_dispatch.go
//
// Go interface dispatch through itabs. A Go interface value is a two-word pair
// (itab, data): the itab is a per-(interface, concrete-type) table emitted by the
// linker holding the interface's type, the concrete type, a type hash, and the
// method slots in interface-declaration order. A call like `s.area(k)` is a load
// of the itab word, a load of a fixed slot inside it, and an indirect call whose
// first argument is the data word. Nothing in the call site names the callee.
//
// The interesting recovery signals:
//   * `pick` materialises FOUR distinct itabs for one interface. Recovering the
//     dispatch means recovering "which itab is in flight", which is a data-flow
//     fact about a linker-built table, not a fact about the call instruction.
//   * `counter` has a POINTER receiver, so `*counter` implements `shaper` and
//     `counter` does not: two type descriptors, one method set, different itabs.
//   * `scalar` is a named non-struct type, so its data word is the value itself
//     when it fits in a word -- the data word is not always a pointer.
//   * a type switch compiles to an itab/type-hash compare chain, NOT to a
//     virtual call; a comma-ok assertion to a SECOND interface (`tagger`) is a
//     runtime itab lookup instead. Three different lowerings of "which type".
//   * `go_iface_nil` separates a nil interface (both words nil) from an
//     interface holding a typed nil pointer (itab set, data nil) -- the two are
//     indistinguishable at any single word and differ only in the pair.
//   * storing interfaces into a `[]shaper` puts pointers into the heap, so the
//     write barrier is live on the append path.
//
// Exposure: every driver is `//export`ed over plain `C.int` scalars and a
// caller-owned `*C.int` buffer, built `-buildmode=c-shared`. Counts are clamped
// to <= 16, buffer pointers are null-checked, selectors are reduced through
// `uint32` (so a negative selector cannot index anything), and every mask yields
// a non-negative value. Go's int32 arithmetic wraps silently rather than
// trapping, so no arithmetic here can panic. `(*counter).area` null-checks its
// receiver, so even the typed-nil path is total.
//
// Deterministic: fresh receivers per call, no map iteration, no goroutines, no
// time, no randomness, no address-dependent values.

package main

import "C"
import "unsafe"

// clampN bounds a caller-supplied count into [0, 16].
func clampN(n int32) int32 {
	if n < 0 {
		return 0
	}
	if n > 16 {
		return 16
	}
	return n
}

// shaper is the dispatched-through interface: two slots, in declaration order.
type shaper interface {
	area(k int32) int32
	tag() int32
}

// tagger is a strict subset of shaper's method set, so an assertion from shaper
// to tagger is a runtime itab lookup rather than a pointer compare.
type tagger interface {
	tag() int32
}

type square struct{ side int32 }

type rect struct{ w, h int32 }

// scalar is a named integer type with methods: its interface data word holds the
// value directly when it fits, not a pointer to it.
type scalar int32

type counter struct{ n int32 }

func (s square) area(k int32) int32 { return s.side*s.side + k }
func (s square) tag() int32         { return 1 }

func (r rect) area(k int32) int32 { return r.w*r.h + k }
func (r rect) tag() int32         { return 2 }

func (v scalar) area(k int32) int32 { return int32(v) + k }
func (v scalar) tag() int32         { return 3 }

// Pointer receiver: `*counter` implements shaper, `counter` does not.
// The receiver is null-checked so a typed-nil interface stays total.
func (c *counter) area(k int32) int32 {
	if c == nil {
		return -1
	}
	c.n += k
	return c.n
}

// tag never dereferences, so it is callable on a typed-nil receiver.
func (c *counter) tag() int32 { return 4 }

// pick materialises one of four distinct itabs for `shaper`.
func pick(sel int32) shaper {
	switch uint32(sel) % 4 {
	case 0:
		return square{side: 3 + (sel & 7)}
	case 1:
		return rect{w: 2 + (sel & 3), h: 5}
	case 2:
		return scalar(sel & 0xFF)
	default:
		return &counter{n: sel & 15}
	}
}

// go_iface_dispatch: two indirect calls through two different itab slots of the
// same interface value.
//
//export go_iface_dispatch
func go_iface_dispatch(sel C.int, k C.int) C.int {
	s := pick(int32(sel))
	return C.int(s.area(int32(k)) + s.tag())
}

// go_iface_type_switch: a type switch is an itab/type-hash compare chain, not a
// virtual call -- the concrete type is recovered, then used directly.
//
//export go_iface_type_switch
func go_iface_type_switch(sel C.int, k C.int) C.int {
	var acc int32
	s := pick(int32(sel))
	switch v := s.(type) {
	case square:
		acc = 10 + v.side
	case rect:
		acc = 20 + v.w + v.h
	case scalar:
		acc = 30 + int32(v)
	case *counter:
		acc = 40 + v.n
	default:
		acc = -1
	}
	return C.int(acc + int32(k))
}

// go_iface_assert: a comma-ok assertion to a CONCRETE type is an itab pointer
// compare; the same form against another INTERFACE is a runtime lookup.
//
//export go_iface_assert
func go_iface_assert(sel C.int, k C.int) C.int {
	s := pick(int32(sel))
	if sq, ok := s.(square); ok {
		return C.int(sq.side*2 + int32(k))
	}
	if t, ok := s.(tagger); ok {
		return C.int(t.tag()*100 + int32(k))
	}
	return C.int(int32(k))
}

// go_iface_table: dispatch in a loop over a heap-allocated []shaper, so the itab
// word is loop-variant and the append path takes the write barrier.
//
//export go_iface_table
func go_iface_table(n C.int, k C.int) C.int {
	m := clampN(int32(n))
	tbl := make([]shaper, 0, 16)
	for i := int32(0); i < m; i++ {
		tbl = append(tbl, pick(i))
	}
	var acc int32
	for _, s := range tbl {
		acc = acc*3 + s.area(int32(k))
	}
	return C.int(acc)
}

// go_iface_fill: per-selector dispatch results into a caller-owned buffer.
//
//export go_iface_fill
func go_iface_fill(out *C.int, n C.int, k C.int) C.int {
	m := clampN(int32(n))
	if out == nil || m == 0 {
		return 0
	}
	buf := unsafe.Slice((*int32)(unsafe.Pointer(out)), int(m))
	for i := int32(0); i < m; i++ {
		buf[i] = pick(i).area(int32(k))
	}
	return C.int(m)
}

// go_iface_nil: a nil interface and an interface holding a typed nil pointer
// differ only in the (itab, data) PAIR -- neither word alone distinguishes them.
//
//export go_iface_nil
func go_iface_nil(sel C.int) C.int {
	var s shaper
	var p *counter
	if uint32(sel)&1 == 1 {
		s = p
	}
	if s == nil {
		return 0
	}
	return C.int(s.tag()*10 + s.area(1))
}

func main() {}
