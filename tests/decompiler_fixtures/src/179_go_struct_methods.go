// 179_go_struct_methods.go
//
// Go methods, receivers and embedding. A Go method is an ordinary function whose
// first parameter is the receiver, but WHICH function a call names depends on
// three source-level facts that leave no trace at the call site: whether the
// receiver is by value or by pointer, whether the receiver expression was
// addressable (so the compiler could insert an implicit `&`), and how far up an
// embedding chain the selector had to walk.
//
// The interesting recovery signals:
//   * a VALUE receiver is a copy. `(cell) bumpValue` mutates a copy that is
//     discarded at return; `(*cell) bumpPointer` mutates the caller's object.
//     Both are one call instruction with one pointer-ish argument at the ABI
//     level, and only the body distinguishes them. `go_recv_value` and
//     `go_recv_pointer` are that pair.
//   * `outer.bumpPointer(k)` on an addressable value is silently rewritten to
//     `(&outer.cell).bumpPointer(k)`: an address-of that appears nowhere in the
//     source. Recovering the source shape means recovering an operator the
//     programmer never wrote.
//   * EMBEDDING is not inheritance. `wrapper` embeds `cell`, so `wrapper.total`
//     is a walk to a fixed byte offset and a direct call to `(*cell).total` --
//     no vtable, no indirection. The promoted method is statically resolved but
//     its receiver is an INTERIOR pointer to a field, so the argument at the
//     call site is `&w + offsetof(cell)`, not `&w`.
//   * SHADOWING: `shadowed` defines its own `total`, so the identical selector
//     `x.total()` resolves to a different function depending only on the static
//     type; the embedded one is still reachable as `x.cell.total()`.
//   * a METHOD VALUE (`v.total`) allocates a closure capturing the bound
//     receiver -- a funcval whose first word is a code pointer -- while a METHOD
//     EXPRESSION (`cell.total`) is a plain function with the receiver as an
//     explicit first parameter. Same syntax family, different objects.
//   * a struct that EMBEDS AN INTERFACE gets its method set promoted through an
//     itab held in a field, so a "promoted" call is an indirect one.
//
// Exposure: every driver is `//export`ed over plain `C.int` scalars and a
// caller-owned `*C.int` buffer, built `-buildmode=c-shared`. Counts are clamped
// to <= 16, buffer pointers are null-checked, selectors are reduced through
// `uint32`, and the embedded interface field is always populated before use, so
// no promoted call can reach a nil itab. Go's int32 arithmetic wraps rather than
// trapping, so nothing here can panic.
//
// Deterministic: receivers are constructed fresh inside each driver, so no state
// survives a call; no map iteration, no goroutines, no time, no randomness.

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

// cell is the base type: one value-receiver mutator, one pointer-receiver
// mutator, and one reader.
type cell struct {
	n int32
	w int32
}

// bumpValue mutates a COPY. The caller's cell is unchanged.
func (c cell) bumpValue(k int32) int32 {
	c.n += k
	c.w = c.n * 2
	return c.n + c.w
}

// bumpPointer mutates the caller's cell through the receiver pointer.
func (c *cell) bumpPointer(k int32) int32 {
	c.n += k
	c.w = c.n * 2
	return c.n + c.w
}

func (c *cell) total() int32 { return c.n*10 + c.w }

// wrapper EMBEDS cell, so cell's methods are promoted to wrapper at a fixed
// field offset -- the promoted receiver is an interior pointer.
type wrapper struct {
	cell
	extra int32
}

// shadowed also embeds cell but defines its OWN total, shadowing the promoted
// one; the embedded method stays reachable through the explicit field.
type shadowed struct {
	cell
	extra int32
}

func (s *shadowed) total() int32 { return s.extra*1000 + s.cell.total() }

// reporter is embedded as an INTERFACE, so its promoted method is dispatched
// through an itab stored in a field rather than resolved statically.
type reporter interface {
	report(k int32) int32
}

type evenReport struct{ base int32 }
type oddReport struct{ base int32 }

func (e evenReport) report(k int32) int32 { return e.base*2 + k }
func (o oddReport) report(k int32) int32  { return o.base*3 - k }

// host embeds the INTERFACE, not a concrete type.
type host struct {
	reporter
	bias int32
}

// go_recv_value: a value receiver mutates a copy, so the caller's object is
// unchanged and the second call sees the original.
//
//export go_recv_value
func go_recv_value(x C.int, k C.int) C.int {
	c := cell{n: int32(x) & 0xFF, w: 1}
	first := c.bumpValue(int32(k))
	second := c.bumpValue(int32(k))
	return C.int(first + second*7 + c.total())
}

// go_recv_pointer: a pointer receiver mutates the caller's object, so the second
// call sees the first one's effect. `c.bumpPointer` on an addressable `c` is an
// implicit `(&c).bumpPointer`.
//
//export go_recv_pointer
func go_recv_pointer(x C.int, k C.int) C.int {
	c := cell{n: int32(x) & 0xFF, w: 1}
	first := c.bumpPointer(int32(k))
	second := c.bumpPointer(int32(k))
	return C.int(first + second*7 + c.total())
}

// go_embed_promote: the promoted selector resolves statically to (*cell), with
// an interior pointer into the wrapper as the receiver.
//
//export go_embed_promote
func go_embed_promote(x C.int, k C.int) C.int {
	w := wrapper{cell: cell{n: int32(x) & 0xFF, w: 2}, extra: 5}
	promoted := w.bumpPointer(int32(k))
	direct := w.cell.bumpPointer(int32(k))
	return C.int(promoted + direct*7 + w.total() + w.extra)
}

// go_embed_shadow: the same selector spelling resolves to the outer method, and
// the shadowed one is only reachable through the explicit embedded field.
//
//export go_embed_shadow
func go_embed_shadow(x C.int, k C.int) C.int {
	s := shadowed{cell: cell{n: int32(x) & 0xFF, w: 3}, extra: int32(k) & 15}
	outer := s.total()
	innerTotal := s.cell.total()
	s.bumpPointer(int32(k))
	return C.int(outer + innerTotal*7 + s.total())
}

// go_method_value: a bound method VALUE (a closure over the receiver) beside a
// method EXPRESSION (a plain function taking the receiver explicitly).
//
//export go_method_value
func go_method_value(sel C.int, x C.int) C.int {
	c := cell{n: int32(x) & 0xFF, w: 4}
	// Method value: captures &c, so later mutations are visible through it.
	bound := c.bumpPointer
	// Method expression: the receiver is an ordinary first parameter.
	expr := (*cell).bumpPointer
	valueExpr := cell.bumpValue
	var acc int32
	if uint32(sel)&1 == 0 {
		acc += bound(1)
		acc += expr(&c, 2) * 3
	} else {
		acc += expr(&c, 2)
		acc += bound(1) * 3
	}
	acc += valueExpr(c, 5)
	return C.int(acc + c.total())
}

// go_embed_iface: an embedded INTERFACE promotes its method set through an itab
// held in a field, so the "promoted" call is indirect.
//
//export go_embed_iface
func go_embed_iface(sel C.int, k C.int) C.int {
	var h host
	if uint32(sel)&1 == 0 {
		h = host{reporter: evenReport{base: int32(k) & 15}, bias: 10}
	} else {
		h = host{reporter: oddReport{base: int32(k) & 15}, bias: 20}
	}
	// Promoted through the embedded interface: an indirect call.
	promoted := h.report(int32(k))
	// The same call written explicitly through the field.
	explicit := h.reporter.report(int32(k))
	return C.int(promoted + explicit*7 + h.bias)
}

// go_recv_fill: a loop of pointer-receiver calls, so the mutation carries across
// iterations and lands in a caller-owned buffer.
//
//export go_recv_fill
func go_recv_fill(out *C.int, n C.int, k C.int) C.int {
	m := clampN(int32(n))
	if out == nil || m == 0 {
		return 0
	}
	buf := unsafe.Slice((*int32)(unsafe.Pointer(out)), int(m))
	w := wrapper{cell: cell{n: int32(k) & 15, w: 1}, extra: 2}
	for i := int32(0); i < m; i++ {
		buf[i] = w.bumpPointer(i) + w.bumpValue(i)
	}
	return C.int(m)
}

func main() {}
