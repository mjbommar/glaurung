// 178_go_defer_panic_recover.go
//
// Go defer, panic and recover. `defer` is two different mechanisms wearing one
// keyword: with a small, statically-known number of deferrals and none inside a
// loop, the compiler OPEN-CODES them -- the deferred calls are emitted inline at
// every return site, guarded by a bitmask of "has this one been armed yet"
// flags, and there is no defer record at all. Put one inside a loop and the
// whole function falls back to the heap path, pushing `runtime._defer` records
// onto a linked list off the `g` and running them from `runtime.deferreturn`.
// The same source construct, two unrecognisably different lowerings.
//
// The interesting recovery signals:
//   * `go_defer_order` (four deferrals, no loop) and `go_defer_loop` (deferrals
//     in a loop) express the same LIFO ordering through those two mechanisms. In
//     the open-coded case the ordering is STRAIGHT-LINE CODE plus a bitmask; in
//     the heap case it is a runtime list walk. Only the first is recoverable as
//     control flow at all.
//   * a deferred closure that writes the NAMED result runs after the `return`
//     expression has already been evaluated and stored, so the returned value is
//     not the value at the return statement. `go_defer_result` is that gap.
//   * `panic` is a call to `runtime.gopanic` that never returns to its call
//     site; the recovery point is a deferred frame, so the edge from panic to
//     resumption exists only through the runtime. There is no CFG edge for it.
//   * `recover()` is only effective when called DIRECTLY from a deferred
//     function -- one more frame of indirection and it returns nil and the panic
//     keeps unwinding. `go_panic_nested` depends on that rule.
//   * runtime panics (index out of range, divide by zero, nil dereference) enter
//     the same machinery from a hardware fault or an inline bounds check, so
//     `go_panic_runtime` reaches gopanic through three different lowerings.
//   * re-panicking from inside a recover handler restarts the unwind with a new
//     value while the first defer is still running.
//
// Exposure: every driver is `//export`ed over plain `C.int` scalars and a
// caller-owned `*C.int` buffer, built `-buildmode=c-shared`. Counts are clamped
// to <= 16 and buffer pointers are null-checked. Every panic raised here is
// raised BEHIND a deferred recover in the same Go call tree and is converted to
// an ordinary integer result, so no panic can ever unwind out through the C
// boundary -- which is the whole point of this fixture: the panic paths are
// present and taken, and they are unreachable as panics from outside.
//
// Deterministic: no goroutines (a panic on another goroutine could not be
// recovered here), no map iteration, no time, no randomness.

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

// go_defer_order: four deferrals, none in a loop -- the OPEN-CODED path. The
// LIFO order is emitted as straight-line code at the return site.
//
//export go_defer_order
func go_defer_order(out *C.int, n C.int) C.int {
	m := clampN(int32(n))
	if out == nil || m < 4 {
		return 0
	}
	buf := unsafe.Slice((*int32)(unsafe.Pointer(out)), int(m))
	slot := int32(0)
	record := func(v int32) {
		if slot < 4 {
			buf[slot] = v
			slot++
		}
	}
	defer record(1)
	defer record(2)
	defer record(3)
	defer record(4)
	return C.int(4)
}

// go_defer_loop: the same LIFO ordering, but the deferrals are inside a loop, so
// the whole function takes the HEAP defer path and the order is produced by a
// runtime list walk instead of by emitted code.
//
//export go_defer_loop
func go_defer_loop(out *C.int, n C.int) C.int {
	m := clampN(int32(n))
	if out == nil || m == 0 {
		return 0
	}
	buf := unsafe.Slice((*int32)(unsafe.Pointer(out)), int(m))
	slot := int32(0)
	for i := int32(0); i < m; i++ {
		v := i
		defer func() {
			if slot < m {
				buf[slot] = v * 10
				slot++
			}
		}()
	}
	return C.int(m)
}

// deferredResult returns `x`, then a deferred closure rewrites the NAMED result
// after the return value has already been stored.
func deferredResult(x int32) (r int32) {
	defer func() { r = r*2 + 1 }()
	defer func() { r += 100 }()
	r = x
	return r
}

// go_defer_result: the returned value is not the value at the return statement.
//
//export go_defer_result
func go_defer_result(x C.int) C.int {
	return C.int(deferredResult(int32(x)))
}

// explicitPanic panics with an int value chosen by sel; the deferred recover
// converts it back into an ordinary result. Nothing escapes.
func explicitPanic(sel int32, x int32) (code int32) {
	defer func() {
		if v := recover(); v != nil {
			if n, ok := v.(int32); ok {
				code = n * 3
			} else {
				code = -2
			}
		}
	}()
	if uint32(sel)%3 == 0 {
		panic(x & 0xFF)
	}
	if uint32(sel)%3 == 1 {
		panic(int32(x&0xFF) + 1)
	}
	return x & 7
}

// go_panic_recover: panic with a value, recover it, map it to a code.
//
//export go_panic_recover
func go_panic_recover(sel C.int, x C.int) C.int {
	return C.int(explicitPanic(int32(sel), int32(x)))
}

// runtimePanic reaches runtime.gopanic through three DIFFERENT lowerings: an
// inline bounds check, a divide-by-zero check, and a hardware fault on a nil
// dereference. All three are recovered here.
func runtimePanic(sel int32, x int32) (code int32) {
	defer func() {
		if v := recover(); v != nil {
			code = 1000
			if _, ok := v.(error); ok {
				code += 7
			}
		}
	}()
	small := []int32{1, 2, 3, 4}
	switch uint32(sel) % 4 {
	case 0:
		// index out of range: an inline bounds check calling panicIndex.
		i := int32(len(small)) + (x & 3)
		return small[i]
	case 1:
		// integer divide by zero.
		d := int32(0)
		return x / d
	case 2:
		// nil dereference: a hardware fault converted into a panic.
		var p *int32
		return *p
	default:
		// the total path: no panic at all, so recover() returns nil.
		return small[uint32(x)%uint32(len(small))]
	}
}

// go_panic_runtime: three runtime panic sources plus a no-panic control.
//
//export go_panic_runtime
func go_panic_runtime(sel C.int, x C.int) C.int {
	return C.int(runtimePanic(int32(sel), int32(x)))
}

// indirectRecover calls recover() from a nested function rather than directly
// from the deferred one, so it is INEFFECTIVE and the panic keeps unwinding.
func indirectRecover() any {
	return recover()
}

// deepPanic panics at the bottom of a chain of frames.
func deepPanic(depth int32, x int32) int32 {
	if depth <= 0 {
		panic(x&0xFF + 5)
	}
	return deepPanic(depth-1, x) + 1
}

// nestedPanic lets the panic pass an INEFFECTIVE recover before reaching an
// effective one, so the unwind crosses a deferred frame that did not stop it.
func nestedPanic(depth int32, x int32) (code int32) {
	defer func() {
		if v := recover(); v != nil {
			if n, ok := v.(int32); ok {
				code = n * 2
			} else {
				code = -3
			}
		}
	}()
	code = inner(depth, x)
	return code
}

func inner(depth int32, x int32) int32 {
	// recover() here is called from a nested call, not directly from the
	// deferred function, so it returns nil and the panic continues past it.
	defer func() { _ = indirectRecover() }()
	return deepPanic(depth, x)
}

// go_panic_nested: an unwind across several frames and one ineffective recover.
//
//export go_panic_nested
func go_panic_nested(depth C.int, x C.int) C.int {
	d := clampN(int32(depth))
	return C.int(nestedPanic(d, int32(x)))
}

// repanic recovers a panic and immediately raises a NEW one from inside the
// handler, which the outer deferred frame then recovers.
func repanic(x int32) (code int32) {
	defer func() {
		if v := recover(); v != nil {
			if n, ok := v.(int32); ok {
				code = n + 1
			} else {
				code = -4
			}
		}
	}()
	code = repanicInner(x)
	return code
}

func repanicInner(x int32) (code int32) {
	defer func() {
		if v := recover(); v != nil {
			if n, ok := v.(int32); ok {
				panic(n * 7)
			}
			panic(int32(-5))
		}
	}()
	panic(x & 0x1F)
}

// go_panic_repanic: a second unwind started from inside the first one's handler.
//
//export go_panic_repanic
func go_panic_repanic(x C.int) C.int {
	return C.int(repanic(int32(x)))
}

func main() {}
