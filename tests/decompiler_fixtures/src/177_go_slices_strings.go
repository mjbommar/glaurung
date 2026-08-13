// 177_go_slices_strings.go
//
// Go slice and string headers. A slice is a three-word header (data, len, cap);
// a string is a two-word header (data, len). Neither is a pointer, both are
// passed by value, and both are spilled to the stack whenever they cross a call
// that the register ABI cannot carry them through. `len`/`cap` are not calls --
// they are field loads from a header that only DWARF and the calling convention
// say exists.
//
// The interesting recovery signals:
//   * `append` is not an operator: it lowers to an inlined "does it fit?" test
//     plus a cold call to `runtime.growslice`, and the growth policy (doubling
//     under a threshold, then 1.25x with rounding to a size class) is a property
//     of the linked runtime rather than of this source. `go_slice_grow` returns
//     the observed cap, so the recovered code has to reproduce the runtime's
//     arithmetic, not a formula from the source.
//   * subslicing `s[a:b]` adjusts data and len; the three-index form `s[a:b:c]`
//     also adjusts cap. All three words move independently -- a recovery that
//     models a slice as a bare pointer loses cap entirely and `go_slice_sub`
//     reports it.
//   * `copy` lowers to `runtime.memmove` with the MIN of two lens, computed from
//     two headers -- a bound that appears nowhere in the source text.
//   * ranging over a string decodes UTF-8: the loop index advances by the
//     ENCODED width (1, 2, 3, or 4), not by one, and yields runes. Ranging over
//     `[]byte(s)` does not. `go_string_runes` vs `go_string_bytes` is that
//     contrast.
//   * `[]byte(s)` allocates and copies (strings are immutable), and `+` on
//     strings is a `runtime.concatstring` call, so string "arithmetic" is
//     allocation.
//
// Exposure: every driver is `//export`ed over plain `C.int` scalars and
// caller-owned `*C.int` buffers, built `-buildmode=c-shared`. Counts and indices
// are clamped to <= 16 and re-clamped against the real len before any index or
// slice expression, buffer pointers are null-checked, and every bound is derived
// through `uint32` so a negative input cannot produce a negative index. No
// indexing, slicing, or conversion here can panic on any C.int the harness can
// pass.
//
// Deterministic: the sample string is a compile-time constant written in ASCII
// escapes, there is no map iteration, no goroutines, no time, no randomness, and
// no value depends on an address.

package main

import "C"
import "unsafe"

// sample mixes 1-, 2-, 3- and 4-byte UTF-8 encodings so a range loop over it
// advances by four different widths. Written as escapes to keep the source pure
// ASCII: "aA0" + U+00E9 + U+4E2D + U+1F600 + "zZ9".
const sample = "aA0\u00e9\u4e2d\U0001F600zZ9"

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

// clampTo bounds v into [0, hi] without ever going negative.
func clampTo(v int32, hi int32) int32 {
	if hi < 0 {
		return 0
	}
	if v < 0 {
		return 0
	}
	if v > hi {
		return hi
	}
	return v
}

// go_slice_grow: append growth. The returned cap is whatever the LINKED runtime
// chose, not a number derivable from this source.
//
//export go_slice_grow
func go_slice_grow(n C.int) C.int {
	m := clampN(int32(n))
	s := make([]int32, 0, 1)
	for i := int32(0); i < m; i++ {
		s = append(s, i*i)
	}
	return C.int(int32(len(s))*1000 + int32(cap(s)))
}

// go_slice_sub: two-index and three-index subslicing move data, len and cap
// independently.
//
//export go_slice_sub
func go_slice_sub(a C.int, b C.int) C.int {
	base := make([]int32, 16, 24)
	for i := range base {
		base[i] = int32(i) * 3
	}
	lo := clampTo(int32(a), int32(len(base)))
	hi := clampTo(int32(b), int32(len(base)))
	if lo > hi {
		lo, hi = hi, lo
	}
	two := base[lo:hi]
	// Three-index form: cap is cut to hi-lo, so `two` and `three` share data and
	// len but differ in cap.
	three := base[lo:hi:hi]
	var sum int32
	for _, v := range three {
		sum += v
	}
	return C.int(sum + int32(len(two))*100 + int32(cap(two))*10 + int32(cap(three)))
}

// go_slice_copy: copy() moves MIN(len(dst), len(src)) elements -- a bound
// computed from two headers.
//
//export go_slice_copy
func go_slice_copy(out *C.int, n C.int) C.int {
	m := clampN(int32(n))
	if out == nil || m == 0 {
		return 0
	}
	dst := unsafe.Slice((*int32)(unsafe.Pointer(out)), int(m))
	src := make([]int32, 8)
	for i := range src {
		src[i] = int32(i)*int32(i) + 1
	}
	moved := copy(dst, src)
	return C.int(int32(moved))
}

// go_slice_header: the three header words made observable side by side, after a
// subslice has moved all three.
//
//export go_slice_header
func go_slice_header(out *C.int, n C.int, k C.int) C.int {
	m := clampN(int32(n))
	if out == nil || m < 3 {
		return 0
	}
	buf := unsafe.Slice((*int32)(unsafe.Pointer(out)), int(m))
	base := make([]int32, 12, 20)
	for i := range base {
		base[i] = int32(i) + int32(k)
	}
	cut := clampTo(int32(k)&7, int32(len(base)))
	view := base[cut:]
	buf[0] = int32(len(view))
	buf[1] = int32(cap(view))
	var sum int32
	for _, v := range view {
		sum += v
	}
	buf[2] = sum
	return C.int(3)
}

// go_string_len: string len is a header field, and indexing yields a BYTE.
//
//export go_string_len
func go_string_len(i C.int) C.int {
	idx := clampTo(int32(uint32(i)&0xFF), int32(len(sample))-1)
	return C.int(int32(len(sample))*1000 + int32(sample[idx]))
}

// go_string_runes: ranging a string decodes UTF-8 -- the index advances by the
// encoded width and the value is a rune, not a byte.
//
//export go_string_runes
func go_string_runes(k C.int) C.int {
	var runes int32
	var sumCodepoints int32
	var lastIndex int32
	for i, r := range sample {
		runes++
		sumCodepoints += int32(r)
		lastIndex = int32(i)
	}
	return C.int(runes*1000000 + sumCodepoints + lastIndex + int32(k))
}

// go_string_bytes: []byte(s) allocates and copies; ranging the result advances
// one byte at a time, unlike ranging the string.
//
//export go_string_bytes
func go_string_bytes(out *C.int, n C.int) C.int {
	m := clampN(int32(n))
	if out == nil || m == 0 {
		return 0
	}
	buf := unsafe.Slice((*int32)(unsafe.Pointer(out)), int(m))
	b := []byte(sample)
	count := clampTo(int32(len(b)), m)
	for i := int32(0); i < count; i++ {
		buf[i] = int32(b[i])
	}
	return C.int(count)
}

// go_string_concat: `+` on strings is a runtime concat call (an allocation), and
// comparison is a length check plus memequal.
//
//export go_string_concat
func go_string_concat(k C.int) C.int {
	cut := clampTo(int32(uint32(k)%uint32(len(sample)+1)), int32(len(sample)))
	head := sample[:cut]
	tail := sample[cut:]
	joined := head + tail
	var acc int32
	if joined == sample {
		acc += 1000
	}
	if len(joined) == len(sample) {
		acc += 100
	}
	return C.int(acc + int32(len(head))*10 + int32(len(tail)))
}

func main() {}
