// 180_go_overflow_bits.go
//
// Go integer semantics and bit operations. Go's arithmetic rules differ from C's
// in ways that change what a CORRECT decompilation is, not merely how it looks:
//
//   * signed overflow WRAPS (two's complement) and is fully defined -- it is not
//     undefined behaviour, so a decompiler may not assume it cannot happen and
//     may not optimise on that assumption.
//   * a SHIFT COUNT >= the operand width is defined: the result is 0 for a left
//     shift or a logical right shift, and 0 or -1 (sign fill) for an arithmetic
//     right shift. In C that is undefined, and x86 masks the count to 5 or 6
//     bits, so the compiler must emit an explicit guard (a compare plus a cmov,
//     or a saturating count) that has NO counterpart in the source text.
//   * division truncates toward zero and `MinInt / -1` is defined to wrap back
//     to MinInt rather than trapping, so the compiler emits an explicit
//     overflow-avoiding branch around `idiv`.
//   * `%` takes the sign of the DIVIDEND, as in C.
//
// The interesting recovery signals:
//   * `go_shift_over` shifts by counts up to 127. The emitted code is a
//     compare-and-select around a masked shift; recovering "shift, defined for
//     all counts" from "cmp $63; cmov" is the whole exercise, and a recovery
//     that drops the guard is wrong exactly on the inputs the fuzzer will pick.
//   * `go_div_trunc` shows the MinInt/-1 branch, which looks like dead code and
//     is not.
//   * math/bits functions are INTRINSIFIED at -O (single `popcnt`, `lzcnt`,
//     `tzcnt`, `bswap`, `rol` instructions) and expand into full software loops
//     at `-N -l`. The same source produces a one-instruction body in one lane
//     and a loop in the other -- an unusually sharp lane contrast.
//   * `bits.Mul32` and `bits.Add32` return TWO results (hi/lo, sum/carry), which
//     the register ABI returns in two registers; there is no out-parameter and
//     no struct in memory to key on.
//   * width conversions truncate and sign-extend at every step, so the fixed
//     ladder in `go_wrap_widths` pins the width lattice.
//
// Exposure: every driver is `//export`ed over plain `C.int` scalars, built
// `-buildmode=c-shared`. Shift counts are taken through `uint` after masking, so
// a negative count -- which WOULD panic in Go -- is unrepresentable here.
// Divisors are forced nonzero (division by zero is the only trapping arithmetic
// in Go), and no slice, string, map or pointer is touched at all, so this
// fixture has no panic paths whatsoever.
//
// Deterministic: pure integer arithmetic, no allocation, no goroutines, no time,
// no randomness.

package main

import "C"
import "math/bits"

// go_wrap_widths: signed overflow wraps at every width, and each conversion
// truncates then sign-extends. The ladder pins the whole width lattice.
//
//export go_wrap_widths
func go_wrap_widths(x C.int) C.int {
	v := int32(x)
	// int8: wraps at 8 bits, then sign-extends back.
	a := int8(v)
	a = a*3 + 97
	// int16: same shape, 16 bits.
	b := int16(v)
	b = b*1103 + 12345
	// int32: the widest that still wraps inside the return width. The multiplier
	// is written unsigned because 2654435761 does not fit in an int32 constant;
	// the multiply itself is the same instruction either way.
	c := int32(uint32(v)*2654435761) + 1
	// int64: computed wide, then truncated back down to 32 bits.
	d := int64(v) * 6364136223846793005
	d += 1442695040888963407
	// unsigned wrap, which differs from the signed one only in the compare
	// operators the compiler chooses.
	u := uint32(v)
	u = u*2246822519 + 374761393
	return C.int(int32(a) + int32(b)*7 + c ^ int32(d>>32) ^ int32(u))
}

// go_shift_over: shift counts up to 127 -- far past every operand width. Go
// defines all of them; x86 does not, so the emitted code carries an explicit
// guard that the source never wrote.
//
//export go_shift_over
func go_shift_over(x C.int, k C.int) C.int {
	v := int32(x)
	// The count is masked into [0, 127] through uint, so it can never be
	// negative (a negative shift count panics in Go).
	sh := uint(uint32(k) & 0x7F)
	// Left shift past the width is defined as 0.
	l32 := v << sh
	// Logical right shift past the width is defined as 0.
	r32 := int32(uint32(v) >> sh)
	// Arithmetic right shift past the width is defined as the sign fill.
	a32 := v >> sh
	// Narrower operands hit the guard at a lower count.
	l8 := int8(v) << sh
	a8 := int8(v) >> sh
	// A 64-bit shift, then truncated.
	w64 := int64(v) << sh
	return C.int(l32 ^ r32*3 ^ a32*5 ^ int32(l8)*7 ^ int32(a8)*11 ^ int32(w64>>32))
}

// go_shift_signed: arithmetic vs logical right shift on the same bits -- the
// only difference is the signedness of the operand's static type.
//
//export go_shift_signed
func go_shift_signed(x C.int, k C.int) C.int {
	v := int32(x)
	sh := uint(uint32(k) & 31)
	arith := v >> sh
	logical := int32(uint32(v) >> sh)
	// Sign extension through a narrow width, then shifted.
	narrow := int32(int8(v)) >> sh
	// Left shift into the sign bit: defined, and wraps.
	up := v << sh
	return C.int(arith ^ logical*3 ^ narrow*5 ^ up*7)
}

// go_bits_count: popcount / leading zeros / trailing zeros / bit length. These
// become single instructions at -O and software loops at -N -l.
//
//export go_bits_count
func go_bits_count(x C.int) C.int {
	u := uint32(x)
	ones := int32(bits.OnesCount32(u))
	lead := int32(bits.LeadingZeros32(u))
	trail := int32(bits.TrailingZeros32(u))
	length := int32(bits.Len32(u))
	// The 8-bit forms hit different intrinsics and different edge cases at 0.
	ones8 := int32(bits.OnesCount8(uint8(u)))
	lead8 := int32(bits.LeadingZeros8(uint8(u)))
	return C.int(ones + lead*100 + trail*10000 + length*3 + ones8*5 + lead8*7)
}

// go_bits_rotate: rotations and byte/bit reversals. RotateLeft32 with a negative
// count is a rotate RIGHT and is well defined, so no guard is needed here.
//
//export go_bits_rotate
func go_bits_rotate(x C.int, k C.int) C.int {
	u := uint32(x)
	r := int32(k) & 31
	rotl := bits.RotateLeft32(u, int(r))
	rotr := bits.RotateLeft32(u, -int(r))
	swapped := bits.ReverseBytes32(u)
	reversed := bits.Reverse32(u)
	return C.int(int32(rotl) ^ int32(rotr)*3 ^ int32(swapped)*5 ^ int32(reversed))
}

// go_div_trunc: truncation toward zero, remainder taking the dividend's sign,
// and the defined MinInt/-1 wrap that forces an explicit branch around idiv.
//
//export go_div_trunc
func go_div_trunc(a C.int, b C.int) C.int {
	x := int32(a)
	// Force a nonzero divisor: division by zero is the only trapping arithmetic
	// operation in Go, and it must be unreachable from the C boundary.
	y := int32(b)
	if y == 0 {
		y = 1
	}
	q := x / y
	r := x % y
	// The defined MinInt/-1 case, reached whenever the fuzzer supplies it.
	var edge int32
	if y == -1 {
		edge = x / y
	} else {
		edge = x / -1
	}
	// Unsigned division has no such edge case and no branch.
	uq := int32(uint32(x) / uint32(y))
	return C.int(q ^ r*3 ^ edge*5 ^ uq*7)
}

// go_mul_wide: full-width multiply and add-with-carry return TWO values in two
// registers, with no out-parameter and no struct in memory.
//
//export go_mul_wide
func go_mul_wide(a C.int, b C.int) C.int {
	x := uint32(a)
	y := uint32(b)
	hi, lo := bits.Mul32(x, y)
	sum, carry := bits.Add32(x, y, 0)
	diff, borrow := bits.Sub32(x, y, 0)
	// Div32 traps when the high word is >= the divisor, so both are pinned into
	// a domain where it cannot: a zero high word and a nonzero divisor.
	d := y
	if d == 0 {
		d = 1
	}
	quo, rem := bits.Div32(0, x, d)
	return C.int(int32(hi) ^ int32(lo)*3 ^ int32(sum)*5 ^ int32(carry)*7 ^
		int32(diff)*11 ^ int32(borrow)*13 ^ int32(quo)*17 ^ int32(rem)*19)
}

// go_conv_sign: signed/unsigned round trips at three widths. Every step is a
// truncation or an extension, and which one depends only on the static type.
//
//export go_conv_sign
func go_conv_sign(x C.int) C.int {
	v := int32(x)
	// Signed -> narrow -> widened back: sign extension.
	s8 := int32(int8(v))
	s16 := int32(int16(v))
	// Signed -> narrow UNSIGNED -> widened: zero extension of the same bits.
	u8 := int32(uint8(v))
	u16 := int32(uint16(v))
	// A 64-bit round trip through unsigned, which is not a no-op for negatives.
	wide := int32(uint64(uint32(v)) >> 3)
	return C.int(s8 ^ s16*3 ^ u8*5 ^ u16*7 ^ wide*11)
}

func main() {}
