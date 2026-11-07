//! The x86-64 backends: the scalar compression, and the AVX2 and AVX-512 batches.

pub(super) use gpr::compress;

#[cfg(target_feature = "avx2")]
use super::batch::Lanes32;
// Only the AVX-512 digest store needs it.
#[cfg(target_feature = "avx512f")]
use super::OUT_LEN;
#[cfg(target_feature = "avx2")]
use core::arch::x86_64::*;

/// AVX2: eight lanes.
///
/// There is no 32-bit vector rotate before AVX-512.
///
/// The byte-aligned rotations (16, 8) become one `vpshufb`, the others (12, 7) a shift pair.
///
/// On an AVX-512 target only the tests use it.
#[cfg(target_feature = "avx2")]
#[cfg_attr(target_feature = "avx512f", allow(dead_code))]
#[derive(Clone, Copy)]
pub(super) struct Avx2(__m256i);

#[cfg(target_feature = "avx2")]
impl Lanes32 for Avx2 {
    const WIDTH: usize = 8;
    // One group waits on its G chains, and a third would spill the 16 registers.
    const GROUPS: usize = 2;

    #[inline(always)]
    unsafe fn load(p: *const u32) -> Self {
        // SAFETY: the impl exists only when the crate is built with AVX2, and the caller guarantees 8 readable words at
        // `p`; the load is unaligned.
        Self(unsafe { _mm256_loadu_si256(p.cast()) })
    }
    #[inline(always)]
    unsafe fn store(self, p: *mut u32) {
        // SAFETY: the impl exists only when the crate is built with AVX2, and the caller guarantees 8 writable words at
        // `p`; the store is unaligned.
        unsafe { _mm256_storeu_si256(p.cast(), self.0) }
    }
    #[inline(always)]
    fn splat(x: u32) -> Self {
        // SAFETY: the impl exists only when the crate is built with AVX2; registers only.
        Self(unsafe { _mm256_set1_epi32(x as i32) })
    }
    #[inline(always)]
    fn add(self, o: Self) -> Self {
        // SAFETY: the impl exists only when the crate is built with AVX2; registers only.
        Self(unsafe { _mm256_add_epi32(self.0, o.0) })
    }
    #[inline(always)]
    fn xor(self, o: Self) -> Self {
        // SAFETY: the impl exists only when the crate is built with AVX2; registers only.
        Self(unsafe { _mm256_xor_si256(self.0, o.0) })
    }
    #[inline(always)]
    fn rotr<const N: u32>(self) -> Self {
        // Byte shuffles rotating each 32-bit lane right by 2 and by 1 bytes, per 16-byte half.
        const ROT16: [i8; 16] = [2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13];
        const ROT8: [i8; 16] = [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12];
        // SAFETY: the impl exists only when the crate is built with AVX2; the one load reads a 16-byte local array.
        unsafe {
            let shuf = |m: [i8; 16]| {
                let half = _mm_loadu_si128(m.as_ptr().cast());
                Self(_mm256_shuffle_epi8(self.0, _mm256_set_m128i(half, half)))
            };
            match N {
                16 => shuf(ROT16),
                8 => shuf(ROT8),
                12 => Self(_mm256_or_si256(
                    _mm256_srli_epi32(self.0, 12),
                    _mm256_slli_epi32(self.0, 20),
                )),
                7 => Self(_mm256_or_si256(
                    _mm256_srli_epi32(self.0, 7),
                    _mm256_slli_epi32(self.0, 25),
                )),
                _ => unreachable!("BLAKE2s rotates by 16, 12, 8 or 7"),
            }
        }
    }

    /// Two 8x8 transposes: each block is two `ymm`, words 0..8 and 8..16.
    #[inline(always)]
    unsafe fn transpose(src: *const u8, stride: usize, block: &mut [Self; 16]) {
        // SAFETY: the impl exists only when the crate is built with AVX2; the loads read 32-byte half `half < 2` of
        // each of the 8 inputs, inside the 64 readable bytes the caller guarantees per input.
        unsafe {
            for half in 0..2 {
                let r: [__m256i; 8] =
                    std::array::from_fn(|l| _mm256_loadu_si256(src.add(l * stride + 32 * half).cast()));
                let mut t = [_mm256_setzero_si256(); 8];
                for k in 0..4 {
                    t[2 * k] = _mm256_unpacklo_epi32(r[2 * k], r[2 * k + 1]);
                    t[2 * k + 1] = _mm256_unpackhi_epi32(r[2 * k], r[2 * k + 1]);
                }
                let s: [__m256i; 8] = [
                    _mm256_unpacklo_epi64(t[0], t[2]),
                    _mm256_unpackhi_epi64(t[0], t[2]),
                    _mm256_unpacklo_epi64(t[1], t[3]),
                    _mm256_unpackhi_epi64(t[1], t[3]),
                    _mm256_unpacklo_epi64(t[4], t[6]),
                    _mm256_unpackhi_epi64(t[4], t[6]),
                    _mm256_unpacklo_epi64(t[5], t[7]),
                    _mm256_unpackhi_epi64(t[5], t[7]),
                ];
                for k in 0..4 {
                    let w = 8 * half + k;
                    block[w] = Self(_mm256_permute2x128_si256(s[k], s[k + 4], 0x20));
                    block[w + 4] = Self(_mm256_permute2x128_si256(s[k], s[k + 4], 0x31));
                }
            }
        }
    }
}

/// AVX-512: sixteen lanes, and `vprord` makes every rotation one instruction.
///
/// Two groups run together, so neither waits on its own dependency chain.
#[cfg(target_feature = "avx512f")]
#[derive(Clone, Copy)]
pub(super) struct Avx512(__m512i);

#[cfg(target_feature = "avx512f")]
impl Lanes32 for Avx512 {
    const WIDTH: usize = 16;

    #[inline(always)]
    unsafe fn load(p: *const u32) -> Self {
        // SAFETY: the impl exists only when the crate is built with AVX-512F, and the caller guarantees 16 readable
        // words at `p`; the load is unaligned.
        Self(unsafe { _mm512_loadu_si512(p.cast()) })
    }
    #[inline(always)]
    unsafe fn store(self, p: *mut u32) {
        // SAFETY: the impl exists only when the crate is built with AVX-512F, and the caller guarantees 16 writable
        // words at `p`; the store is unaligned.
        unsafe { _mm512_storeu_si512(p.cast(), self.0) }
    }
    #[inline(always)]
    fn splat(x: u32) -> Self {
        // SAFETY: the impl exists only when the crate is built with AVX-512F; registers only.
        Self(unsafe { _mm512_set1_epi32(x as i32) })
    }
    #[inline(always)]
    fn add(self, o: Self) -> Self {
        // SAFETY: the impl exists only when the crate is built with AVX-512F; registers only.
        Self(unsafe { _mm512_add_epi32(self.0, o.0) })
    }
    #[inline(always)]
    fn xor(self, o: Self) -> Self {
        // SAFETY: the impl exists only when the crate is built with AVX-512F; registers only.
        Self(unsafe { _mm512_xor_si512(self.0, o.0) })
    }
    #[inline(always)]
    fn rotr<const N: u32>(self) -> Self {
        // SAFETY: the impl exists only when the crate is built with AVX-512F; registers only.
        unsafe {
            match N {
                16 => Self(_mm512_ror_epi32(self.0, 16)),
                12 => Self(_mm512_ror_epi32(self.0, 12)),
                8 => Self(_mm512_ror_epi32(self.0, 8)),
                7 => Self(_mm512_ror_epi32(self.0, 7)),
                _ => unreachable!("BLAKE2s rotates by 16, 12, 8 or 7"),
            }
        }
    }

    /// Two groups: 32 state vectors, the whole register file.
    const GROUPS: usize = 2;

    #[inline(always)]
    unsafe fn compress_groups<const G: usize>(h: &mut [[Self; 8]; G], m: [&[Self; 16]; G], t: u64, last: bool) {
        // A lone tail group takes the generic rounds.
        if G != 2 {
            // SAFETY: forwarded from the caller.
            return unsafe { super::batch::compress_groups::<Self, G>(h, m, t, last) };
        }
        // SAFETY: the kernel's layouts, two groups of 8 vectors and two blocks of 16.
        unsafe {
            zmm::compress_x2(
                h.as_mut_ptr().cast(),
                m[0].as_ptr().cast(),
                m[1].as_ptr().cast(),
                t,
                last,
            );
        }
    }

    /// An 8x16 to 16x8 transpose for the digests.
    ///
    /// Two unpack phases leave each digest in two 128-bit lanes:
    ///
    /// ```text
    ///     digest 4L + c    lane L of s[c], then lane L of s[4 + c]
    /// ```
    #[inline(always)]
    unsafe fn store_digests(h: &[Self; 8], out: *mut u8) {
        // SAFETY: the impl exists only when the crate is built with AVX-512F; each store writes 16 bytes at `(4L + c) *
        // 32` or 16 past it, `4L + c < 16`, so all of them fall in the `16 * 32` writable bytes the caller guarantees.
        unsafe {
            let mut s = [_mm512_setzero_si512(); 8];
            for a in 0..2 {
                let (r0, r1, r2, r3) = (h[4 * a].0, h[4 * a + 1].0, h[4 * a + 2].0, h[4 * a + 3].0);
                let lo01 = _mm512_unpacklo_epi32(r0, r1);
                let hi01 = _mm512_unpackhi_epi32(r0, r1);
                let lo23 = _mm512_unpacklo_epi32(r2, r3);
                let hi23 = _mm512_unpackhi_epi32(r2, r3);
                s[4 * a] = _mm512_unpacklo_epi64(lo01, lo23);
                s[4 * a + 1] = _mm512_unpackhi_epi64(lo01, lo23);
                s[4 * a + 2] = _mm512_unpacklo_epi64(hi01, hi23);
                s[4 * a + 3] = _mm512_unpackhi_epi64(hi01, hi23);
            }
            macro_rules! lane {
                ($l:expr, $c:expr) => {{
                    let p = out.add((4 * $l + $c) * OUT_LEN);
                    _mm_storeu_si128(p.cast(), _mm512_extracti32x4_epi32::<$l>(s[$c]));
                    _mm_storeu_si128(p.add(16).cast(), _mm512_extracti32x4_epi32::<$l>(s[4 + $c]));
                }};
            }
            lane!(0, 0);
            lane!(0, 1);
            lane!(0, 2);
            lane!(0, 3);
            lane!(1, 0);
            lane!(1, 1);
            lane!(1, 2);
            lane!(1, 3);
            lane!(2, 0);
            lane!(2, 1);
            lane!(2, 2);
            lane!(2, 3);
            lane!(3, 0);
            lane!(3, 1);
            lane!(3, 2);
            lane!(3, 3);
        }
    }

    /// A 16x16 transpose: each block is exactly one `zmm`.
    ///
    /// ```text
    ///     2 unpack phases           four rows of one column per 128-bit lane
    ///     2 shuffle_i32x4 phases    collect the four row groups
    /// ```
    #[inline(always)]
    unsafe fn transpose(src: *const u8, stride: usize, block: &mut [Self; 16]) {
        // SAFETY: the impl exists only when the crate is built with AVX-512F; each load reads the 64 bytes of one of
        // the 16 inputs, which the caller guarantees readable.
        unsafe {
            let r: [__m512i; 16] = std::array::from_fn(|l| _mm512_loadu_si512(src.add(l * stride).cast()));
            // Phases 1 and 2: lane L of s[4a + c] holds column 4L + c of rows 4a..4a + 4.
            let mut s = [_mm512_setzero_si512(); 16];
            for a in 0..4 {
                let (r0, r1, r2, r3) = (r[4 * a], r[4 * a + 1], r[4 * a + 2], r[4 * a + 3]);
                let lo01 = _mm512_unpacklo_epi32(r0, r1);
                let hi01 = _mm512_unpackhi_epi32(r0, r1);
                let lo23 = _mm512_unpacklo_epi32(r2, r3);
                let hi23 = _mm512_unpackhi_epi32(r2, r3);
                s[4 * a] = _mm512_unpacklo_epi64(lo01, lo23);
                s[4 * a + 1] = _mm512_unpackhi_epi64(lo01, lo23);
                s[4 * a + 2] = _mm512_unpacklo_epi64(hi01, hi23);
                s[4 * a + 3] = _mm512_unpackhi_epi64(hi01, hi23);
            }
            // Phases 3 and 4: word w is lane w / 4 of the four s entries with c = w % 4.
            //
            // The first shuffles broadcast that lane, then 0x88 keeps lanes 0 and 2 of each half.
            macro_rules! word {
                ($w:expr) => {{
                    const L: i32 = ($w / 4) as i32;
                    const C: usize = ($w % 4) as usize;
                    const IMM_L: i32 = L * 0x55;
                    let p = _mm512_shuffle_i32x4::<IMM_L>(s[C], s[4 + C]);
                    let q = _mm512_shuffle_i32x4::<IMM_L>(s[8 + C], s[12 + C]);
                    block[$w] = Self(_mm512_shuffle_i32x4::<0x88>(p, q));
                }};
            }
            word!(0);
            word!(1);
            word!(2);
            word!(3);
            word!(4);
            word!(5);
            word!(6);
            word!(7);
            word!(8);
            word!(9);
            word!(10);
            word!(11);
            word!(12);
            word!(13);
            word!(14);
            word!(15);
        }
    }
}

mod gpr {
    //! One compression with its state in general-purpose registers.
    //!
    //! The compiler spills a 16-word state over 15 free registers, and reloads the message pointer.
    //!
    //! Here the message is copied to the stack and read at `rsp` offsets, which frees its pointer.
    //!
    //! Fifteen words then live in registers, and `v[11]` on the stack:
    //!
    //! ```text
    //!     v[0..4]     eax  ecx  edx  esi
    //!     v[4..8]     edi  r8d  r9d  r10d
    //!     v[8..12]    r11d r12d r13d [rsp + 64]
    //!     v[12..16]   r14d r15d ebx  ebp
    //! ```
    //!
    //! `v[11]` is always a G's `c`, whose partners are registers, so no instruction takes two memory operands.

    use crate::blake2s::IV;

    /// The stack slot holding `v[11]`.
    macro_rules! v11 {
        () => {
            "dword ptr [rsp + 64]"
        };
    }

    /// Four independent G functions, emitted one step at a time across all of them.
    ///
    /// Each G is `(a, b, c, d, x, y)`: four state registers and two message word indices.
    macro_rules! g {
        ($(($a:expr, $b:expr, $c:expr, $d:expr, $x:literal, $y:literal))*) => {
            concat!(
                $("add ", $a, ", dword ptr [rsp + 4*", $x, "]\n",)*
                $("add ", $a, ", ", $b, "\n",)*
                $("xor ", $d, ", ", $a, "\n",)*
                $("ror ", $d, ", 16\n",)*
                $("add ", $c, ", ", $d, "\n",)*
                $("xor ", $b, ", ", $c, "\n",)*
                $("ror ", $b, ", 12\n",)*
                $("add ", $a, ", dword ptr [rsp + 4*", $y, "]\n",)*
                $("add ", $a, ", ", $b, "\n",)*
                $("xor ", $d, ", ", $a, "\n",)*
                $("ror ", $d, ", 8\n",)*
                $("add ", $c, ", ", $d, "\n",)*
                $("xor ", $b, ", ", $c, "\n",)*
                $("ror ", $b, ", 7\n",)*
            )
        };
    }

    /// One round with the message schedule `s`: columns, then diagonals.
    #[rustfmt::skip]
    macro_rules! round {
        ([$s0:literal, $s1:literal, $s2:literal, $s3:literal, $s4:literal, $s5:literal, $s6:literal, $s7:literal,
          $s8:literal, $s9:literal, $s10:literal, $s11:literal, $s12:literal, $s13:literal, $s14:literal, $s15:literal]) => {
            concat!(
                g!(
                    ("eax", "edi", "r11d", "r14d", $s0, $s1)
                    ("ecx", "r8d", "r12d", "r15d", $s2, $s3)
                    ("edx", "r9d", "r13d", "ebx", $s4, $s5)
                    ("esi", "r10d", v11!(), "ebp", $s6, $s7)
                ),
                g!(
                    ("eax", "r8d", "r13d", "ebp", $s8, $s9)
                    ("ecx", "r9d", v11!(), "r14d", $s10, $s11)
                    ("edx", "r10d", "r11d", "r15d", $s12, $s13)
                    ("esi", "edi", "r12d", "ebx", $s14, $s15)
                ),
            )
        };
    }

    /// The BLAKE2s compression: absorb block `m` at byte counter `t` into `h`.
    ///
    /// Equal to the portable compression, which the tests pin it to.
    #[inline]
    pub(in crate::blake2s) fn compress(h: &mut [u32; 8], m: &[u32; 16], t: u64, last: bool) {
        // SAFETY: `h` and `m` are valid for their 32 and 64 bytes.
        // The kernel saves and restores `rbx` and `rbp`, and frees the 88 bytes of stack it takes.
        unsafe {
            core::arch::asm!(
                "push rbx",
                "push rbp",
                "sub rsp, 88",
                // The message to `rsp + 0 .. 64`, and `h`'s address to `rsp + 72`.
                //
                // General-purpose moves: no vector register, so no SSE and AVX transition.
                "mov rax, [rsi]",
                "mov rcx, [rsi + 8]",
                "mov rdx, [rsi + 16]",
                "mov r8, [rsi + 24]",
                "mov [rsp], rax",
                "mov [rsp + 8], rcx",
                "mov [rsp + 16], rdx",
                "mov [rsp + 24], r8",
                "mov rax, [rsi + 32]",
                "mov rcx, [rsi + 40]",
                "mov rdx, [rsi + 48]",
                "mov r8, [rsi + 56]",
                "mov [rsp + 32], rax",
                "mov [rsp + 40], rcx",
                "mov [rsp + 48], rdx",
                "mov [rsp + 56], r8",
                "mov [rsp + 72], rdi",
                // v[0..8] = h, and v[8..16] = the IV with the counter and flag folded in.
                "mov ebx, r13d",
                "mov eax, [rdi]",
                "mov ecx, [rdi + 4]",
                "mov edx, [rdi + 8]",
                "mov esi, [rdi + 12]",
                "mov r8d, [rdi + 20]",
                "mov r9d, [rdi + 24]",
                "mov r10d, [rdi + 28]",
                "mov edi, [rdi + 16]",
                "mov r11d, {iv0}",
                "mov r12d, {iv1}",
                "mov r13d, {iv2}",
                concat!("mov ", v11!(), ", {iv3}"),
                "mov ebp, {iv7}",
                // The ten rounds (RFC 7693 message schedule).
                round!([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
                round!([14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]),
                round!([11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4]),
                round!([7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8]),
                round!([9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13]),
                round!([2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9]),
                round!([12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11]),
                round!([13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10]),
                round!([6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5]),
                round!([10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]),
                // h[i] ^= v[i] ^ v[i + 8], through `h`'s address back in `rdi`.
                "xor edi, r14d",
                "mov [rsp + 80], edi",
                "mov rdi, [rsp + 72]",
                "xor eax, r11d",
                "xor [rdi], eax",
                "xor ecx, r12d",
                "xor [rdi + 4], ecx",
                "xor edx, r13d",
                "xor [rdi + 8], edx",
                concat!("xor esi, ", v11!()),
                "xor [rdi + 12], esi",
                "mov eax, [rsp + 80]",
                "xor [rdi + 16], eax",
                "xor r8d, r15d",
                "xor [rdi + 20], r8d",
                "xor r9d, ebx",
                "xor [rdi + 24], r9d",
                "xor r10d, ebp",
                "xor [rdi + 28], r10d",
                "add rsp, 88",
                "pop rbp",
                "pop rbx",
                iv0 = const IV[0],
                iv1 = const IV[1],
                iv2 = const IV[2],
                iv3 = const IV[3],
                iv7 = const IV[7],
                inout("rdi") h.as_mut_ptr() => _,
                inout("rsi") m.as_ptr() => _,
                inout("r13") if last { !IV[6] } else { IV[6] } => _,
                inout("r14") IV[4] ^ t as u32 => _,
                inout("r15") IV[5] ^ (t >> 32) as u32 => _,
                out("rax") _, out("rcx") _, out("rdx") _,
                out("r8") _, out("r9") _, out("r10") _, out("r11") _, out("r12") _,
            );
        }
    }
}

#[cfg(target_feature = "avx512f")]
mod zmm {
    //! Two 16-lane compressions in one hand-scheduled AVX-512 kernel.
    //!
    //! On Zen 5, a 512-bit add, xor or rotate has a 2-cycle latency.
    //!
    //! One 16-lane group then waits on its own G chains, and most vector pipes idle.
    //!
    //! Two groups in lockstep double the independent work, and fill the whole register file:
    //!
    //! ```text
    //!     zmm0  .. zmm15    group A's state
    //!     zmm16 .. zmm31    group B's state
    //! ```
    //!
    //! Nothing else fits, so every update is in place and message words stay in memory.
    //!
    //! The compiler spills at this pressure, hence assembly.

    use crate::blake2s::IV;

    /// `op zmmD, zmmD, zmmS`.
    macro_rules! rr {
        ($op:literal, $d:literal, $s:literal) => {
            concat!($op, " zmm", $d, ", zmm", $d, ", zmm", $s, "\n")
        };
    }

    /// `zmmD += m[w]`, with the message word as a memory operand.
    macro_rules! addm {
        ($d:literal, $m:literal, $w:literal) => {
            concat!("vpaddd zmm", $d, ", zmm", $d, ", zmmword ptr [", $m, " + 64*", $w, "]\n")
        };
    }

    /// `zmmD >>>= n`.
    macro_rules! ror {
        ($d:literal, $n:literal) => {
            concat!("vprord zmm", $d, ", zmm", $d, ", ", $n, "\n")
        };
    }

    /// Independent G functions, emitted one step at a time across all of them.
    ///
    /// Each step is then a run of independent instructions.
    ///
    /// The second message add is hoisted early, off the dependency chain.
    macro_rules! g {
        ($(($a:literal, $b:literal, $c:literal, $d:literal, $m:literal, $x:literal, $y:literal))*) => {
            concat!(
                $(addm!($a, $m, $x),)*
                $(rr!("vpaddd", $a, $b),)*
                $(rr!("vpxord", $d, $a),)*
                $(addm!($a, $m, $y),)*
                $(ror!($d, 16),)*
                $(rr!("vpaddd", $c, $d),)*
                $(rr!("vpxord", $b, $c),)*
                $(ror!($b, 12),)*
                $(rr!("vpaddd", $a, $b),)*
                $(rr!("vpxord", $d, $a),)*
                $(ror!($d, 8),)*
                $(rr!("vpaddd", $c, $d),)*
                $(rr!("vpxord", $b, $c),)*
                $(ror!($b, 7),)*
            )
        };
    }

    /// One round of both groups: columns, then diagonals.
    #[rustfmt::skip]
    macro_rules! round {
        ([$s0:literal, $s1:literal, $s2:literal, $s3:literal, $s4:literal, $s5:literal, $s6:literal, $s7:literal,
          $s8:literal, $s9:literal, $s10:literal, $s11:literal, $s12:literal, $s13:literal, $s14:literal, $s15:literal]) => {
            concat!(
                g!(
                    (0, 4, 8, 12, "{ma}", $s0, $s1)       (1, 5, 9, 13, "{ma}", $s2, $s3)
                    (2, 6, 10, 14, "{ma}", $s4, $s5)      (3, 7, 11, 15, "{ma}", $s6, $s7)
                    (16, 20, 24, 28, "{mb}", $s0, $s1)    (17, 21, 25, 29, "{mb}", $s2, $s3)
                    (18, 22, 26, 30, "{mb}", $s4, $s5)    (19, 23, 27, 31, "{mb}", $s6, $s7)
                ),
                g!(
                    (0, 5, 10, 15, "{ma}", $s8, $s9)      (1, 6, 11, 12, "{ma}", $s10, $s11)
                    (2, 7, 8, 13, "{ma}", $s12, $s13)     (3, 4, 9, 14, "{ma}", $s14, $s15)
                    (16, 21, 26, 31, "{mb}", $s8, $s9)    (17, 22, 27, 28, "{mb}", $s10, $s11)
                    (18, 23, 24, 29, "{mb}", $s12, $s13)  (19, 20, 25, 30, "{mb}", $s14, $s15)
                ),
            )
        };
    }

    /// Load `v[i] = h[i]` and broadcast `v[8 + i]` from `src`, for both groups.
    macro_rules! init {
        ($($i:literal $j:literal $vi:literal $vj:literal $src:literal),*) => {
            concat!($(
                "vmovdqu64 zmm", $i, ", zmmword ptr [{h} + 64*", $i, "]\n",
                "vmovdqu64 zmm", $j, ", zmmword ptr [{h} + 512 + 64*", $i, "]\n",
                "vpbroadcastd zmm", $vi, ", ", $src, "\n",
                "vmovdqa64 zmm", $vj, ", zmm", $vi, "\n",
            )*)
        };
    }

    /// `h[i] ^= v[i] ^ v[i + 8]` for both groups.
    ///
    /// One `vpternlogd` each: `0x96` is the three-way xor.
    macro_rules! feed_forward {
        ($($i:literal $j:literal $vi:literal $vj:literal),*) => {
            concat!($(
                "vpternlogd zmm", $i, ", zmm", $vi, ", zmmword ptr [{h} + 64*", $i, "], 0x96\n",
                "vmovdqu64 zmmword ptr [{h} + 64*", $i, "], zmm", $i, "\n",
                "vpternlogd zmm", $j, ", zmm", $vj, ", zmmword ptr [{h} + 512 + 64*", $i, "], 0x96\n",
                "vmovdqu64 zmmword ptr [{h} + 512 + 64*", $i, "], zmm", $j, "\n",
            )*)
        };
    }

    /// Compress two transposed 16-lane blocks at byte counter `t`.
    ///
    /// Both chaining values are updated in place:
    ///
    /// ```text
    ///     byte 64 * i          group A's word i
    ///     byte 512 + 64 * i    group B's word i
    /// ```
    ///
    /// The counter and final flag arrive in registers, so no per-block row round-trips through memory.
    ///
    /// # Safety
    ///
    /// - `h` must be valid for reads and writes of `2 * 8 * 16` `u32`.
    /// - `ma` and `mb` must each be valid for reads of `16 * 16` `u32`.
    #[inline(always)]
    pub(super) unsafe fn compress_x2(h: *mut u32, ma: *const u32, mb: *const u32, t: u64, last: bool) {
        let iv: &'static [u32; 8] = &IV;
        // SAFETY: the caller guarantees the three buffers.
        // The kernel touches no stack and no memory other than theirs and `IV`.
        unsafe {
            core::arch::asm!(
                // v[0..8] = h, and v[8..16] = the IV row with the counter and flag folded in.
                init!(
                    0 16 8 24 "dword ptr [{iv}]",
                    1 17 9 25 "dword ptr [{iv} + 4]",
                    2 18 10 26 "dword ptr [{iv} + 8]",
                    3 19 11 27 "dword ptr [{iv} + 12]",
                    4 20 12 28 "{t0:e}",
                    5 21 13 29 "{t1:e}",
                    6 22 14 30 "{f:e}",
                    7 23 15 31 "dword ptr [{iv} + 28]"
                ),
                // The ten rounds (RFC 7693 message schedule), both groups in lockstep.
                round!([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
                round!([14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]),
                round!([11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4]),
                round!([7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8]),
                round!([9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13]),
                round!([2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9]),
                round!([12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11]),
                round!([13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10]),
                round!([6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5]),
                round!([10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]),
                // h[i] ^= v[i] ^ v[i + 8], written back in place.
                feed_forward!(
                    0 16 8 24, 1 17 9 25, 2 18 10 26, 3 19 11 27, 4 20 12 28, 5 21 13 29, 6 22 14 30, 7 23 15 31
                ),
                h = in(reg) h,
                ma = in(reg) ma,
                mb = in(reg) mb,
                iv = in(reg) iv.as_ptr(),
                t0 = in(reg) iv[4] ^ t as u32,
                t1 = in(reg) iv[5] ^ (t >> 32) as u32,
                f = in(reg) if last { !iv[6] } else { iv[6] },
                out("zmm0") _, out("zmm1") _, out("zmm2") _, out("zmm3") _,
                out("zmm4") _, out("zmm5") _, out("zmm6") _, out("zmm7") _,
                out("zmm8") _, out("zmm9") _, out("zmm10") _, out("zmm11") _,
                out("zmm12") _, out("zmm13") _, out("zmm14") _, out("zmm15") _,
                out("zmm16") _, out("zmm17") _, out("zmm18") _, out("zmm19") _,
                out("zmm20") _, out("zmm21") _, out("zmm22") _, out("zmm23") _,
                out("zmm24") _, out("zmm25") _, out("zmm26") _, out("zmm27") _,
                out("zmm28") _, out("zmm29") _, out("zmm30") _, out("zmm31") _,
                options(nostack),
            );
        }
    }
}
