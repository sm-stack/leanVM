//! The transform's SIMD kernels: the butterflies of a row pair, and the column dot products of a row evaluation.
//!
//! Every kernel has a portable arm, which the SIMD arms are tested against.

#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
use core::arch::aarch64::*;
#[cfg(all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx2"))]
use core::arch::x86_64::*;
use primitives::field::F64;
#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
use primitives::field::gf2_64::aarch64::{reduce_pair_pmull2, reduce_pair_pmull4};
use primitives::field::gf2_64::mul_wide;
#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
use primitives::field::neon::xor3_u64;

/// Layers L, L+1 and L+2 fused into one sweep over a layer-L block.
///
/// ```text
///     a group is 8 rows, e = (block rows) / 8 apart:  r, r + e, ..., r + 7e
///
///     layer L     pairs rows 4e apart
///     layer L+1   pairs rows 2e apart
///     layer L+2   pairs rows  e apart
/// ```
///
/// - The eight rows stay in L1 across all twelve butterflies.
/// - The seven twiddles are breadth-first: one for layer L, two for L+1, four for L+2.
pub(super) fn butterfly_interleaved_fused_3layer(block: &mut [F64], t: &[F64; 7], eighth: usize, num_ntts: usize) {
    fused_rows::<8>(block, eighth, num_ntts, |rows| radix8_butterflies(rows, t));
}

/// Layers L and L+1 fused into one sweep over a layer-L block, four rows at a time.
pub(super) fn butterfly_interleaved_fused_2layer(
    block: &mut [F64],
    t_outer: F64,
    t_inner_a: F64,
    t_inner_b: F64,
    quarter: usize,
    num_ntts: usize,
) {
    fused_rows::<4>(block, quarter, num_ntts, |rows| {
        let [row_a, row_b, row_c, row_d] = rows;
        // Layer L: rows 2 apart, one twiddle for the block.
        butterfly_lanes(row_a, row_c, t_outer);
        butterfly_lanes(row_b, row_d, t_outer);
        // Layer L+1: adjacent rows, one twiddle per half.
        butterfly_lanes(row_a, row_b, t_inner_a);
        butterfly_lanes(row_c, row_d, t_inner_b);
    });
}

/// One layer over a block: each top-half row paired with the row half a block below it, under one twiddle.
#[inline]
pub(super) fn butterfly_interleaved_block(block: &mut [F64], twiddle: F64, block_size_half: usize, num_ntts: usize) {
    let half_offset = block_size_half * num_ntts;
    let (top, bot) = block.split_at_mut(half_offset);
    for r in 0..block_size_half {
        let off = r * num_ntts;
        butterfly_lanes(&mut top[off..off + num_ntts], &mut bot[off..off + num_ntts], twiddle);
    }
}

/// Visit every row group of a fused multi-layer block.
///
/// ```text
///     the block is N slabs of equal height
///
///     slab 0:     row 0   row 1   ...   row r   ...
///     slab 1:     row 0   row 1   ...   row r   ...
///     ...
///     slab N-1:   row 0   row 1   ...   row r   ...
///
///     group r  =  row r of every slab
/// ```
///
/// # Why the rows are disjoint
///
/// - Distinct groups take distinct rows inside each slab.
/// - The slabs do not overlap.
/// - So the groups are pairwise disjoint, and one base pointer can stand in for N nested splits.
fn fused_rows<const N: usize>(
    block: &mut [F64],
    stride_rows: usize,
    num_ntts: usize,
    do_one: impl Fn(&mut [&mut [F64]; N]),
) {
    // Words from one slab to the next.
    let stride = stride_rows * num_ntts;
    debug_assert_eq!(block.len(), N * stride);
    let base = block.as_mut_ptr();
    for r in 0..stride_rows {
        // Row `r` of each slab starts this many words into it.
        let off = r * num_ntts;
        // SAFETY:
        // - The groups are disjoint, as argued above.
        // - The row ends inside its slab, since the row index is below the slab height.
        let mut rows: [&mut [F64]; N] =
            std::array::from_fn(|i| unsafe { std::slice::from_raw_parts_mut(base.add(i * stride + off), num_ntts) });
        do_one(&mut rows);
    }
}

/// The twelve butterflies of one radix-8 row group, with its seven twiddles breadth-first.
#[inline(always)]
fn radix8_butterflies(rows: &mut [&mut [F64]; 8], t: &[F64; 7]) {
    let [r0, r1, r2, r3, r4, r5, r6, r7] = rows;
    // Layer L: rows 4 apart, one twiddle for the whole block.
    butterfly_lanes(r0, r4, t[0]);
    butterfly_lanes(r1, r5, t[0]);
    butterfly_lanes(r2, r6, t[0]);
    butterfly_lanes(r3, r7, t[0]);
    // Layer L+1: rows 2 apart, one twiddle per half.
    butterfly_lanes(r0, r2, t[1]);
    butterfly_lanes(r1, r3, t[1]);
    butterfly_lanes(r4, r6, t[2]);
    butterfly_lanes(r5, r7, t[2]);
    // Layer L+2: adjacent rows, one twiddle per quarter.
    butterfly_lanes(r0, r1, t[3]);
    butterfly_lanes(r2, r3, t[4]);
    butterfly_lanes(r4, r5, t[5]);
    butterfly_lanes(r6, r7, t[6]);
}

/// The forward butterfly on every lane of a row pair, with a shared twiddle: `u' = u + v * t`, then `v' = v + u'`.
#[inline]
fn butterfly_lanes(top: &mut [F64], bot: &mut [F64], twiddle: F64) {
    lane_butterflies::<false>(top, bot, twiddle);
}

/// The transposed butterfly on every lane of a row pair: `s = u + v`, then `u' = s` and `v' = v + s * t`.
///
/// It is the inverse of the forward butterfly with top and bottom exchanged, on both input and output.
#[inline]
pub(super) fn transposed_butterfly_lanes(top: &mut [F64], bot: &mut [F64], twiddle: F64) {
    lane_butterflies::<true>(top, bot, twiddle);
}

/// The butterflies of every lane of a row pair, forward or transposed.
///
/// - A zero twiddle needs no product, so the butterfly is one addition.
/// - A twiddle below `2^61` leaves products whose high word times `0x1B` fits a word, so each reduction folds once.
///   The two deepest layers' twiddles all are.
/// - Otherwise a SIMD kernel takes whole vectors of lanes, and the scalar butterfly the rest.
/// - On NEON a call takes eight lanes as four independent reductions, so their PMULL chains overlap.
/// - There a two-lane kernel takes an even tail, and the scalar butterfly an odd last lane.
#[inline]
fn lane_butterflies<const TRANSPOSED: bool>(top: &mut [F64], bot: &mut [F64], twiddle: F64) {
    debug_assert_eq!(top.len(), bot.len());
    if twiddle == F64::ZERO {
        if TRANSPOSED {
            for (u, v) in top.iter_mut().zip(bot) {
                *u += *v;
            }
        } else {
            for (u, v) in top.iter().zip(bot) {
                *v += *u;
            }
        }
        return;
    }
    if twiddle.0 >> 61 == 0 {
        lane_products::<TRANSPOSED, true>(top, bot, twiddle);
    } else {
        lane_products::<TRANSPOSED, false>(top, bot, twiddle);
    }
}

/// The butterflies of a row pair under a nonzero twiddle, `SMALL` when it is below `2^61`.
#[inline]
fn lane_products<const TRANSPOSED: bool, const SMALL: bool>(top: &mut [F64], bot: &mut [F64], twiddle: F64) {
    #[cfg(all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx512f"))]
    let done = {
        let vectors = top.len() / 8;
        // SAFETY: the features are enabled at compile time, and call `i` touches words `8i..8i + 8` of both rows.
        unsafe {
            for i in 0..vectors {
                butterfly_lanes_avx512::<TRANSPOSED, SMALL>(
                    top.as_mut_ptr().add(8 * i),
                    bot.as_mut_ptr().add(8 * i),
                    twiddle.0,
                );
            }
        }
        8 * vectors
    };
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "vpclmulqdq",
        target_feature = "avx2",
        not(target_feature = "avx512f")
    ))]
    let done = {
        let vectors = top.len() / 4;
        // SAFETY: the features are enabled at compile time, and call `i` touches words `4i..4i + 4` of both rows.
        unsafe {
            for i in 0..vectors {
                butterfly_lanes_avx2::<TRANSPOSED, SMALL>(
                    top.as_mut_ptr().add(4 * i),
                    bot.as_mut_ptr().add(4 * i),
                    twiddle.0,
                );
            }
        }
        4 * vectors
    };
    #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
    let done = {
        let vectors = top.len() / 8;
        let mut lane = 8 * vectors;
        // SAFETY:
        // - The `aes` target feature is enabled at compile time.
        // - The eight-lane calls touch words `8i..8i + 8`, and the pair calls `lane..lane + 2`, all inside both rows.
        unsafe {
            for i in 0..vectors {
                butterfly_lanes_neon_8::<TRANSPOSED, SMALL>(
                    top.as_mut_ptr().add(8 * i),
                    bot.as_mut_ptr().add(8 * i),
                    twiddle.0,
                );
            }
            while lane + 2 <= top.len() {
                butterfly_lane_pair_neon::<TRANSPOSED, SMALL>(
                    top.as_mut_ptr().add(lane),
                    bot.as_mut_ptr().add(lane),
                    twiddle.0,
                );
                lane += 2;
            }
        }
        lane
    };
    #[cfg(not(any(
        all(target_arch = "aarch64", target_feature = "aes"),
        all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx2")
    )))]
    let done = 0;
    for (u, v) in top[done..].iter_mut().zip(&mut bot[done..]) {
        butterfly_one::<TRANSPOSED>(u, v, twiddle);
    }
}

/// One lane's butterfly, forward or transposed.
#[inline(always)]
fn butterfly_one<const TRANSPOSED: bool>(u: &mut F64, v: &mut F64, t: F64) {
    if TRANSPOSED {
        let s = *u + *v;
        *u = s;
        *v += s * t;
    } else {
        *u += *v * t;
        *v += *u;
    }
}

/// Eight butterflies with a shared twiddle, one per 64-bit lane of an AVX-512 register.
///
/// # Algorithm
///
/// ```text
///     products:   even lanes 0,2,4,6 -> CLMUL 0x00      odd lanes 1,3,5,7 -> CLMUL 0x11
///                 each 128-bit lane then holds one whole 128-bit product
///
///     unpack:     lo = [ lo(p_0), lo(p_1), ..., lo(p_7) ]     hi = [ hi(p_0), ..., hi(p_7) ]
///
///     reduce:     p = lo + hi * x^64,  x^64 = x^4 + x^3 + x + 1
///                 p mod f = lo ^ g(hi ^ spill),  g(y) = y ^ y<<1 ^ y<<3 ^ y<<4
///                 spill = hi>>63 ^ hi>>61 ^ hi>>60, the bits g pushes past x^63
/// ```
///
/// - The unpacks stay inside 128-bit lanes, so no shuffle crosses lanes.
/// - The reduction takes shifts and three-way XORs, `vpternlogq 0x96`, instead of two more carry-less multiplies.
/// - The carry-less multiplier is the scarce unit on Zen 5, so those two would dominate the kernel.
///
/// # Safety
///
/// - Requires VPCLMULQDQ and AVX-512F.
/// - Each pointer must address eight readable and writable words.
#[cfg(all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx512f"))]
#[inline]
#[target_feature(enable = "vpclmulqdq", enable = "avx512f", enable = "avx2")]
unsafe fn butterfly_lanes_avx512<const TRANSPOSED: bool, const SMALL: bool>(
    top: *mut F64,
    bot: *mut F64,
    twiddle: u64,
) {
    // SAFETY:
    // - The caller supplies two valid eight-word rows.
    // - This function's target features cover every intrinsic below.
    unsafe {
        // Load both rows and broadcast the twiddle to every lane.
        let u = _mm512_loadu_si512(top.cast());
        let v = _mm512_loadu_si512(bot.cast());
        let tw = _mm512_set1_epi64(twiddle as i64);
        // The row multiplied by the twiddle, and the row the product is added to.
        let (m, acc) = if TRANSPOSED {
            (_mm512_xor_si512(u, v), v)
        } else {
            (v, u)
        };

        // Products m * t: even lanes, then odd lanes, one 128-bit product per 128-bit lane.
        let even = _mm512_clmulepi64_epi128::<0x00>(m, tw);
        let odd = _mm512_clmulepi64_epi128::<0x11>(m, tw);
        // Back to lane order: qword i of lo / hi is the low / high half of lane i's product.
        let lo = _mm512_unpacklo_epi64(even, odd);
        let hi = _mm512_unpackhi_epi64(even, odd);

        // Reduce modulo x^64 + x^4 + x^3 + x + 1 with shifts and three-way XORs.
        const XOR3: i32 = 0x96;
        // The bits of hi * (x^4 + x^3 + x + 1) that land past x^63, none when hi is below 2^60.
        // Both hi and spill are multiplied by the same constant, so fold them first.
        let x = if SMALL {
            hi
        } else {
            let spill = _mm512_ternarylogic_epi64::<XOR3>(
                _mm512_srli_epi64::<63>(hi),
                _mm512_srli_epi64::<61>(hi),
                _mm512_srli_epi64::<60>(hi),
            );
            _mm512_xor_si512(hi, spill)
        };
        // g(x) = x ^ x<<1 ^ x<<3 ^ x<<4, split across two three-way XORs.
        let fx = _mm512_ternarylogic_epi64::<XOR3>(x, _mm512_slli_epi64::<1>(x), _mm512_slli_epi64::<3>(x));
        // acc + m * t, with the product's lo and g(x) folded in one step.
        let sum = _mm512_ternarylogic_epi64::<XOR3>(acc, lo, _mm512_xor_si512(fx, _mm512_slli_epi64::<4>(x)));
        // Forward: u' = u + v * t, then v' = v + u'. Transposed: u' = u + v, then v' = v + u' * t.
        let (new_u, new_v) = if TRANSPOSED {
            (m, sum)
        } else {
            (sum, _mm512_xor_si512(v, sum))
        };
        _mm512_storeu_si512(top.cast(), new_u);
        _mm512_storeu_si512(bot.cast(), new_v);
    }
}

/// Four butterflies with a shared twiddle, for a machine with VPCLMULQDQ but no AVX-512.
///
/// ```text
///     reduce:     p = lo + hi * x^64,  x^64 = x^4 + x^3 + x + 1
///                 p mod f = lo ^ g(hi ^ spill),  g(y) = y ^ y<<1 ^ y<<3 ^ y<<4
///                 spill = n ^ n>>1 ^ n>>3 with n = hi>>60, the bits g pushes past x^63
/// ```
///
/// - The reduction takes no further carry-less multiply, the scarce unit.
/// - The spill is one byte-shuffle lookup of the top nibble.
/// - The left shifts of g are doublings, which issue on more ports than shifts.
///
/// # Safety
///
/// - Requires VPCLMULQDQ and AVX2.
/// - Each pointer must address four readable and writable words.
#[cfg(all(
    target_arch = "x86_64",
    target_feature = "vpclmulqdq",
    target_feature = "avx2",
    not(target_feature = "avx512f")
))]
#[inline]
#[target_feature(enable = "vpclmulqdq", enable = "avx2")]
unsafe fn butterfly_lanes_avx2<const TRANSPOSED: bool, const SMALL: bool>(top: *mut F64, bot: *mut F64, twiddle: u64) {
    // SAFETY:
    // - The caller supplies two valid four-word rows.
    // - This function's target features cover every intrinsic below.
    unsafe {
        let u = _mm256_loadu_si256(top.cast());
        let v = _mm256_loadu_si256(bot.cast());
        let tw = _mm256_set1_epi64x(twiddle as i64);

        // The row multiplied by the twiddle, and the row the product is added to.
        let (m, acc) = if TRANSPOSED {
            (_mm256_xor_si256(u, v), v)
        } else {
            (v, u)
        };

        // Products m * t, one 128-bit product per 128-bit lane, then back to lane order.
        let even = _mm256_clmulepi64_epi128::<0x00>(m, tw);
        let odd = _mm256_clmulepi64_epi128::<0x11>(m, tw);
        let lo = _mm256_unpacklo_epi64(even, odd);
        let hi = _mm256_unpackhi_epi64(even, odd);

        // The spill of every top nibble, none when hi is below 2^60.
        const SPILL: [u8; 16] = {
            let mut table = [0u8; 16];
            let mut n = 0;
            while n < 16 {
                table[n] = (n ^ (n >> 1) ^ (n >> 3)) as u8;
                n += 1;
            }
            table
        };
        // Both hi and spill are multiplied by the same constant, so fold them first.
        let x = if SMALL {
            hi
        } else {
            let table = _mm256_broadcastsi128_si256(_mm_loadu_si128(SPILL.as_ptr().cast()));
            _mm256_xor_si256(hi, _mm256_shuffle_epi8(table, _mm256_srli_epi64::<60>(hi)))
        };
        let x2 = _mm256_add_epi64(x, x);
        let x8 = {
            let x4 = _mm256_add_epi64(x2, x2);
            _mm256_add_epi64(x4, x4)
        };
        let x16 = _mm256_add_epi64(x8, x8);
        let gx = _mm256_xor_si256(_mm256_xor_si256(x, x2), _mm256_xor_si256(x8, x16));
        let product = _mm256_xor_si256(lo, gx);

        let sum = _mm256_xor_si256(acc, product);
        let (new_u, new_v) = if TRANSPOSED {
            (m, sum)
        } else {
            (sum, _mm256_xor_si256(v, sum))
        };
        _mm256_storeu_si256(top.cast(), new_u);
        _mm256_storeu_si256(bot.cast(), new_v);
    }
}

/// Eight butterflies with a shared twiddle, as four independent NEON two-lane reductions.
///
/// - Every row vector loads before any product, so the core has four independent PMULL chains to overlap.
/// - One call spreads the loop control and the twiddle and reduction constants over eight lanes.
///
/// # Safety
///
/// - Requires the `aes` target feature.
/// - Each pointer must address eight readable and writable words.
#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
#[inline]
#[target_feature(enable = "aes")]
unsafe fn butterfly_lanes_neon_8<const TRANSPOSED: bool, const SMALL: bool>(
    top: *mut F64,
    bot: *mut F64,
    twiddle: u64,
) {
    // SAFETY:
    // - The caller supplies two valid eight-word rows, and F64 is repr(transparent) over u64.
    // - This function's target feature covers every intrinsic below.
    unsafe {
        let v0 = vld1q_u64(bot.cast());
        let v1 = vld1q_u64(bot.cast::<u64>().add(2));
        let v2 = vld1q_u64(bot.cast::<u64>().add(4));
        let v3 = vld1q_u64(bot.cast::<u64>().add(6));
        let u0 = vld1q_u64(top.cast());
        let u1 = vld1q_u64(top.cast::<u64>().add(2));
        let u2 = vld1q_u64(top.cast::<u64>().add(4));
        let u3 = vld1q_u64(top.cast::<u64>().add(6));
        let tw = vdupq_n_u64(twiddle);
        // The rows multiplied by the twiddle, and the rows the products are added to.
        let ((m0, a0), (m1, a1), (m2, a2), (m3, a3)) = if TRANSPOSED {
            (
                (veorq_u64(u0, v0), v0),
                (veorq_u64(u1, v1), v1),
                (veorq_u64(u2, v2), v2),
                (veorq_u64(u3, v3), v3),
            )
        } else {
            ((v0, u0), (v1, u1), (v2, u2), (v3, u3))
        };

        let p00 = vreinterpretq_u64_p128(vmull_p64(vgetq_lane_u64::<0>(m0), twiddle));
        let p01 = vreinterpretq_u64_p128(vmull_high_p64(vreinterpretq_p64_u64(m0), vreinterpretq_p64_u64(tw)));
        let p10 = vreinterpretq_u64_p128(vmull_p64(vgetq_lane_u64::<0>(m1), twiddle));
        let p11 = vreinterpretq_u64_p128(vmull_high_p64(vreinterpretq_p64_u64(m1), vreinterpretq_p64_u64(tw)));
        let p20 = vreinterpretq_u64_p128(vmull_p64(vgetq_lane_u64::<0>(m2), twiddle));
        let p21 = vreinterpretq_u64_p128(vmull_high_p64(vreinterpretq_p64_u64(m2), vreinterpretq_p64_u64(tw)));
        let p30 = vreinterpretq_u64_p128(vmull_p64(vgetq_lane_u64::<0>(m3), twiddle));
        let p31 = vreinterpretq_u64_p128(vmull_high_p64(vreinterpretq_p64_u64(m3), vreinterpretq_p64_u64(tw)));

        let sum0 = veorq_u64(a0, reduce_pair::<SMALL>(p00, p01));
        let sum1 = veorq_u64(a1, reduce_pair::<SMALL>(p10, p11));
        let sum2 = veorq_u64(a2, reduce_pair::<SMALL>(p20, p21));
        let sum3 = veorq_u64(a3, reduce_pair::<SMALL>(p30, p31));
        // Forward: u' = u + v * t, then v' = v + u'. Transposed: u' = u + v, then v' = v + u' * t.
        let ((new_u0, new_v0), (new_u1, new_v1), (new_u2, new_v2), (new_u3, new_v3)) = if TRANSPOSED {
            ((m0, sum0), (m1, sum1), (m2, sum2), (m3, sum3))
        } else {
            (
                (sum0, veorq_u64(v0, sum0)),
                (sum1, veorq_u64(v1, sum1)),
                (sum2, veorq_u64(v2, sum2)),
                (sum3, veorq_u64(v3, sum3)),
            )
        };

        vst1q_u64(top.cast(), new_u0);
        vst1q_u64(top.cast::<u64>().add(2), new_u1);
        vst1q_u64(top.cast::<u64>().add(4), new_u2);
        vst1q_u64(top.cast::<u64>().add(6), new_u3);
        vst1q_u64(bot.cast(), new_v0);
        vst1q_u64(bot.cast::<u64>().add(2), new_v1);
        vst1q_u64(bot.cast::<u64>().add(4), new_v2);
        vst1q_u64(bot.cast::<u64>().add(6), new_v3);
    }
}

/// Two products reduced as a lane pair, folding once when `SMALL`.
///
/// # Safety
///
/// Requires the `aes` target feature.
#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
#[inline]
#[target_feature(enable = "aes")]
unsafe fn reduce_pair<const SMALL: bool>(p0: uint64x2_t, p1: uint64x2_t) -> uint64x2_t {
    // SAFETY: this function's target feature covers both reductions.
    unsafe {
        if SMALL {
            reduce_pair_pmull2(p0, p1)
        } else {
            reduce_pair_pmull4(p0, p1)
        }
    }
}

/// Two butterflies with a shared twiddle, kept in NEON registers end to end.
///
/// - PMULL and PMULL2 multiply the loaded row's two words, with no lane extraction.
/// - The two products reduce through a two-lane fold made of carry-less multiplies alone.
///
/// # Safety
///
/// - Requires the `aes` target feature.
/// - Each pointer must address two readable and writable words.
#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
#[inline]
#[target_feature(enable = "aes")]
unsafe fn butterfly_lane_pair_neon<const TRANSPOSED: bool, const SMALL: bool>(
    top: *mut F64,
    bot: *mut F64,
    twiddle: u64,
) {
    // SAFETY:
    // - The caller supplies two valid two-word rows, and F64 is repr(transparent) over u64.
    // - This function's target feature covers every intrinsic below.
    unsafe {
        let u = vld1q_u64(top as *const u64);
        let v = vld1q_u64(bot as *const u64);
        let m = if TRANSPOSED { veorq_u64(u, v) } else { v };
        // Products by the twiddle: PMULL on the low word, PMULL2 on the high one.
        // The broadcast twiddle is loop-invariant, so it is hoisted once the kernel is inlined.
        let tw = vdupq_n_u64(twiddle);
        let p0 = vreinterpretq_u64_p128(vmull_p64(vgetq_lane_u64::<0>(m), twiddle));
        let p1 = vreinterpretq_u64_p128(vmull_high_p64(vreinterpretq_p64_u64(m), vreinterpretq_p64_u64(tw)));
        let prod = reduce_pair::<SMALL>(p0, p1);
        let (new_u, new_v) = if TRANSPOSED {
            (m, veorq_u64(v, prod))
        } else {
            let new_u = veorq_u64(u, prod);
            (new_u, veorq_u64(v, new_u))
        };
        vst1q_u64(top as *mut u64, new_u);
        vst1q_u64(bot as *mut u64, new_v);
    }
}

/// Column sums of rows weighted by a table, as unreduced 128-bit carry-less products.
///
/// ```text
///     sums[w] = sum_j table[j] * rows[j][w]
/// ```
///
/// The rows are `sums.len()` words each, one row per table entry.
pub(super) fn dot_columns(table: &[F64], rows: &[F64], sums: &mut [u128]) {
    let width = sums.len();
    debug_assert_eq!(rows.len(), table.len() * width);
    #[cfg(all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx512f"))]
    let done = {
        let vectors = width / 8;
        for c in 0..vectors {
            // SAFETY: the target features are enabled at compile time, and words `8c..8c + 8` lie inside every row.
            let column = unsafe { dot_column_avx512(table, rows.as_ptr().add(8 * c), width) };
            sums[8 * c..][..8].copy_from_slice(&column);
        }
        8 * vectors
    };
    #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
    let done = {
        let vectors = width / 8;
        for c in 0..vectors {
            // SAFETY: the target feature is enabled at compile time, and words `8c..8c + 8` lie inside every row.
            let column = unsafe { dot_column_neon(table, rows.as_ptr().add(8 * c), width) };
            sums[8 * c..][..8].copy_from_slice(&column);
        }
        8 * vectors
    };
    #[cfg(not(any(
        all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx512f"),
        all(target_arch = "aarch64", target_feature = "aes")
    )))]
    let done = 0;
    for (w, sum) in sums.iter_mut().enumerate().skip(done) {
        *sum = (table.iter().zip(rows[w..].iter().step_by(width))).fold(0, |acc, (t, x)| acc ^ mul_wide(t.0, x.0));
    }
}

/// The unreduced column sums over eight words of every row, the first at `column`, rows `width` words apart.
///
/// One carry-less multiply takes the even words and another the odd words, one product per 128-bit lane.
///
/// # Safety
///
/// - Requires VPCLMULQDQ and AVX-512F.
/// - `column` must address eight readable words in each of `table.len()` rows.
#[cfg(all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx512f"))]
#[inline]
#[target_feature(enable = "vpclmulqdq", enable = "avx512f")]
unsafe fn dot_column_avx512(table: &[F64], column: *const F64, width: usize) -> [u128; 8] {
    // SAFETY:
    // - The caller supplies eight readable words in every row.
    // - This function's target features cover every intrinsic below.
    unsafe {
        // Sums of the even words' products, then of the odd words', one 128-bit sum per 128-bit lane.
        let (mut even, mut odd) = (_mm512_setzero_si512(), _mm512_setzero_si512());
        for (j, t) in table.iter().enumerate() {
            let x = _mm512_loadu_si512(column.add(j * width).cast());
            let t = _mm512_set1_epi64(t.0 as i64);
            even = _mm512_xor_si512(even, _mm512_clmulepi64_epi128::<0x00>(t, x));
            odd = _mm512_xor_si512(odd, _mm512_clmulepi64_epi128::<0x10>(t, x));
        }
        let (mut e, mut o) = ([0u128; 4], [0u128; 4]);
        _mm512_storeu_si512(e.as_mut_ptr().cast(), even);
        _mm512_storeu_si512(o.as_mut_ptr().cast(), odd);
        std::array::from_fn(|w| if w % 2 == 0 { e[w / 2] } else { o[w / 2] })
    }
}

/// Unreduced column sums over eight words of every row, the first at `column`, rows `width` words apart.
///
/// - Each 128-bit load holds two words.
/// - `PMULL` multiplies the low one by the row's table entry, `PMULL2` the high one.
/// - Two rows go per step, so one three-way XOR folds both of a word's products into its sum.
///
/// # Safety
///
/// - Requires the `aes` target feature.
/// - `column` must address eight readable words in each of `table.len()` rows.
#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
#[inline]
#[target_feature(enable = "aes")]
unsafe fn dot_column_neon(table: &[F64], column: *const F64, width: usize) -> [u128; 8] {
    // SAFETY:
    // - The caller supplies eight readable words in every row.
    // - This function's target feature covers every intrinsic below.
    unsafe {
        // Row j's eight words as four vectors, each word times the row's table entry t_j.
        //
        //     x[v] = [w_2v, w_2v+1]   ->   (t_j * w_2v, t_j * w_2v+1)
        let products = |j: usize| {
            let row = column.add(j * width).cast::<u64>();
            let t = vdupq_n_u64(table[j].0);
            std::array::from_fn::<_, 4, _>(|v| {
                let x = vld1q_u64(row.add(2 * v));
                let lo = vmull_p64(vgetq_lane_u64::<0>(t), vgetq_lane_u64::<0>(x));
                let hi = vmull_high_p64(vreinterpretq_p64_u64(t), vreinterpretq_p64_u64(x));
                (vreinterpretq_u64_p128(lo), vreinterpretq_u64_p128(hi))
            })
        };
        // One 128-bit sum per word of the column.
        let mut sums = [vdupq_n_u64(0); 8];
        // Rows two at a time: each sum takes both rows' products in one three-way XOR.
        let pairs = table.len() / 2;
        for j in 0..pairs {
            let (a, b) = (products(2 * j), products(2 * j + 1));
            for v in 0..4 {
                sums[2 * v] = xor3_u64(sums[2 * v], a[v].0, b[v].0);
                sums[2 * v + 1] = xor3_u64(sums[2 * v + 1], a[v].1, b[v].1);
            }
        }
        // An odd last row goes alone.
        if table.len() % 2 == 1 {
            let a = products(table.len() - 1);
            for v in 0..4 {
                sums[2 * v] = veorq_u64(sums[2 * v], a[v].0);
                sums[2 * v + 1] = veorq_u64(sums[2 * v + 1], a[v].1);
            }
        }
        sums.map(|s| vreinterpretq_p128_u64(s))
    }
}
