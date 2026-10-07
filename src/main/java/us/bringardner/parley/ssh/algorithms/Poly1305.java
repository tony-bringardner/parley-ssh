/**
 * <PRE>
 * 
 * Copyright Tony Bringardner 1998, 2026 <A href="http://bringardner.com/tony">Tony Bringardner</A>
 * 
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       <A href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</A>
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *  </PRE>
 *   
 *   
 *	@author Tony Bringardner   
 *
 *
 * ~version~V000.00.01-V000.00.00-
 */
package us.bringardner.parley.ssh.algorithms;

/**
 * The Poly1305 one-time authenticator (RFC 8439 2.5), which the JDK has only inside its
 * ChaCha20-Poly1305 AEAD (a different construction from OpenSSH's). 26-bit limbs, the
 * well known "donna" design: no branches or table lookups that depend on the key or data.
 *
 * @author Tony Bringardner
 */
public final class Poly1305 {

	private static final long MASK26 = 0x3ffffff;

	private Poly1305() {
	}

	private static long le32(byte[] b, int off) {
		return (b[off] & 0xffL) | ((b[off+1] & 0xffL) << 8) | ((b[off+2] & 0xffL) << 16) | ((b[off+3] & 0xffL) << 24);
	}

	/**
	 * @param key 32 bytes, used once
	 * @return the 16 byte tag of msg[off..off+len)
	 */
	public static byte[] mac(byte[] key, byte[] msg, int off, int len) {
		long r0 = le32(key, 0) & 0x3ffffff;
		long r1 = (le32(key, 3) >>> 2) & 0x3ffff03;
		long r2 = (le32(key, 6) >>> 4) & 0x3ffc0ff;
		long r3 = (le32(key, 9) >>> 6) & 0x3f03fff;
		long r4 = (le32(key, 12) >>> 8) & 0x00fffff;
		long s1 = r1*5, s2 = r2*5, s3 = r3*5, s4 = r4*5;
		long h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
		byte[] block = new byte[16];
		int pos = off;
		int end = off+len;
		while( pos < end ) {
			int n = Math.min(16, end-pos);
			long hibit;
			byte[] m;
			int mo;
			if( n == 16 ) {
				m = msg;
				mo = pos;
				hibit = 1L << 24;
			} else {
				// The last partial block: a 1 byte after the data, then zeros, no high bit
				java.util.Arrays.fill(block, (byte) 0);
				System.arraycopy(msg, pos, block, 0, n);
				block[n] = 1;
				m = block;
				mo = 0;
				hibit = 0;
			}
			h0 += le32(m, mo) & MASK26;
			h1 += (le32(m, mo+3) >>> 2) & MASK26;
			h2 += (le32(m, mo+6) >>> 4) & MASK26;
			h3 += (le32(m, mo+9) >>> 6) & MASK26;
			h4 += (le32(m, mo+12) >>> 8) | hibit;

			long d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1;
			long d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2;
			long d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3;
			long d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4;
			long d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;

			long c = d0 >>> 26; h0 = d0 & MASK26;
			d1 += c; c = d1 >>> 26; h1 = d1 & MASK26;
			d2 += c; c = d2 >>> 26; h2 = d2 & MASK26;
			d3 += c; c = d3 >>> 26; h3 = d3 & MASK26;
			d4 += c; c = d4 >>> 26; h4 = d4 & MASK26;
			h0 += c*5; c = h0 >>> 26; h0 &= MASK26;
			h1 += c;
			pos += n;
		}

		// Fully carry h
		long c = h1 >>> 26; h1 &= MASK26;
		h2 += c; c = h2 >>> 26; h2 &= MASK26;
		h3 += c; c = h3 >>> 26; h3 &= MASK26;
		h4 += c; c = h4 >>> 26; h4 &= MASK26;
		h0 += c*5; c = h0 >>> 26; h0 &= MASK26;
		h1 += c;

		// g = h + 5 - 2^130; use g if it isn't negative (h >= p), else h
		long g0 = h0+5; c = g0 >>> 26; g0 &= MASK26;
		long g1 = h1+c; c = g1 >>> 26; g1 &= MASK26;
		long g2 = h2+c; c = g2 >>> 26; g2 &= MASK26;
		long g3 = h3+c; c = g3 >>> 26; g3 &= MASK26;
		long g4 = h4+c-(1L << 26);
		long mask = (g4 >>> 63)-1;   // all ones if g4 >= 0
		g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
		mask = ~mask;
		h0 = (h0 & mask) | g0;
		h1 = (h1 & mask) | g1;
		h2 = (h2 & mask) | g2;
		h3 = (h3 & mask) | g3;
		h4 = (h4 & mask) | g4;

		// h % 2^128, then + s
		h0 = (h0 | (h1 << 26)) & 0xffffffffL;
		h1 = ((h1 >>> 6) | (h2 << 20)) & 0xffffffffL;
		h2 = ((h2 >>> 12) | (h3 << 14)) & 0xffffffffL;
		h3 = ((h3 >>> 18) | (h4 << 8)) & 0xffffffffL;
		long f = h0+le32(key, 16); h0 = f & 0xffffffffL;
		f = h1+le32(key, 20)+(f >>> 32); h1 = f & 0xffffffffL;
		f = h2+le32(key, 24)+(f >>> 32); h2 = f & 0xffffffffL;
		f = h3+le32(key, 28)+(f >>> 32); h3 = f & 0xffffffffL;

		byte[] tag = new byte[16];
		long[] hs = {h0, h1, h2, h3};
		for (int i = 0; i < 4; i++) {
			tag[4*i] = (byte) hs[i];
			tag[4*i+1] = (byte) (hs[i] >>> 8);
			tag[4*i+2] = (byte) (hs[i] >>> 16);
			tag[4*i+3] = (byte) (hs[i] >>> 24);
		}
		return tag;
	}
}
