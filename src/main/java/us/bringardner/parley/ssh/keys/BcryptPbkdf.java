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
package us.bringardner.parley.ssh.keys;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * bcrypt_pbkdf, OpenBSD's key derivation that OpenSSH uses for passphrase protected private
 * keys ("openssh-key-v1" with kdf "bcrypt"): PBKDF2-like rounds of a bcrypt hash built on
 * the Eksblowfish key schedule.
 * <p>
 * Blowfish starts from 1042 words of the hexadecimal digits of pi. The JDK has them but not
 * where it can be reached, so they are computed once here (Machin's formula) and checked
 * against the published first and last words.
 *
 * @author Tony Bringardner
 */
public final class BcryptPbkdf {

	private static final int[] PI_P = new int[18];
	private static final int[][] PI_S = new int[4][256];

	static {
		int[] words = piWords(18+4*256);
		System.arraycopy(words, 0, PI_P, 0, 18);
		for (int i = 0; i < 4; i++) {
			System.arraycopy(words, 18+256*i, PI_S[i], 0, 256);
		}
		// The published Blowfish tables begin and end with these
		if( PI_P[0] != 0x243F6A88 || PI_P[17] != 0x8979FB1B || PI_S[0][0] != 0xD1310BA6 || PI_S[3][255] != 0x3AC372E6 ) {
			throw new IllegalStateException("Blowfish tables computed wrongly");
		}
	}

	private BcryptPbkdf() {
	}

	/**
	 * @return the first n 32-bit words of the hexadecimal fraction of pi
	 */
	private static int[] piWords(int n) {
		int bits = 32*n+64;
		BigInteger one = BigInteger.ONE.shiftLeft(bits);
		// pi = 16 atan(1/5) - 4 atan(1/239)
		BigInteger pi = atanInverse(5, one).shiftLeft(4).subtract(atanInverse(239, one).shiftLeft(2));
		BigInteger frac = pi.subtract(BigInteger.valueOf(3).shiftLeft(bits));
		int[] ret = new int[n];
		for (int i = 0; i < n; i++) {
			ret[i] = frac.shiftRight(bits-32*(i+1)).intValue();
		}
		return ret;
	}

	/**
	 * @return atan(1/x) in fixed point (one = the scale)
	 */
	private static BigInteger atanInverse(int x, BigInteger one) {
		BigInteger x2 = BigInteger.valueOf((long) x*x);
		BigInteger term = one.divide(BigInteger.valueOf(x));
		BigInteger sum = term;
		for (int k = 1; term.signum() != 0; k++) {
			term = term.divide(x2);
			BigInteger t = term.divide(BigInteger.valueOf(2L*k+1));
			sum = (k & 1) == 1 ? sum.subtract(t) : sum.add(t);
		}
		return sum;
	}

	// ------------------------------------------------------------------ Blowfish

	private static final class Blowfish {
		final int[] p = PI_P.clone();
		final int[][] s = {PI_S[0].clone(), PI_S[1].clone(), PI_S[2].clone(), PI_S[3].clone()};
		private final int[] lr = new int[2];

		private int f(int x) {
			return ((s[0][x >>> 24] + s[1][(x >>> 16) & 0xff]) ^ s[2][(x >>> 8) & 0xff]) + s[3][x & 0xff];
		}

		/** Encipher lr[0], lr[1] in place */
		void encipher() {
			int l = lr[0] ^ p[0];
			int r = lr[1];
			for (int i = 1; i <= 16; i += 2) {
				r ^= f(l) ^ p[i];
				l ^= f(r) ^ p[i+1];
			}
			lr[0] = r ^ p[17];
			lr[1] = l;
		}

		/** OpenBSD's stream2word: 4 bytes big endian, wrapping around the data */
		private static int word(byte[] data, int[] pos) {
			int ret = 0;
			for (int i = 0; i < 4; i++) {
				ret = (ret << 8) | (data[pos[0]] & 0xff);
				pos[0] = (pos[0]+1) % data.length;
			}
			return ret;
		}

		void expand(byte[] data, byte[] key) {
			int[] j = {0};
			for (int i = 0; i < 18; i++) {
				p[i] ^= word(key, j);
			}
			j[0] = 0;
			lr[0] = 0;
			lr[1] = 0;
			for (int i = 0; i < 18; i += 2) {
				if( data != null ) {
					lr[0] ^= word(data, j);
					lr[1] ^= word(data, j);
				}
				encipher();
				p[i] = lr[0];
				p[i+1] = lr[1];
			}
			for (int[] box : s) {
				for (int k = 0; k < 256; k += 2) {
					if( data != null ) {
						lr[0] ^= word(data, j);
						lr[1] ^= word(data, j);
					}
					encipher();
					box[k] = lr[0];
					box[k+1] = lr[1];
				}
			}
		}
	}

	private static final byte[] MAGIC = "OxychromaticBlowfishSwatDynamite".getBytes(StandardCharsets.US_ASCII);

	/**
	 * OpenBSD's bcrypt_hash: 32 bytes from the hashed passphrase and salt.
	 */
	private static byte[] bcryptHash(byte[] sha2pass, byte[] sha2salt) {
		Blowfish b = new Blowfish();
		b.expand(sha2salt, sha2pass);
		for (int i = 0; i < 64; i++) {
			b.expand(null, sha2salt);
			b.expand(null, sha2pass);
		}
		int[] cdata = new int[8];
		int[] j = {0};
		for (int i = 0; i < 8; i++) {
			cdata[i] = Blowfish.word(MAGIC, j);
		}
		for (int i = 0; i < 64; i++) {
			for (int k = 0; k < 8; k += 2) {
				b.lr[0] = cdata[k];
				b.lr[1] = cdata[k+1];
				b.encipher();
				cdata[k] = b.lr[0];
				cdata[k+1] = b.lr[1];
			}
		}
		byte[] out = new byte[32];
		for (int i = 0; i < 8; i++) {
			out[4*i+3] = (byte) (cdata[i] >>> 24);
			out[4*i+2] = (byte) (cdata[i] >>> 16);
			out[4*i+1] = (byte) (cdata[i] >>> 8);
			out[4*i] = (byte) cdata[i];
		}
		return out;
	}

	/**
	 * @param passphrase the passphrase's bytes (UTF-8)
	 * @param salt from the key file
	 * @param rounds from the key file (ssh-keygen uses 16 by default)
	 * @param keyLength bytes wanted (key and IV of the cipher)
	 */
	public static byte[] derive(byte[] passphrase, byte[] salt, int rounds, int keyLength) {
		if( rounds < 1 || keyLength < 1 || keyLength > 1024 || salt.length == 0 ) {
			throw new IllegalArgumentException("Bad bcrypt_pbkdf parameters");
		}
		MessageDigest sha512;
		try {
			sha512 = MessageDigest.getInstance("SHA-512");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
		int stride = (keyLength+31)/32;
		int amt = (keyLength+stride-1)/stride;
		byte[] key = new byte[keyLength];
		byte[] sha2pass = sha512.digest(passphrase);
		int left = keyLength;
		for (int count = 1; left > 0; count++) {
			byte[] countsalt = Arrays.copyOf(salt, salt.length+4);
			countsalt[salt.length] = (byte) (count >>> 24);
			countsalt[salt.length+1] = (byte) (count >>> 16);
			countsalt[salt.length+2] = (byte) (count >>> 8);
			countsalt[salt.length+3] = (byte) count;
			byte[] tmp = bcryptHash(sha2pass, sha512.digest(countsalt));
			byte[] out = tmp.clone();
			for (int i = 1; i < rounds; i++) {
				tmp = bcryptHash(sha2pass, sha512.digest(tmp));
				for (int k = 0; k < out.length; k++) {
					out[k] ^= tmp[k];
				}
			}
			amt = Math.min(amt, left);
			int i;
			for (i = 0; i < amt; i++) {
				int dest = i*stride+(count-1);
				if( dest >= keyLength ) {
					break;
				}
				key[dest] = out[i];
			}
			left -= i;
		}
		Arrays.fill(sha2pass, (byte) 0);
		return key;
	}
}
