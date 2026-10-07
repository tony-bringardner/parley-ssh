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
package us.bringardner.net.ssh.algorithms;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * chacha20-poly1305@openssh.com (OpenSSH's PROTOCOL.chacha20poly1305), OpenSSH's preferred
 * cipher. The 64 byte key is two ChaCha20 keys: the second encrypts the packet length, the
 * first the payload (block counter 1) and makes the one-time Poly1305 key (block 0). The
 * nonce is the packet's sequence number. The tag covers the encrypted length and payload.
 * <p>
 * OpenSSH uses the original ChaCha20 (64 bit nonce, 64 bit counter); the JDK's (RFC 8439)
 * has a 96 bit nonce and a 32 bit counter. With the counter below 2^32 they are the same
 * with four zero bytes in front of the nonce. The JDK's cipher is used in decrypt mode
 * (the same key stream), which doesn't refuse a key and nonce used twice as encrypt mode does:
 * here that is by design (the length, the Poly1305 key and the payload share the nonce).
 *
 * @author Tony Bringardner
 */
public class ChaChaPolyCipher implements ISshCipher {

	public static final String NAME = "chacha20-poly1305@openssh.com";

	private SecretKeySpec main;
	private SecretKeySpec header;
	private long sequence;

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public int getKeySize() {
		return 64;
	}

	@Override
	public int getIvSize() {
		return 0;
	}

	@Override
	public int getBlockSize() {
		return 8;
	}

	@Override
	public int getTagSize() {
		return 16;
	}

	@Override
	public boolean isLengthEncrypted() {
		return true;
	}

	@Override
	public void setSequence(long sequence) {
		this.sequence = sequence;
	}

	@Override
	public void init(boolean encrypt, byte[] key, byte[] iv) {
		main = new SecretKeySpec(key, 0, 32, "ChaCha20");
		header = new SecretKeySpec(key, 32, 32, "ChaCha20");
	}

	@Override
	public void update(byte[] buf, int off, int len) {
		throw new UnsupportedOperationException(NAME+" is an AEAD cipher");
	}

	private byte[] nonce() {
		byte[] n = new byte[12];
		for (int i = 0; i < 8; i++) {
			n[4+i] = (byte) (sequence >>> (56-8*i));
		}
		return n;
	}

	/**
	 * XOR buf[off..off+len) with the key stream from the block counter.
	 */
	private void xor(SecretKeySpec key, byte[] nonce, int counter, byte[] buf, int off, int len) throws GeneralSecurityException {
		Cipher c = Cipher.getInstance("ChaCha20");
		c.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, counter));
		byte[] out = c.doFinal(buf, off, len);
		System.arraycopy(out, 0, buf, off, len);
	}

	private byte[] polyKey(byte[] nonce) throws GeneralSecurityException {
		byte[] k = new byte[32];
		xor(main, nonce, 0, k, 0, 32);
		return k;
	}

	@Override
	public int decryptLength(byte[] buf, int off) throws GeneralSecurityException {
		byte[] tmp = Arrays.copyOfRange(buf, off, off+4);
		xor(header, nonce(), 0, tmp, 0, 4);
		return ((tmp[0] & 0xff) << 24) | ((tmp[1] & 0xff) << 16) | ((tmp[2] & 0xff) << 8) | (tmp[3] & 0xff);
	}

	@Override
	public void encryptAead(byte[] buf, int aadOff, int aadLen, int off, int len) throws GeneralSecurityException {
		byte[] nonce = nonce();
		byte[] pk = polyKey(nonce);
		xor(header, nonce, 0, buf, aadOff, aadLen);
		xor(main, nonce, 1, buf, off, len);
		byte[] tag = Poly1305.mac(pk, buf, aadOff, aadLen+len);
		System.arraycopy(tag, 0, buf, off+len, 16);
		Arrays.fill(pk, (byte) 0);
	}

	@Override
	public void decryptAead(byte[] buf, int aadOff, int aadLen, int off, int len) throws GeneralSecurityException {
		byte[] nonce = nonce();
		byte[] pk = polyKey(nonce);
		byte[] want = Poly1305.mac(pk, buf, aadOff, aadLen+len);
		Arrays.fill(pk, (byte) 0);
		if( !MessageDigest.isEqual(want, Arrays.copyOfRange(buf, off+len, off+len+16)) ) {
			throw new AEADBadTagException("Bad Poly1305 tag");
		}
		xor(header, nonce, 0, buf, aadOff, aadLen);
		xor(main, nonce, 1, buf, off, len);
	}
}
