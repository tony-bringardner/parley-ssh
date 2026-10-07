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
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * aes128-gcm@openssh.com and aes256-gcm@openssh.com (RFC 5647 as OpenSSH uses it): the packet
 * length is authenticated but not encrypted, the 12 byte IV is a fixed 4 bytes and an 8 byte
 * counter that goes up by one for each packet, and the 16 byte tag replaces the MAC.
 *
 * @author Tony Bringardner
 */
public class AesGcmCipher implements ISshCipher {

	private static final int TAG = 16;

	private final String name;
	private final int keySize;
	private boolean encrypt;
	private SecretKeySpec key;
	private byte[] iv;
	private Cipher cipher;

	public AesGcmCipher(String name, int keySize) {
		this.name = name;
		this.keySize = keySize;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int getKeySize() {
		return keySize;
	}

	@Override
	public int getIvSize() {
		return 12;
	}

	@Override
	public int getBlockSize() {
		return 16;
	}

	@Override
	public int getTagSize() {
		return TAG;
	}

	@Override
	public void init(boolean encrypt, byte[] key, byte[] iv) throws GeneralSecurityException {
		this.encrypt = encrypt;
		this.key = new SecretKeySpec(key, 0, keySize, "AES");
		this.iv = Arrays.copyOf(iv, 12);
		this.cipher = Cipher.getInstance("AES/GCM/NoPadding");
	}

	@Override
	public void update(byte[] buf, int off, int len) {
		throw new UnsupportedOperationException(name+" is an AEAD cipher");
	}

	@Override
	public void encryptAead(byte[] buf, int aadOff, int aadLen, int off, int len) throws GeneralSecurityException {
		if( !encrypt ) {
			throw new IllegalStateException("Initialized for decryption");
		}
		cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG*8, iv));
		cipher.updateAAD(buf, aadOff, aadLen);
		byte[] out = cipher.doFinal(buf, off, len);
		System.arraycopy(out, 0, buf, off, out.length);
		nextIv();
	}

	@Override
	public void decryptAead(byte[] buf, int aadOff, int aadLen, int off, int len) throws GeneralSecurityException {
		if( encrypt ) {
			throw new IllegalStateException("Initialized for encryption");
		}
		cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG*8, iv));
		cipher.updateAAD(buf, aadOff, aadLen);
		// AEADBadTagException if the packet or its length was changed
		byte[] out = cipher.doFinal(buf, off, len+TAG);
		System.arraycopy(out, 0, buf, off, out.length);
		nextIv();
	}

	/**
	 * The invocation counter (the last 8 bytes, big endian) goes up by one per packet.
	 */
	private void nextIv() {
		for (int i = 11; i >= 4; i--) {
			if( ++iv[i] != 0 ) {
				break;
			}
		}
	}
}
