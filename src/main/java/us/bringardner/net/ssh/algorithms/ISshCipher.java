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

/**
 * A packet cipher (RFC 4253 section 6.3). Either a plain cipher, used with a MAC, or an AEAD
 * cipher ({@link #getTagSize()} &gt; 0) that also protects the packet and needs no MAC
 * (e.g. aes128-gcm@openssh.com).
 * <p>
 * An instance holds the state of one direction of one connection.
 *
 * @author Tony Bringardner
 */
public interface ISshCipher {

	String getName();

	/** Key length in bytes */
	int getKeySize();

	/** IV length in bytes, as derived by the key exchange */
	int getIvSize();

	/** Block size in bytes, which the packet length is padded to */
	int getBlockSize();

	/**
	 * @return the authentication tag length of an AEAD cipher, 0 for a plain cipher
	 */
	default int getTagSize() {
		return 0;
	}

	default boolean isAead() {
		return getTagSize() > 0;
	}

	void init(boolean encrypt, byte[] key, byte[] iv) throws GeneralSecurityException;

	/**
	 * Plain ciphers: encrypt or decrypt buf[off..off+len) in place, continuing the stream.
	 */
	void update(byte[] buf, int off, int len) throws GeneralSecurityException;

	/**
	 * AEAD ciphers: encrypt buf[off..off+len) in place and write the tag at buf[off+len].
	 * buf[aadOff..aadOff+aadLen) (the packet length) is authenticated, not encrypted.
	 */
	default void encryptAead(byte[] buf, int aadOff, int aadLen, int off, int len) throws GeneralSecurityException {
		throw new UnsupportedOperationException(getName()+" is not an AEAD cipher");
	}

	/**
	 * AEAD ciphers: check the tag at buf[off+len] and decrypt buf[off..off+len) in place.
	 *
	 * @throws GeneralSecurityException (AEADBadTagException) if the packet was changed
	 */
	default void decryptAead(byte[] buf, int aadOff, int aadLen, int off, int len) throws GeneralSecurityException {
		throw new UnsupportedOperationException(getName()+" is not an AEAD cipher");
	}
}
