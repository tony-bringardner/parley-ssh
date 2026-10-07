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
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;

import us.bringardner.net.ssh.SshConstants;
import us.bringardner.net.ssh.SshException;

/**
 * X25519 for curve25519-sha256 (RFC 8731), with the JDK's XDH (Java 11+). The public values
 * are the 32 byte RFC 7748 encodings; the shared secret's 32 bytes are used as an unsigned
 * big endian number.
 *
 * @author Tony Bringardner
 */
public class X25519Agreement implements IKeyAgreement {

	/** The X.509 SubjectPublicKeyInfo header of an X25519 key, followed by the 32 key bytes */
	private static final byte[] X509_PREFIX = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00};

	private KeyPair pair;

	@Override
	public byte[] init(SecureRandom random) throws GeneralSecurityException {
		KeyPairGenerator g = KeyPairGenerator.getInstance("X25519");
		g.initialize(255, random);
		pair = g.generateKeyPair();
		byte[] enc = pair.getPublic().getEncoded();
		return Arrays.copyOfRange(enc, enc.length-32, enc.length);
	}

	@Override
	public byte[] agree(byte[] peer) throws SshException, GeneralSecurityException {
		if( peer.length != 32 ) {
			throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "X25519 public key of "+peer.length+" bytes");
		}
		byte[] enc = Arrays.copyOf(X509_PREFIX, X509_PREFIX.length+32);
		System.arraycopy(peer, 0, enc, X509_PREFIX.length, 32);
		PublicKey key = KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(enc));
		KeyAgreement ka = KeyAgreement.getInstance("X25519");
		ka.init(pair.getPrivate());
		ka.doPhase(key, true);
		byte[] secret = ka.generateSecret();
		// A low order point gives all zeros (RFC 7748 6.1): the peer chose the secret
		boolean zero = true;
		for (byte b : secret) {
			zero &= b == 0;
		}
		if( zero ) {
			throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "X25519 shared secret is zero");
		}
		return secret;
	}
}
