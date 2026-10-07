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

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Ed25519 (RFC 8032, RFC 8709 for SSH) through the JDK's provider, which has it from Java 15.
 * Only names are used ("Ed25519"), no Java 15 classes, so this compiles for Java 11 and
 * {@link #isSupported()} says whether this JVM can do it.
 * <p>
 * Keys are moved in and out of the JDK as their X.509 / PKCS#8 encodings: a fixed header
 * (RFC 8410) and the 32 raw bytes SSH uses.
 *
 * @author Tony Bringardner
 */
public final class Ed25519 {

	public static final String SSH_ED25519 = "ssh-ed25519";

	/** SubjectPublicKeyInfo header of an Ed25519 public key (OID 1.3.101.112), then 32 bytes */
	private static final byte[] X509_PREFIX = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
	/** PKCS#8 PrivateKeyInfo header of an Ed25519 private key, then the 32 byte seed */
	private static final byte[] PKCS8_PREFIX = {0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20};

	private static final boolean SUPPORTED;

	static {
		boolean ok;
		try {
			Signature.getInstance("Ed25519");
			KeyFactory.getInstance("Ed25519");
			ok = true;
		} catch (GeneralSecurityException e) {
			ok = false;
		}
		SUPPORTED = ok;
	}

	private Ed25519() {
	}

	/**
	 * @return true if this JVM has Ed25519 (Java 15 and later)
	 */
	public static boolean isSupported() {
		return SUPPORTED;
	}

	/**
	 * @return true if the key is an Ed25519 key (public or private)
	 */
	public static boolean isEd25519(Key key) {
		byte[] enc = key.getEncoded();
		if( enc == null ) {
			return false;
		}
		byte[] prefix = key instanceof PublicKey ? X509_PREFIX : PKCS8_PREFIX;
		if( key instanceof PublicKey ) {
			return enc.length == 44 && Arrays.equals(Arrays.copyOf(enc, 12), prefix);
		}
		// A PKCS#8 v2 key may carry the public key after the seed
		return enc.length >= 48 && Arrays.equals(Arrays.copyOfRange(enc, 5, 12), Arrays.copyOfRange(PKCS8_PREFIX, 5, 12));
	}

	/**
	 * @return the 32 byte public key
	 */
	public static byte[] publicBytes(PublicKey key) {
		byte[] enc = key.getEncoded();
		return Arrays.copyOfRange(enc, enc.length-32, enc.length);
	}

	/**
	 * @return the 32 byte seed (the private key as RFC 8032 and OpenSSH keep it)
	 */
	public static byte[] seed(PrivateKey key) {
		byte[] enc = key.getEncoded();
		// OCTET STRING { OCTET STRING seed } right after the algorithm
		for (int i = 0; i+34 <= enc.length; i++) {
			if( enc[i] == 0x04 && enc[i+1] == 0x22 && enc[i+2] == 0x04 && enc[i+3] == 0x20 ) {
				return Arrays.copyOfRange(enc, i+4, i+36);
			}
		}
		throw new IllegalArgumentException("Not an Ed25519 private key");
	}

	public static PublicKey publicKey(byte[] raw) throws GeneralSecurityException {
		if( raw.length != 32 ) {
			throw new GeneralSecurityException("An Ed25519 public key is 32 bytes, not "+raw.length);
		}
		byte[] enc = Arrays.copyOf(X509_PREFIX, 44);
		System.arraycopy(raw, 0, enc, 12, 32);
		return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(enc));
	}

	public static PrivateKey privateKey(byte[] seed) throws GeneralSecurityException {
		if( seed.length != 32 ) {
			throw new GeneralSecurityException("An Ed25519 seed is 32 bytes, not "+seed.length);
		}
		byte[] enc = Arrays.copyOf(PKCS8_PREFIX, 48);
		System.arraycopy(seed, 0, enc, 16, 32);
		return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(enc));
	}

	public static KeyPair generate() throws GeneralSecurityException {
		return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
	}
}
