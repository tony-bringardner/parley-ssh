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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

import us.bringardner.net.ssh.SshBuffer;
import us.bringardner.net.ssh.SshException;

/**
 * rsa-sha2-256 and rsa-sha2-512 (RFC 8332) with "ssh-rsa" keys. The SHA-1 "ssh-rsa" signature
 * is available for old peers but not offered by default.
 *
 * @author Tony Bringardner
 */
public class RsaSignature implements ISignatureAlgorithm {

	/** Shorter RSA keys are refused (OpenSSH refuses keys under 1024 bits too) */
	public static final int MIN_KEY_BITS = 1024;

	private final String name;
	private final String jceName;

	public RsaSignature(String name, String jceName) {
		this.name = name;
		this.jceName = jceName;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getKeyType() {
		return SshPublicKeys.SSH_RSA;
	}

	@Override
	public boolean verify(PublicKey key, byte[] data, byte[] signature) throws SshException {
		if( !(key instanceof RSAPublicKey) ) {
			return false;
		}
		RSAPublicKey rsa = (RSAPublicKey) key;
		if( rsa.getModulus().bitLength() < MIN_KEY_BITS ) {
			return false;
		}
		SshBuffer b = new SshBuffer(signature);
		if( !name.equals(b.getStringUtf8()) ) {
			return false;
		}
		byte[] sig = b.getString();
		int size = (rsa.getModulus().bitLength()+7)/8;
		if( sig.length > size ) {
			return false;
		}
		if( sig.length < size ) {
			// Some signers drop leading zero bytes
			byte[] tmp = new byte[size];
			System.arraycopy(sig, 0, tmp, size-sig.length, sig.length);
			sig = tmp;
		}
		try {
			Signature s = Signature.getInstance(jceName);
			s.initVerify(key);
			s.update(data);
			return s.verify(sig);
		} catch (GeneralSecurityException e) {
			return false;
		}
	}

	@Override
	public byte[] sign(PrivateKey key, byte[] data) throws GeneralSecurityException {
		Signature s = Signature.getInstance(jceName);
		s.initSign(key);
		s.update(data);
		return new SshBuffer().putString(name).putString(s.sign()).toByteArray();
	}

	@Override
	public String toString() {
		return name;
	}
}
