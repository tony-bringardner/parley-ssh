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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshException;

/**
 * ssh-ed25519 (RFC 8709): host keys and user keys, on Java 15 and later.
 *
 * @author Tony Bringardner
 */
public class Ed25519Signature implements ISignatureAlgorithm {

	@Override
	public String getName() {
		return Ed25519.SSH_ED25519;
	}

	@Override
	public String getKeyType() {
		return Ed25519.SSH_ED25519;
	}

	@Override
	public boolean isSupported() {
		return Ed25519.isSupported();
	}

	@Override
	public boolean verify(PublicKey key, byte[] data, byte[] signature) throws SshException {
		if( !Ed25519.isSupported() || !Ed25519.isEd25519(key) ) {
			return false;
		}
		SshBuffer b = new SshBuffer(signature);
		if( !getName().equals(b.getStringUtf8()) ) {
			return false;
		}
		byte[] sig = b.getString();
		if( sig.length != 64 ) {
			return false;
		}
		try {
			Signature s = Signature.getInstance("Ed25519");
			s.initVerify(key);
			s.update(data);
			return s.verify(sig);
		} catch (GeneralSecurityException e) {
			return false;
		}
	}

	@Override
	public byte[] sign(PrivateKey key, byte[] data) throws GeneralSecurityException {
		Signature s = Signature.getInstance("Ed25519");
		s.initSign(key);
		s.update(data);
		return new SshBuffer().putString(getName()).putString(s.sign()).toByteArray();
	}

	@Override
	public String toString() {
		return getName();
	}
}
