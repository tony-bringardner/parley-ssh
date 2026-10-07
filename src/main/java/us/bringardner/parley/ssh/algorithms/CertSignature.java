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

import us.bringardner.parley.ssh.SshException;

/**
 * A certificate's signature algorithm (PROTOCOL.certkeys), e.g.
 * "ssh-ed25519-cert-v01@openssh.com" or "rsa-sha2-512-cert-v01@openssh.com": the key blob is
 * an {@link SshCertificate}, the signature is the certified key's own (made and checked
 * with the plain algorithm, on the certified key).
 *
 * @author Tony Bringardner
 */
public final class CertSignature implements ISignatureAlgorithm {

	private final ISignatureAlgorithm plain;
	private final String name;

	/**
	 * @param plain the algorithm of the certified key, e.g. rsa-sha2-512
	 */
	public CertSignature(ISignatureAlgorithm plain) {
		this.plain = plain;
		this.name = SshCertificate.certificateType(plain.getName());
	}

	/**
	 * @return the plain algorithm, e.g. "rsa-sha2-512" for "rsa-sha2-512-cert-v01@openssh.com"
	 */
	public ISignatureAlgorithm getPlain() {
		return plain;
	}

	@Override
	public String getName() {
		return name;
	}

	/**
	 * @return the certificate type, e.g. "ssh-rsa-cert-v01@openssh.com" for every RSA algorithm
	 */
	@Override
	public String getKeyType() {
		return SshCertificate.certificateType(plain.getKeyType());
	}

	/**
	 * @param key the certified key ({@link SshCertificate#getPublicKey()})
	 */
	@Override
	public boolean verify(PublicKey key, byte[] data, byte[] signature) throws SshException {
		return plain.verify(key, data, signature);
	}

	@Override
	public byte[] sign(PrivateKey key, byte[] data) throws GeneralSecurityException {
		return plain.sign(key, data);
	}

	@Override
	public boolean isSupported() {
		return plain.isSupported();
	}

	@Override
	public String toString() {
		return name;
	}
}
