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

import us.bringardner.net.ssh.SshException;

/**
 * A public key signature algorithm, used for host keys in the key exchange and for user keys
 * in public key authentication, e.g. "rsa-sha2-256" (key type "ssh-rsa") or "ecdsa-sha2-nistp256".
 * <p>
 * Instances are stateless and may be shared.
 *
 * @author Tony Bringardner
 */
public interface ISignatureAlgorithm {

	/**
	 * @return the algorithm name, as in the host key algorithm list and the signature blob
	 */
	String getName();

	/**
	 * @return the key type this algorithm signs with, as in the key blob (rsa-sha2-256 uses "ssh-rsa")
	 */
	String getKeyType();

	/**
	 * @param key the signer's public key
	 * @param data what was signed
	 * @param signature the signature blob (string algorithm name, string signature)
	 * @return true if the signature is valid and made by this algorithm
	 * @throws SshException if the blob is malformed
	 */
	boolean verify(PublicKey key, byte[] data, byte[] signature) throws SshException;

	/**
	 * @return the signature blob (string algorithm name, string signature)
	 */
	byte[] sign(PrivateKey key, byte[] data) throws GeneralSecurityException;
}
