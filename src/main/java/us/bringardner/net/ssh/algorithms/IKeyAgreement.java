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
import java.security.SecureRandom;

import us.bringardner.net.ssh.SshException;

/**
 * The math of an ephemeral key exchange (Diffie-Hellman, ECDH or X25519): make a key pair,
 * then agree on a shared secret with the peer's public value. Used by
 * {@link EphemeralKeyExchange}, which does the SSH messages, the exchange hash and the
 * host key, the same for every agreement.
 * <p>
 * One instance per exchange.
 *
 * @author Tony Bringardner
 */
public interface IKeyAgreement {

	/**
	 * Make this side's key pair.
	 *
	 * @return this side's public value, the contents of the string that is sent: e as mpint 
	 * bytes for Diffie-Hellman, the point Q_C / Q_S for ECDH and X25519
	 */
	byte[] init(SecureRandom random) throws GeneralSecurityException;

	/**
	 * @param peer the peer's public value (the contents of the string received)
	 * @return the shared secret K as an unsigned big endian number
	 * @throws SshException if the peer's value is invalid
	 */
	byte[] agree(byte[] peer) throws SshException, GeneralSecurityException;

}
