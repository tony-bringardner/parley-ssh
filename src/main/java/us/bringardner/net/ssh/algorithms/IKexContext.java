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

import java.io.IOException;
import java.security.SecureRandom;

import us.bringardner.net.ssh.SshBuffer;

/**
 * What the transport gives a key exchange: the strings that go into the exchange hash, a way
 * to send messages, and the host key (checked by a client, used to sign by a server).
 *
 * @author Tony Bringardner
 */
public interface IKexContext {

	/**
	 * @return true on the client side
	 */
	boolean isClient();

	/** V_C, the client's identification string without CR LF */
	byte[] getClientVersion();

	/** V_S, the server's identification string without CR LF */
	byte[] getServerVersion();

	/** I_C, the payload of the client's SSH_MSG_KEXINIT */
	byte[] getClientKexInit();

	/** I_S, the payload of the server's SSH_MSG_KEXINIT */
	byte[] getServerKexInit();

	/**
	 * @return the negotiated host key algorithm, e.g. "rsa-sha2-256"
	 */
	String getHostKeyAlgorithm();

	SecureRandom getRandom();

	/**
	 * Send a key exchange message.
	 */
	void send(SshBuffer message) throws IOException;

	/**
	 * Client side: check that the host key signed the exchange hash with the negotiated
	 * algorithm, and that the key is trusted for this host.
	 *
	 * @param hostKey K_S, the server's host key blob
	 * @param signature the signature blob
	 * @param exchangeHash H
	 * @throws IOException (an SshException) if the signature is bad or the key isn't trusted
	 */
	void verifyHostKey(byte[] hostKey, byte[] signature, byte[] exchangeHash) throws IOException;

	/**
	 * Server side: K_S, the blob of the host key for the negotiated algorithm.
	 */
	byte[] getHostKey() throws IOException;

	/**
	 * Server side: sign the exchange hash with the host key.
	 *
	 * @return the signature blob
	 */
	byte[] signExchangeHash(byte[] exchangeHash) throws IOException;
}
