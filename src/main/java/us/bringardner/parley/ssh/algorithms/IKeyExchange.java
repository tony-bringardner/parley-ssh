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

import java.io.IOException;

import us.bringardner.parley.ssh.SshBuffer;

/**
 * A key exchange method (RFC 4253 section 8): after the algorithms are negotiated, it trades
 * its messages (numbers 30 to 49) through the context and produces the shared secret K and
 * the exchange hash H, from which the transport derives the keys.
 * <p>
 * One instance per key exchange. Its methods are called one at a time.
 *
 * @author Tony Bringardner
 */
public interface IKeyExchange {

	String getName();

	/**
	 * @return the JCE name of the hash (SHA-256, SHA-384, SHA-512), also used to derive the keys
	 */
	String getHashAlgorithm();

	/**
	 * Begin; a client sends its first message here.
	 */
	void start(IKexContext context) throws IOException;

	/**
	 * @param msg the message number (30 to 49)
	 * @param message the message, read position after the message number
	 * @return true when the exchange is done (K and H are known and, on the client, the
	 * host key has been checked)
	 * @throws IOException (an SshException) for an unexpected or invalid message
	 */
	boolean handle(int msg, SshBuffer message) throws IOException;

	/**
	 * @return H, once done
	 */
	byte[] getExchangeHash();

	/**
	 * @return K as an unsigned big endian number, once done
	 */
	byte[] getSharedSecret();
}
