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
package us.bringardner.net.ssh.client;

import java.io.IOException;
import java.util.List;

import us.bringardner.net.ssh.SshBuffer;
import us.bringardner.net.ssh.algorithms.SshAlgorithms;

/**
 * What a client authentication method can use: the user, the session id it signs, and a way
 * to send messages.
 *
 * @author Tony Bringardner
 */
public interface IClientAuthContext {

	String getUser();

	/**
	 * @return the service to start once authenticated ("ssh-connection")
	 */
	String getService();

	/**
	 * @return H of the first key exchange, part of what publickey signs
	 */
	byte[] getSessionId();

	/**
	 * @return a new SSH_MSG_USERAUTH_REQUEST with user, service and method name filled in
	 */
	default SshBuffer newRequest(String method) {
		return SshBuffer.message(us.bringardner.net.ssh.SshConstants.SSH_MSG_USERAUTH_REQUEST)
				.putString(getUser()).putString(getService()).putString(method);
	}

	void send(SshBuffer message) throws IOException;

	/**
	 * @return the signature algorithms the server accepts (RFC 8308 server-sig-algs), empty if it didn't say
	 */
	List<String> getServerSignatureAlgorithms();

	/**
	 * @return the session's algorithms (e.g. whether SHA-1 ssh-rsa signatures are allowed)
	 */
	SshAlgorithms getAlgorithms();

	/**
	 * The method can't go on (e.g. the server asked for a password change): the next method is tried.
	 */
	void methodFailed(String why) throws IOException;
}
