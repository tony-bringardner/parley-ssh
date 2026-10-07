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
package us.bringardner.parley.ssh.client;

import java.io.IOException;

import us.bringardner.parley.ssh.SshBuffer;

/**
 * A client side user authentication method (RFC 4252), e.g. "password" or "publickey".
 * {@link ClientSession#authenticate(String, IClientAuthMethod...)} tries the methods in
 * order, those the server allows, until one succeeds.
 * <p>
 * An instance is used for one authenticate call; its methods are called one at a time.
 *
 * @author Tony Bringardner
 * @see PasswordAuth
 * @see PublicKeyAuth
 * @see KeyboardInteractiveAuth
 */
public interface IClientAuthMethod {

	/**
	 * @return the method name, as in SSH_MSG_USERAUTH_REQUEST and the server's list
	 */
	String getName();

	/**
	 * Send the first request.
	 *
	 * @return false if there is nothing to try (e.g. no usable key), then the next method is tried
	 */
	boolean start(IClientAuthContext context) throws IOException;

	/**
	 * A method specific message (60 to 79), e.g. publickey's PK_OK or keyboard-interactive's INFO_REQUEST.
	 *
	 * @return true if it was expected
	 */
	boolean handle(int msg, SshBuffer message, IClientAuthContext context) throws IOException;

	/**
	 * The server refused the last request.
	 *
	 * @return true if another request was sent (e.g. with the next key), false to give up on this method
	 */
	boolean retry(IClientAuthContext context) throws IOException;
}
