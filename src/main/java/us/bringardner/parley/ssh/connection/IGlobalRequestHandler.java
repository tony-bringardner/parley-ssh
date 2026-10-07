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
package us.bringardner.parley.ssh.connection;

import java.io.IOException;

import us.bringardner.parley.ssh.SshBuffer;

/**
 * Answers one kind of global request from the peer (RFC 4254 4), e.g. "tcpip-forward".
 * Registered with {@link ConnectionService#addGlobalRequestHandler(String, IGlobalRequestHandler)};
 * requests without a handler fail.
 *
 * @author Tony Bringardner
 */
@FunctionalInterface
public interface IGlobalRequestHandler {

	/**
	 * @param request the request name
	 * @param data the request's data
	 * @return the data of SSH_MSG_REQUEST_SUCCESS (an empty buffer for none), or null for failure
	 */
	SshBuffer handle(String request, SshBuffer data) throws IOException;
}
