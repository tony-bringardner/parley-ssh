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
import java.security.PublicKey;
import java.util.Collections;
import java.util.List;

/**
 * Decides whether a server's host key is trusted. Called once per connection, after the key
 * exchange proved the server holds the key's private half. Without this check anyone between
 * the client and the server could pretend to be the server.
 * <p>
 * May block (e.g. to ask a user); it runs on the connection's handler thread.
 *
 * @author Tony Bringardner
 * @see KnownHosts
 * @see HostKeyVerifiers
 */
@FunctionalInterface
public interface IHostKeyVerifier {

	/**
	 * @param host the host name or address as given to connect
	 * @param port the port
	 * @param key the server's host key
	 * @return true to trust the key and go on, false to disconnect
	 */
	boolean verify(String host, int port, PublicKey key) throws IOException;

	/**
	 * @return the key types already known for the host (e.g. "ecdsa-sha2-nistp256"), so the
	 * client asks for those host key algorithms first; empty if none
	 */
	default List<String> getKnownKeyTypes(String host, int port) {
		return Collections.emptyList();
	}
}
