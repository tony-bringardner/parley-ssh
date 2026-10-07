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
package us.bringardner.net.ssh.server;

/**
 * Decides which port forwarding a user may do. Forwarding lets a logged in user reach other
 * hosts through the server (-L) or open ports on it (-R), so a server refuses all of it
 * unless it has a filter; with an access control list the user also needs the "forward"
 * permission.
 *
 * @author Tony Bringardner
 * @see ForwardingFilters
 */
public interface IForwardingFilter {

	/**
	 * ssh -L: may the server connect to host:port for this user?
	 */
	boolean canConnect(ServerSession session, String host, int port);

	/**
	 * ssh -R: may the server listen on bindHost:port (0: any free port) for this user?
	 */
	boolean canListen(ServerSession session, String bindHost, int port);
}
