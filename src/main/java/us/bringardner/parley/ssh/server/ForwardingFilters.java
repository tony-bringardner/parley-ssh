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
package us.bringardner.parley.ssh.server;

import java.util.Locale;

/**
 * Common forwarding filters.
 *
 * @author Tony Bringardner
 */
public final class ForwardingFilters {

	private ForwardingFilters() {
	}

	/**
	 * Anything: connect anywhere, listen on any address. Like OpenSSH's AllowTcpForwarding yes
	 * with GatewayPorts yes.
	 */
	public static IForwardingFilter allowAll() {
		return new IForwardingFilter() {
			@Override
			public boolean canConnect(ServerSession session, String host, int port) {
				return true;
			}

			@Override
			public boolean canListen(ServerSession session, String bindHost, int port) {
				return true;
			}
		};
	}

	/**
	 * Only this machine: connect to localhost, listen on the loopback address only
	 * (OpenSSH's GatewayPorts no), ports above 1023.
	 */
	public static IForwardingFilter localOnly() {
		return new IForwardingFilter() {
			@Override
			public boolean canConnect(ServerSession session, String host, int port) {
				return isLoopback(host);
			}

			@Override
			public boolean canListen(ServerSession session, String bindHost, int port) {
				return isLoopback(bindHost) && (port == 0 || port > 1023);
			}
		};
	}

	static boolean isLoopback(String host) {
		String h = host == null ? "" : host.toLowerCase(Locale.ROOT);
		return h.equals("localhost") || h.equals("127.0.0.1") || h.equals("::1") || h.equals("[::1]");
	}
}
