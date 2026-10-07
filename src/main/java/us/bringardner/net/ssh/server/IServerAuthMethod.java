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

import java.io.IOException;

import us.bringardner.net.framework.server.IPrincipal;
import us.bringardner.net.ssh.SshBuffer;

/**
 * A server side user authentication method (RFC 4252), e.g. "password" or "publickey".
 * The server offers the methods it has, in order; a request for one goes to it.
 * <p>
 * Methods are shared by all sessions: keep per-session state in the context.
 *
 * @author Tony Bringardner
 * @see PasswordAuthMethod
 * @see PublicKeyAuthMethod
 * @see KeyboardInteractiveAuthMethod
 */
public interface IServerAuthMethod {

	/**
	 * The outcome of a request.
	 */
	final class Result {
		/** Not authenticated */
		public static final Result FAILURE = new Result(null, false);
		/** The method sent its own message (PK_OK, INFO_REQUEST) and waits for the client */
		public static final Result PENDING = new Result(null, true);

		private final IPrincipal principal;
		private final boolean pending;

		private Result(IPrincipal principal, boolean pending) {
			this.principal = principal;
			this.pending = pending;
		}

		/**
		 * @param principal the authenticated user
		 */
		public static Result success(IPrincipal principal) {
			if( principal == null ) {
				throw new IllegalArgumentException("principal");
			}
			return new Result(principal, false);
		}

		public boolean isSuccess() {
			return principal != null;
		}

		public boolean isPending() {
			return pending;
		}

		public IPrincipal getPrincipal() {
			return principal;
		}
	}

	String getName();

	/**
	 * An SSH_MSG_USERAUTH_REQUEST for this method.
	 *
	 * @param user the user name
	 * @param data the method specific part
	 */
	Result request(IServerAuthContext context, String user, SshBuffer data) throws IOException;

	/**
	 * A method specific message from the client (e.g. 61, keyboard-interactive's INFO_RESPONSE),
	 * after this method returned PENDING.
	 */
	default Result handle(IServerAuthContext context, int msg, SshBuffer data) throws IOException {
		throw new us.bringardner.net.ssh.SshException("Unexpected message "+msg+" for "+getName());
	}
}
