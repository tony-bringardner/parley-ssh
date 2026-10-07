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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshConstants;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.SshAlgorithms;

/**
 * One run of client user authentication (RFC 4252 5): a "none" request learns which methods
 * the server allows, then the given methods are tried in order, those the server allows,
 * until it sends SSH_MSG_USERAUTH_SUCCESS. A partial success (the server wants more than one
 * method) goes on with the methods it still lists.
 * <p>
 * Used on the session's handler thread.
 *
 * @author Tony Bringardner
 */
final class UserAuthClient implements IClientAuthContext {

	private final ClientSession session;
	private final String user;
	private final List<IClientAuthMethod> methods;
	private final CompletableFuture<Void> result = new CompletableFuture<Void>();
	private final Set<IClientAuthMethod> finished = new HashSet<IClientAuthMethod>();
	private IClientAuthMethod current;
	private List<String> allowed = Collections.emptyList();
	private String lastProblem;

	UserAuthClient(ClientSession session, String user, List<IClientAuthMethod> methods) {
		this.session = session;
		this.user = user;
		this.methods = new ArrayList<IClientAuthMethod>(methods);
	}

	CompletableFuture<Void> getResult() {
		return result;
	}

	/**
	 * Ask with method "none": the answer lists the methods (or, rarely, lets the user in).
	 */
	void start() throws IOException {
		send(newRequest("none"));
	}

	void onFailure(List<String> canContinue, boolean partialSuccess) throws IOException {
		allowed = canContinue;
		if( current != null ) {
			if( partialSuccess ) {
				// That method was accepted, the server wants another one as well
				finished.add(current);
				current = null;
			} else if( current.retry(this) ) {
				return;
			} else {
				finished.add(current);
				current = null;
			}
		}
		next();
	}

	void onSuccess() {
		current = null;
		result.complete(null);
	}

	boolean handle(int msg, SshBuffer message) throws IOException {
		return current != null && current.handle(msg, message, this);
	}

	void fail(Throwable reason) {
		result.completeExceptionally(reason);
	}

	private void next() throws IOException {
		for (IClientAuthMethod m : methods) {
			if( finished.contains(m) || !allowed.contains(m.getName()) ) {
				continue;
			}
			current = m;
			if( m.start(this) ) {
				return;
			}
			finished.add(m);
			current = null;
		}
		result.completeExceptionally(new SshException(SshConstants.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
				"Authentication of "+user+" failed"+(lastProblem == null ? "" : " ("+lastProblem+")")
				+"; the server allows "+allowed));
	}

	// ------------------------------------------------------------------ IClientAuthContext

	@Override
	public String getUser() {
		return user;
	}

	@Override
	public String getService() {
		return SshConstants.SERVICE_CONNECTION;
	}

	@Override
	public byte[] getSessionId() {
		return session.getSessionId();
	}

	@Override
	public void send(SshBuffer message) throws IOException {
		session.send(message);
	}

	@Override
	public List<String> getServerSignatureAlgorithms() {
		return session.getServerSignatureAlgorithms();
	}

	@Override
	public SshAlgorithms getAlgorithms() {
		return session.getAlgorithms();
	}

	@Override
	public void methodFailed(String why) throws IOException {
		lastProblem = why;
		if( current != null ) {
			finished.add(current);
			current = null;
		}
		next();
	}
}
