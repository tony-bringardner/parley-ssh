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

import java.io.IOException;
import java.net.SocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import us.bringardner.parley.net.nio.INioConnection;
import us.bringardner.parley.net.server.IPrincipal;
import us.bringardner.parley.net.server.Permission;
import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshConstants;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.ISignatureAlgorithm;
import us.bringardner.parley.ssh.algorithms.SshCertificate;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;
import us.bringardner.parley.ssh.connection.ConnectionService;
import us.bringardner.parley.ssh.transport.SshTransport;

/**
 * The server end of one SSH connection: the server side of the key exchange (with the
 * server's host keys), the ssh-userauth service (with the server's methods, a limit on
 * failures, a delay after each, and a time limit for logging in), then the connection
 * protocol with "session" channels.
 *
 * @author Tony Bringardner
 */
public class ServerSession extends SshTransport {

	private final SshServer server;
	private final ConnectionService connection;
	private final ServerForwarding forwarding;
	private final Map<String, Object> attributes = new ConcurrentHashMap<String, Object>();
	private volatile boolean authenticated;
	private volatile String user;
	private volatile IPrincipal principal;
	private volatile ScheduledFuture<?> loginTimer;

	// user authentication, on the handler thread
	private boolean userAuthAccepted;
	private boolean bannerSent;
	private int failures;
	private IServerAuthMethod pending;
	private String pendingUser;

	private final IServerAuthContext authContext = new IServerAuthContext() {
		@Override
		public SshServer getServer() {
			return server;
		}

		@Override
		public byte[] getSessionId() {
			return ServerSession.this.getSessionId();
		}

		@Override
		public SocketAddress getRemoteAddress() {
			return getConnection().getRemoteAddress();
		}

		@Override
		public String getService() {
			return SshConstants.SERVICE_CONNECTION;
		}

		@Override
		public void send(SshBuffer message) throws IOException {
			ServerSession.this.send(message);
		}

		@Override
		public Map<String, Object> getAttributes() {
			return attributes;
		}
	};

	public ServerSession(SshServer server) {
		super(false, server.getAlgorithms(), server.getVersion(), server.getRandom());
		this.server = server;
		this.connection = new ConnectionService(this);
		connection.addChannelFactory("session", (type, data) -> new ServerSessionChannel(this));
		connection.setMaxChannels(server.getMaxChannelsPerSession());
		forwarding = new ServerForwarding(this);
	}

	public SshServer getServer() {
		return server;
	}

	public ConnectionService getConnectionService() {
		return connection;
	}

	public boolean isAuthenticated() {
		return authenticated;
	}

	/**
	 * @return the user name that logged in, null before
	 */
	public String getUser() {
		return user;
	}

	public IPrincipal getPrincipal() {
		return principal;
	}

	/**
	 * @return state shared by the auth methods and plug-ins of this session
	 */
	public Map<String, Object> getAttributes() {
		return attributes;
	}

	/**
	 * @param permission e.g. "shell", "exec", "sftp"
	 * @return the OpenSSH certificate the user logged in with, or null
	 */
	public SshCertificate getLoginCertificate() {
		return authenticated ? (SshCertificate) attributes.get(PublicKeyAuthMethod.CERTIFICATE) : null;
	}

	/**
	 * @param extension e.g. {@link SshCertificate#PERMIT_PTY}
	 * @return true unless the user logged in with a certificate that doesn't have it
	 */
	public boolean isPermittedByCertificate(String extension) {
		SshCertificate c = getLoginCertificate();
		return c == null || c.hasExtension(extension);
	}

	/**
	 * @return true if the user may: always without an access control list, else only with the permission
	 */
	public boolean isPermitted(String permission) {
		if( server.getAccessControl() == null ) {
			return true;
		}
		return principal != null && server.isAuthorized(principal, new Permission(permission));
	}

	// ------------------------------------------------------------------ transport hooks

	@Override
	public void onConnect(INioConnection c) throws Exception {
		super.onConnect(c);
		long grace = server.getLoginTimeLimit();
		if( grace > 0 ) {
			loginTimer = server.getScheduler().schedule(() -> {
				if( !authenticated ) {
					logDebug("Login time limit reached for "+c.getRemoteAddress());
					disconnect(SshConstants.SSH_DISCONNECT_BY_APPLICATION, "Login time limit reached");
				}
			}, grace, TimeUnit.MILLISECONDS);
		}
	}

	@Override
	protected List<String> getHostKeyAlgorithmsToOffer() {
		List<String> ret = new ArrayList<String>();
		for (String alg : super.getHostKeyAlgorithmsToOffer()) {
			if( hostKey(alg) != null ) {
				ret.add(alg);
			}
		}
		return ret;
	}

	private KeyPair hostKey(String algorithm) {
		ISignatureAlgorithm sig = getAlgorithms().findHostKeyAlgorithm(algorithm);
		if( sig == null ) {
			return null;
		}
		if( SshCertificate.isCertificateType(sig.getKeyType()) ) {
			SshCertificate c = hostCertificate(sig.getKeyType());
			return c == null ? null : keyOf(c);
		}
		for (KeyPair kp : server.getHostKeys()) {
			if( sig.getKeyType().equals(SshPublicKeys.keyType(kp.getPublic())) ) {
				return kp;
			}
		}
		return null;
	}

	private SshCertificate hostCertificate(String type) {
		for (SshCertificate c : server.getHostCertificates()) {
			if( c.getType().equals(type) ) {
				return c;
			}
		}
		return null;
	}

	private KeyPair keyOf(SshCertificate c) {
		for (KeyPair kp : server.getHostKeys()) {
			if( Arrays.equals(SshPublicKeys.encode(kp.getPublic()), c.getPublicKeyBlob()) ) {
				return kp;
			}
		}
		return null;
	}

	/**
	 * K_S: the key's blob, or for a certificate algorithm the certificate's
	 */
	@Override
	protected byte[] getHostKey(String algorithm) throws IOException {
		KeyPair kp = hostKey(algorithm);
		if( kp == null ) {
			throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "No host key for "+algorithm);
		}
		String type = getAlgorithms().findHostKeyAlgorithm(algorithm).getKeyType();
		return SshCertificate.isCertificateType(type) ? hostCertificate(type).getBlob() : SshPublicKeys.encode(kp.getPublic());
	}

	@Override
	protected byte[] signExchangeHash(byte[] exchangeHash, String algorithm) throws IOException {
		KeyPair kp = hostKey(algorithm);
		try {
			return getAlgorithms().findHostKeyAlgorithm(algorithm).sign(kp.getPrivate(), exchangeHash);
		} catch (GeneralSecurityException e) {
			throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Can't sign with the host key: "+e.getMessage(), e);
		}
	}

	/**
	 * server-sig-algs (RFC 8308): the signature algorithms accepted for user keys, so
	 * clients with RSA keys use rsa-sha2-*.
	 */
	@Override
	protected SshBuffer getExtInfo() {
		return SshBuffer.message(SshConstants.SSH_MSG_EXT_INFO).putInt(1)
				.putString("server-sig-algs").putString(String.join(",", getAlgorithms().getHostKeyAlgorithmNames()));
	}

	@Override
	protected void onReady() {
	}

	@Override
	protected void onClosed(Throwable reason) {
		ScheduledFuture<?> t = loginTimer;
		if( t != null ) {
			t.cancel(false);
		}
		connection.closeAll(reason);
		forwarding.close();
	}

	// ------------------------------------------------------------------ messages

	@Override
	protected boolean handleMessage(int msg, SshBuffer message) throws Exception {
		if( msg == SshConstants.SSH_MSG_SERVICE_REQUEST ) {
			String name = message.getStringUtf8();
			if( SshConstants.SERVICE_USERAUTH.equals(name) && !authenticated ) {
				userAuthAccepted = true;
				send(SshBuffer.message(SshConstants.SSH_MSG_SERVICE_ACCEPT).putString(name));
			} else {
				disconnect(SshConstants.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE, "Service not available: "+name);
			}
			return true;
		}
		if( msg == SshConstants.SSH_MSG_USERAUTH_REQUEST ) {
			if( !userAuthAccepted ) {
				throw new SshException("USERAUTH_REQUEST before the ssh-userauth service");
			}
			if( !authenticated ) {
				authRequest(message);
			}
			// After success, further requests are ignored (RFC 4252 5.1)
			return true;
		}
		if( msg > SshConstants.SSH_MSG_USERAUTH_BANNER && msg < SshConstants.SSH_MSG_GLOBAL_REQUEST ) {
			IServerAuthMethod m = pending;
			if( m == null || authenticated ) {
				throw new SshException("Unexpected "+SshConstants.messageName(msg));
			}
			pending = null;
			apply(m, pendingUser, m.handle(authContext, msg, message));
			return true;
		}
		if( msg >= SshConstants.SSH_MSG_GLOBAL_REQUEST && msg <= SshConstants.SSH_MSG_CHANNEL_FAILURE ) {
			if( !authenticated ) {
				throw new SshException("Unexpected "+SshConstants.messageName(msg)+" before authentication");
			}
			return connection.handle(msg, message);
		}
		return false;
	}

	private void authRequest(SshBuffer m) throws IOException {
		String name = m.getStringUtf8();
		String service = m.getStringUtf8();
		String method = m.getStringUtf8();
		if( !SshConstants.SERVICE_CONNECTION.equals(service) ) {
			disconnect(SshConstants.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE, "Service not available: "+service);
			return;
		}
		pending = null;
		String banner = server.getBanner();
		if( !bannerSent && banner != null && !banner.isEmpty() ) {
			bannerSent = true;
			send(SshBuffer.message(SshConstants.SSH_MSG_USERAUTH_BANNER).putString(banner).putString(""));
		}
		if( "none".equals(method) ) {
			sendFailure();
			return;
		}
		IServerAuthMethod am = server.findAuthMethod(method);
		if( am == null ) {
			failed(name);
			return;
		}
		apply(am, name, am.request(authContext, name, m));
	}

	private void apply(IServerAuthMethod m, String name, IServerAuthMethod.Result r) throws IOException {
		if( r.isPending() ) {
			pending = m;
			pendingUser = name;
		} else if( r.isSuccess() ) {
			user = name;
			principal = r.getPrincipal();
			authenticated = true;
			getConnection().setPrincipal(principal);
			ScheduledFuture<?> t = loginTimer;
			if( t != null ) {
				t.cancel(false);
			}
			logInfo("User "+name+" logged in with "+m.getName()+" from "+getConnection().getRemoteAddress());
			send(SshBuffer.message(SshConstants.SSH_MSG_USERAUTH_SUCCESS));
			startDelayedCompression();
		} else {
			failed(name);
		}
	}

	private void failed(String name) throws IOException {
		failures++;
		logDebug(() -> "Authentication failure "+failures+" for "+name+" from "+getConnection().getRemoteAddress());
		if( server.isTooManyLoginFailures(failures) ) {
			logInfo("Too many authentication failures for "+name+" from "+getConnection().getRemoteAddress());
			disconnect(SshConstants.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, "Too many authentication failures");
			return;
		}
		long delay = server.getLoginFailureDelay();
		if( delay > 0 ) {
			// Slows down guessing; the client waits for the answer, the thread doesn't
			server.getScheduler().schedule(() -> {
				try {
					sendFailure();
				} catch (IOException e) {
					logDebug("Can't send USERAUTH_FAILURE", e);
				}
			}, delay, TimeUnit.MILLISECONDS);
		} else {
			sendFailure();
		}
	}

	private void sendFailure() throws IOException {
		List<String> names = new ArrayList<String>();
		for (IServerAuthMethod am : server.getAuthMethods()) {
			names.add(am.getName());
		}
		send(SshBuffer.message(SshConstants.SSH_MSG_USERAUTH_FAILURE).putNameList(names).putBoolean(false));
	}

	@Override
	public String toString() {
		return "ServerSession["+getConnection()+(user == null ? "" : " "+user)+"]";
	}
}
