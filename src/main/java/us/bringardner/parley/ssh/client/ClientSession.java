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
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import us.bringardner.parley.net.nio.INioConnection;
import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.connection.ConnectionService;
import us.bringardner.parley.ssh.SshConstants;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.ISignatureAlgorithm;
import us.bringardner.parley.ssh.algorithms.SshAlgorithms;
import us.bringardner.parley.ssh.algorithms.SshCertificate;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;
import us.bringardner.parley.ssh.transport.SshTransport;

/**
 * The client end of an SSH connection, made by {@link SshClient#connect(String, int)}.
 * <p>
 * The key exchange checks the server's host key with the client's {@link IHostKeyVerifier};
 * {@link #getReadyFuture()} completes once it is done and the keys are in use.
 *
 * @author Tony Bringardner
 */
public class ClientSession extends SshTransport {

	private final String host;
	private final int port;
	private final IHostKeyVerifier verifier;
	private final CompletableFuture<ClientSession> ready = new CompletableFuture<ClientSession>();
	private volatile PublicKey hostKey;
	private volatile SshCertificate hostCertificate;
	// What the first key exchange's host key blob was: a re-key must use the same
	private volatile byte[] hostKeyBlob;
	// One service request at a time (RFC 4253 10)
	private CompletableFuture<Void> serviceRequest;
	private String requestedService;
	// user authentication
	private volatile UserAuthClient auth;
	private volatile boolean userAuthAccepted;
	private volatile boolean authenticated;
	private volatile String authenticatedUser;
	private volatile Consumer<String> bannerListener;
	private volatile long authTimeout = 60000;
	// connection protocol
	private final ConnectionService connection = new ConnectionService(this);
	private volatile java.util.concurrent.Executor executor = java.util.concurrent.ForkJoinPool.commonPool();
	// ssh -R: the server's bound port to the local target "host:port"
	private final java.util.Map<Integer, String> remoteTargets = new java.util.concurrent.ConcurrentHashMap<Integer, String>();
	private volatile long channelTimeout = 30000;
	private volatile int maxKeepAliveFailures = 3;
	private final java.util.concurrent.atomic.AtomicInteger unansweredKeepAlives = new java.util.concurrent.atomic.AtomicInteger();

	protected ClientSession(String host, int port, IHostKeyVerifier verifier, SshAlgorithms algorithms, String version, SecureRandom random) {
		super(true, algorithms, version, random);
		this.host = host;
		this.port = port;
		this.verifier = verifier;
		connection.addChannelFactory(us.bringardner.parley.ssh.connection.ForwardingChannel.FORWARDED, (type, data) -> forwarded(data));
		connection.addChannelFactory(us.bringardner.parley.ssh.connection.AgentChannel.TYPE, (type, data) -> agentChannel());
	}

	// null: agent forwarding off; "": the user's agent (SSH_AUTH_SOCK); else the agent's path
	private volatile String forwardedAgent;

	/**
	 * Allow the server to use an SSH agent through this session once a session channel asks
	 * for it ({@link SessionChannel#requestAgentForwarding()}). Off by default: the server's
	 * agent channels are refused.
	 *
	 * @param agentPath the agent's socket or pipe, "" for the user's agent, null to turn it off
	 */
	public void setAgentForwarding(String agentPath) {
		this.forwardedAgent = agentPath;
	}

	public void setAgentForwarding(boolean on) {
		setAgentForwarding(on ? "" : null);
	}

	/**
	 * The server opened an agent channel: connect it to the agent, if forwarding is on.
	 */
	private us.bringardner.parley.ssh.connection.AgentChannel agentChannel() {
		String path = forwardedAgent;
		if( path == null ) {
			logInfo("Refused an agent channel from "+host+": agent forwarding is off");
			return null;
		}
		us.bringardner.parley.ssh.connection.AgentChannel ch = new us.bringardner.parley.ssh.connection.AgentChannel();
		ch.setOnOpen(() -> executor.execute(() -> {
			try {
				SshAgent a = path.isEmpty() ? SshAgent.connect() : SshAgent.connect(path);
				ch.bridge(a.rawInput(), a.rawOutput(), a.rawCloseable(), executor);
			} catch (IOException e) {
				logDebug("Can't reach the SSH agent to forward: "+e.getMessage());
				ch.close();
			}
		}));
		return ch;
	}

	/**
	 * @param executor runs the copying of forwarded connections (the client's pool)
	 */
	void setExecutor(java.util.concurrent.Executor executor) {
		this.executor = executor;
	}

	// ------------------------------------------------------------------ port forwarding

	/**
	 * Ask the server to connect to host:port and carry the connection over a channel 
	 * (the channel's streams are the connection).
	 */
	public us.bringardner.parley.ssh.connection.ForwardingChannel openDirectTcpip(String host, int port) throws IOException {
		return openChannel(new us.bringardner.parley.ssh.connection.ForwardingChannel(
				us.bringardner.parley.ssh.connection.ForwardingChannel.DIRECT, host, port, "127.0.0.1", 0));
	}

	/**
	 * ssh -L: listen on bindHost:bindPort here, and send each connection to host:port as the 
	 * server sees it.
	 * 
	 * @param bindHost e.g. "localhost" (only this machine can use it)
	 * @param bindPort 0 for any free port (see getBoundPort)
	 */
	public PortForwarder startLocalForwarding(String bindHost, int bindPort, String host, int port) throws IOException {
		java.net.ServerSocket ss = new java.net.ServerSocket();
		ss.setReuseAddress(true);
		ss.bind(new java.net.InetSocketAddress(bindHost, bindPort));
		executor.execute(() -> {
			while( !ss.isClosed() ) {
				java.net.Socket s;
				try {
					s = ss.accept();
				} catch (IOException e) {
					break;
				}
				executor.execute(() -> {
					try {
						us.bringardner.parley.ssh.connection.ForwardingChannel ch = openChannel(new us.bringardner.parley.ssh.connection.ForwardingChannel(
								us.bringardner.parley.ssh.connection.ForwardingChannel.DIRECT, host, port,
								s.getInetAddress().getHostAddress(), s.getPort()));
						ch.bridge(s, executor);
					} catch (IOException | RuntimeException e) {
						logDebug("Forwarding to "+host+":"+port+" refused: "+e.getMessage());
						us.bringardner.parley.io.IoUtils.closeQuietly(s);
					}
				});
			}
		});
		return new PortForwarder() {
			@Override
			public int getBoundPort() {
				return ss.getLocalPort();
			}

			@Override
			public void close() {
				us.bringardner.parley.io.IoUtils.closeQuietly(ss);
			}
		};
	}

	/**
	 * ssh -R: ask the server to listen on bindHost:bindPort and send each connection back 
	 * here, to localHost:localPort.
	 * 
	 * @param bindHost on the server, e.g. "localhost"
	 * @param bindPort 0 for any free port (the server's choice, see getBoundPort)
	 * @throws IOException if the server refuses
	 */
	public PortForwarder startRemoteForwarding(String bindHost, int bindPort, String localHost, int localPort) throws IOException {
		SshBuffer reply = await(connection.sendGlobalRequest("tcpip-forward", true, new SshBuffer().putString(bindHost).putInt(bindPort)),
				channelTimeout, "tcpip-forward");
		if( reply == null ) {
			throw new SshException(SshConstants.SSH_DISCONNECT_BY_APPLICATION, "The server refused to listen on "+bindHost+":"+bindPort);
		}
		int bound = bindPort == 0 ? reply.getInt() : bindPort;
		remoteTargets.put(bound, localHost+":"+localPort);
		return new PortForwarder() {
			@Override
			public int getBoundPort() {
				return bound;
			}

			@Override
			public void close() {
				remoteTargets.remove(bound);
				if( isOpen() ) {
					connection.sendGlobalRequest("cancel-tcpip-forward", true, new SshBuffer().putString(bindHost).putInt(bound));
				}
			}
		};
	}

	/**
	 * The server reports a connection to a port it listens on for us (ssh -R).
	 */
	private us.bringardner.parley.ssh.connection.ForwardingChannel forwarded(SshBuffer data) throws IOException {
		String bindHost = data.getStringUtf8();
		int bound = data.getInt();
		String originHost = data.getStringUtf8();
		int originPort = data.getInt();
		String target = remoteTargets.get(bound);
		if( target == null ) {
			// Nothing asked for it: refused
			return null;
		}
		int i = target.lastIndexOf(':');
		String host = target.substring(0, i);
		int port = Integer.parseInt(target.substring(i+1));
		us.bringardner.parley.ssh.connection.ForwardingChannel ch = new us.bringardner.parley.ssh.connection.ForwardingChannel(
				us.bringardner.parley.ssh.connection.ForwardingChannel.FORWARDED, bindHost, bound, originHost, originPort);
		ch.setOnOpen(() -> executor.execute(() -> {
			java.net.Socket s = new java.net.Socket();
			try {
				s.connect(new java.net.InetSocketAddress(host, port), 10000);
				ch.bridge(s, executor);
			} catch (IOException e) {
				logDebug("Can't connect to "+target+": "+e.getMessage());
				us.bringardner.parley.io.IoUtils.closeQuietly(s);
				ch.close();
			}
		}));
		return ch;
	}

	/**
	 * @return completes with this session when the first key exchange is done (the host
	 * key is trusted), or fails with the reason
	 */
	public CompletableFuture<ClientSession> getReadyFuture() {
		return ready;
	}

	public String getHost() {
		return host;
	}

	public int getPort() {
		return port;
	}

	/**
	 * @return the server's host key, null until the key exchange checked it
	 */
	public PublicKey getServerHostKey() {
		return hostKey;
	}

	/**
	 * @return the host certificate the server identified itself with (null if it used a plain key)
	 */
	public SshCertificate getHostCertificate() {
		return hostCertificate;
	}

	/**
	 * Ask for a service, e.g. {@link SshConstants#SERVICE_USERAUTH}.
	 *
	 * @return completes when the server accepts it; fails if it refuses (it disconnects)
	 */
	public synchronized CompletableFuture<Void> requestService(String name) {
		CompletableFuture<Void> ret = new CompletableFuture<Void>();
		if( serviceRequest != null ) {
			ret.completeExceptionally(new IllegalStateException("A service request is already waiting for "+requestedService));
			return ret;
		}
		serviceRequest = ret;
		requestedService = name;
		try {
			send(SshBuffer.message(SshConstants.SSH_MSG_SERVICE_REQUEST).putString(name));
		} catch (IOException e) {
			serviceRequest = null;
			ret.completeExceptionally(e);
		}
		return ret;
	}

	// ------------------------------------------------------------------ user authentication

	/**
	 * Log in (RFC 4252), trying the methods in order (those the server allows) until one 
	 * succeeds. Asks for the ssh-userauth service first if needed. May be called again after 
	 * a failure, e.g. with other credentials.
	 * 
	 * @param user the user name on the server
	 * @param methods e.g. new PublicKeyAuth(keys), new PasswordAuth(password)
	 * @return completes once authenticated; fails with an SshException 
	 * (SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE) if no method worked, the session stays open
	 */
	public CompletableFuture<Void> authenticate(String user, IClientAuthMethod... methods) {
		UserAuthClient a;
		synchronized (this) {
			if( authenticated ) {
				CompletableFuture<Void> ret = new CompletableFuture<Void>();
				ret.completeExceptionally(new IllegalStateException("Already authenticated as "+authenticatedUser));
				return ret;
			}
			UserAuthClient old = auth;
			if( old != null && !old.getResult().isDone() ) {
				CompletableFuture<Void> ret = new CompletableFuture<Void>();
				ret.completeExceptionally(new IllegalStateException("Authentication is already running"));
				return ret;
			}
			a = new UserAuthClient(this, user, java.util.Arrays.asList(methods));
			auth = a;
		}
		CompletableFuture<Void> service = userAuthAccepted ? CompletableFuture.completedFuture(null)
				: requestService(SshConstants.SERVICE_USERAUTH);
		service.whenComplete((v, error) -> {
			if( error != null ) {
				a.fail(error);
				return;
			}
			userAuthAccepted = true;
			try {
				a.start();
			} catch (IOException e) {
				a.fail(e);
			}
		});
		return a.getResult().thenRun(() -> {
			authenticatedUser = user;
			authenticated = true;
		});
	}

	/**
	 * {@link #authenticate(String, IClientAuthMethod...)} and wait (up to the auth timeout).
	 * 
	 * @throws IOException why it failed (an SshException)
	 */
	public void authenticateAndWait(String user, IClientAuthMethod... methods) throws IOException {
		await(authenticate(user, methods), authTimeout, "Authentication");
	}

	/**
	 * Log in with a password ("password", then "keyboard-interactive" for PAM servers).
	 */
	public void authPassword(String user, char[] password) throws IOException {
		authenticateAndWait(user, new PasswordAuth(password), KeyboardInteractiveAuth.password(password));
	}

	/**
	 * Log in with keys ("publickey").
	 */
	public void authPublicKey(String user, java.security.KeyPair... keys) throws IOException {
		authenticateAndWait(user, new PublicKeyAuth(keys));
	}

	public boolean isAuthenticated() {
		return authenticated;
	}

	/**
	 * @return the user name that logged in, null before
	 */
	public String getAuthenticatedUser() {
		return authenticatedUser;
	}

	/**
	 * @param listener gets the server's SSH_MSG_USERAUTH_BANNER text (e.g. a legal notice); 
	 * without one, banners are logged
	 */
	public void setBannerListener(Consumer<String> listener) {
		this.bannerListener = listener;
	}

	public long getAuthTimeout() {
		return authTimeout;
	}

	public void setAuthTimeout(long milliSeconds) {
		this.authTimeout = milliSeconds;
	}

	/**
	 * @return the signature algorithms the server accepts for public keys (RFC 8308 
	 * server-sig-algs), empty if it didn't say
	 */
	public List<String> getServerSignatureAlgorithms() {
		byte[] v = getPeerExtensions().get("server-sig-algs");
		if( v == null ) {
			return Collections.emptyList();
		}
		return java.util.Arrays.asList(new String(v, java.nio.charset.StandardCharsets.US_ASCII).split(","));
	}

	@Override
	protected boolean isAutomaticRekeyAllowed() {
		return authenticated;
	}

	static <T> T await(CompletableFuture<T> f, long timeout, String what) throws IOException {
		try {
			return timeout > 0 ? f.get(timeout, TimeUnit.MILLISECONDS) : f.get();
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new java.io.InterruptedIOException(what+" interrupted");
		} catch (TimeoutException e) {
			throw new java.net.SocketTimeoutException(what+" took more than "+timeout+" ms");
		} catch (ExecutionException e) {
			Throwable cause = e.getCause();
			if( cause instanceof IOException ) {
				throw (IOException) cause;
			}
			throw new IOException(what+" failed: "+cause, cause);
		}
	}

	private boolean handleAuthMessage(int msg, SshBuffer message) throws Exception {
		if( msg == SshConstants.SSH_MSG_USERAUTH_BANNER ) {
			String text = message.getStringUtf8();
			Consumer<String> l = bannerListener;
			if( l != null ) {
				l.accept(text);
			} else {
				logInfo("Banner from "+host+": "+text);
			}
			return true;
		}
		UserAuthClient a = auth;
		if( a == null || a.getResult().isDone() ) {
			throw new SshException("Unexpected "+SshConstants.messageName(msg));
		}
		switch (msg) {
		case SshConstants.SSH_MSG_USERAUTH_SUCCESS:
			startDelayedCompression();
			a.onSuccess();
			return true;
		case SshConstants.SSH_MSG_USERAUTH_FAILURE:
			List<String> canContinue = message.getNameList();
			boolean partial = message.getBoolean();
			a.onFailure(canContinue, partial);
			return true;
		default:
			if( !a.handle(msg, message) ) {
				throw new SshException("Unexpected "+SshConstants.messageName(msg)+" during authentication");
			}
			return true;
		}
	}

	// ------------------------------------------------------------------ channels

	/**
	 * @return the connection protocol: open other channel types, send global requests, 
	 * accept channels the server opens
	 */
	public ConnectionService getConnectionService() {
		return connection;
	}

	/**
	 * Open a "session" channel (for exec, shell or a subsystem). Needs a login first.
	 */
	public SessionChannel openSession() throws IOException {
		return openChannel(new SessionChannel());
	}

	/**
	 * Open a channel and wait for the server to confirm it.
	 */
	public <C extends us.bringardner.parley.ssh.connection.SshChannel> C openChannel(C channel) throws IOException {
		if( !authenticated ) {
			throw new IllegalStateException("Not authenticated");
		}
		return await(connection.open(channel), channelTimeout, "Opening a "+channel.getType()+" channel");
	}

	/**
	 * Run a command and collect what it writes, like "ssh host command".
	 * 
	 * @param command the command line
	 * @param stdin sent to the command, then EOF; null for none
	 * @param timeout ms for the whole run, 0 for no limit
	 * @throws IOException if the channel or the command can't start, or the time runs out
	 */
	public ExecResult exec(String command, byte[] stdin, long timeout) throws IOException {
		SessionChannel ch = openSession();
		Thread writer = null;
		try {
			ch.exec(command);
			if( stdin != null && stdin.length > 0 ) {
				// Written while the output is read: a command that echoes its input (cat) would
				// otherwise fill our window and stop reading, and the write would wait forever
				writer = new Thread(() -> {
					try {
						ch.getOutputStream().write(stdin);
						ch.sendEof();
					} catch (IOException e) {
						logDebug("Writing stdin of '"+command+"' failed", e);
					}
				}, "SshExec-stdin");
				writer.setDaemon(true);
				writer.start();
			} else {
				ch.sendEof();
			}
			java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
			java.io.ByteArrayOutputStream err = new java.io.ByteArrayOutputStream();
			long start = System.currentTimeMillis();
			ch.drain(out, err, timeout);
			long left = timeout > 0 ? Math.max(1, timeout-(System.currentTimeMillis()-start)) : Long.MAX_VALUE;
			// exit-status may come just after EOF
			if( !ch.waitForClose(left, TimeUnit.MILLISECONDS) ) {
				throw new java.net.SocketTimeoutException("'"+command+"' didn't finish within "+timeout+" ms");
			}
			return new ExecResult(ch.getExitStatus(), ch.getExitSignal(), out.toByteArray(), err.toByteArray());
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new java.io.InterruptedIOException();
		} finally {
			ch.close();
			if( writer != null ) {
				// The closed channel wakes a writer waiting for the window
				writer.interrupt();
			}
		}
	}

	public long getChannelTimeout() {
		return channelTimeout;
	}

	/**
	 * @param milliSeconds how long opening a channel waits for the server
	 */
	public void setChannelTimeout(long milliSeconds) {
		this.channelTimeout = milliSeconds;
	}

	public int getMaxKeepAliveFailures() {
		return maxKeepAliveFailures;
	}

	/**
	 * @param n disconnect after this many keep-alives in a row get no answer
	 */
	public void setMaxKeepAliveFailures(int n) {
		this.maxKeepAliveFailures = n;
	}

	/**
	 * Nothing came or went for the keep-alive interval (SshClient.setKeepAliveInterval): send 
	 * keepalive@openssh.com. Any answer (OpenSSH answers failure) shows the server is there.
	 */
	@Override
	public void onIdle(INioConnection c) {
		if( !isReady() || !isOpen() ) {
			c.close();
			return;
		}
		if( unansweredKeepAlives.incrementAndGet() > maxKeepAliveFailures ) {
			logError("No answer to "+maxKeepAliveFailures+" keep-alives from "+host+", disconnecting");
			disconnect(SshConstants.SSH_DISCONNECT_CONNECTION_LOST, "No answer to keep-alives");
			return;
		}
		connection.sendGlobalRequest("keepalive@openssh.com", true, null).whenComplete((r, error) -> {
			if( error == null ) {
				unansweredKeepAlives.set(0);
			}
		});
	}

	@Override
	protected boolean handleMessage(int msg, SshBuffer message) throws Exception {
		if( msg >= SshConstants.SSH_MSG_USERAUTH_REQUEST && msg < SshConstants.SSH_MSG_GLOBAL_REQUEST ) {
			return handleAuthMessage(msg, message);
		}
		if( msg >= SshConstants.SSH_MSG_GLOBAL_REQUEST && msg <= SshConstants.SSH_MSG_CHANNEL_FAILURE ) {
			if( !authenticated ) {
				throw new SshException("Unexpected "+SshConstants.messageName(msg)+" before authentication");
			}
			return connection.handle(msg, message);
		}
		if( msg == SshConstants.SSH_MSG_SERVICE_ACCEPT ) {
			String name = message.getStringUtf8();
			CompletableFuture<Void> f;
			synchronized (this) {
				if( serviceRequest == null || !name.equals(requestedService) ) {
					throw new SshException("Unexpected SERVICE_ACCEPT for "+name);
				}
				f = serviceRequest;
				serviceRequest = null;
				requestedService = null;
			}
			f.complete(null);
			return true;
		}
		return false;
	}

	@Override
	protected void onReady() {
		ready.complete(this);
	}

	@Override
	protected void onClosed(Throwable reason) {
		ready.completeExceptionally(reason);
		CompletableFuture<Void> f;
		synchronized (this) {
			f = serviceRequest;
			serviceRequest = null;
		}
		if( f != null ) {
			f.completeExceptionally(reason);
		}
		UserAuthClient a = auth;
		if( a != null ) {
			a.fail(reason);
		}
		connection.closeAll(reason);
	}

	/**
	 * Algorithms for key types already known for the host go first, so the server uses the
	 * key the verifier knows rather than one of another type (as OpenSSH does).
	 */
	@Override
	protected List<String> getHostKeyAlgorithmsToOffer() {
		List<String> all = super.getHostKeyAlgorithmsToOffer();
		List<String> known = verifier.getKnownKeyTypes(host, port);
		if( known.isEmpty() ) {
			return all;
		}
		List<String> first = new ArrayList<String>();
		List<String> rest = new ArrayList<String>();
		for (String name : all) {
			ISignatureAlgorithm s = getAlgorithms().findHostKeyAlgorithm(name);
			(s != null && known.contains(s.getKeyType()) ? first : rest).add(name);
		}
		first.addAll(rest);
		return first;
	}

	@Override
	protected void verifyHostKey(byte[] blob, byte[] signature, byte[] exchangeHash, String algorithm) throws IOException {
		ISignatureAlgorithm sig = getAlgorithms().findHostKeyAlgorithm(algorithm);
		if( sig == null ) {
			throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "No host key algorithm "+algorithm);
		}
		String type = SshPublicKeys.blobType(blob);
		if( !sig.getKeyType().equals(type) ) {
			throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Host key is "+type+", expected "+sig.getKeyType());
		}
		SshCertificate cert = SshCertificate.isCertificateType(type) ? SshCertificate.decode(blob) : null;
		PublicKey key = cert != null ? cert.getPublicKey() : SshPublicKeys.decode(blob);
		if( !sig.verify(key, exchangeHash, signature) ) {
			throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Bad host key signature");
		}
		byte[] known = hostKeyBlob;
		if( known == null ) {
			if( cert != null ? !verifier.verifyCertificate(host, port, cert) : !verifier.verify(host, port, key) ) {
				throw new SshException(SshConstants.SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE,
						"Host "+(cert != null ? "certificate " : "key ")+type+" "+SshPublicKeys.fingerprint(key)+" for "+host+" is not trusted");
			}
			hostKey = key;
			hostCertificate = cert;
			hostKeyBlob = blob.clone();
		} else if( !Arrays.equals(known, blob) ) {
			throw new SshException(SshConstants.SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, "The host key changed during re-keying");
		}
	}

	@Override
	public String toString() {
		return "ClientSession["+host+":"+port+(isReady() ? ", "+getNegotiated() : "")+"]";
	}
}
