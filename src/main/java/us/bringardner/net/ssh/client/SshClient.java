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

import java.io.Closeable;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import us.bringardner.core.BaseObject;
import us.bringardner.core.NamedThreadFactory;
import us.bringardner.net.framework.nio.LineFrameDecoder;
import us.bringardner.net.framework.nio.NioClient;
import us.bringardner.net.framework.server.Server;
import us.bringardner.net.ssh.SshConstants;
import us.bringardner.net.ssh.algorithms.SshAlgorithms;
import us.bringardner.net.ssh.transport.SshTransport;

/**
 * An SSH client, in the spirit of JSch's JSch and MINA's SshClient: configure it once, then
 * {@link #connect(String, int)} as many sessions as needed. Built on the framework's
 * non-blocking {@link NioClient}: one selector thread serves all of a client's sessions, and
 * their messages are handled on a small pool of threads.
 *
 * <pre>
 * try (SshClient client = new SshClient()) {
 *     ClientSession session = client.connectAndWait("example.com", 22);
 *     ...
 * }
 * </pre>
 *
 * By default the server's host key must be in ~/.ssh/known_hosts (see {@link KnownHosts}).
 *
 * @author Tony Bringardner
 */
public class SshClient extends BaseObject implements Closeable {

	/** How long connecting and the first key exchange may take (ms) */
	public static final long DEFAULT_CONNECT_TIMEOUT = 30000;

	private final NioClient nio;
	private final ExecutorService executor;
	private final SecureRandom random = new SecureRandom();
	private volatile SshAlgorithms algorithms = SshAlgorithms.defaults();
	private volatile IHostKeyVerifier hostKeyVerifier;
	private volatile String version = SshTransport.DEFAULT_VERSION;
	private volatile long connectTimeout = DEFAULT_CONNECT_TIMEOUT;
	private volatile long keepAliveInterval;

	public SshClient() {
		getLogger().setLevel(Server.getDefaultLogLevel());
		nio = new NioClient("SshClient");
		executor = Executors.newCachedThreadPool(NamedThreadFactory.numbered("SshClient-"));
		nio.setHandlerExecutor(executor);
		// The transport has its own limits, the framework's must not cut packets short
		nio.setMaxInputBuffer(2*1024*1024);
	}

	/**
	 * Connect and run the key exchange.
	 *
	 * @return completes with the session once the host key is trusted and the keys are in use
	 */
	public CompletableFuture<ClientSession> connect(String host, int port) {
		ClientSession session = newSession(host, port);
		CompletableFuture<ClientSession> ret = session.getReadyFuture();
		long timeout = connectTimeout;
		if( timeout > 0 ) {
			ret.orTimeout(timeout, TimeUnit.MILLISECONDS);
		}
		ret.whenComplete((s, error) -> {
			if( error != null ) {
				session.disconnect(SshConstants.SSH_DISCONNECT_BY_APPLICATION, "Connect failed");
			}
		});
		// The identification line, then the transport switches to its packet decoder
		nio.connect(new InetSocketAddress(host, port), session, new LineFrameDecoder(1024)).whenComplete((c, error) -> {
			if( error != null ) {
				ret.completeExceptionally(error);
			}
		});
		return ret;
	}

	/**
	 * @return a new, not yet connected session; override to use a ClientSession subclass
	 */
	protected ClientSession newSession(String host, int port) {
		IHostKeyVerifier v = hostKeyVerifier;
		if( v == null ) {
			try {
				v = KnownHosts.userFile();
			} catch (IOException e) {
				throw new IllegalStateException("Can't read ~/.ssh/known_hosts: "+e.getMessage(), e);
			}
		}
		ClientSession s = new ClientSession(host, port, v, algorithms, version, random);
		s.setExecutor(executor);
		return s;
	}

	/**
	 * Connect and wait for the key exchange.
	 *
	 * @throws IOException why it failed (an SshException with the disconnect reason,
	 * SocketTimeoutException after the connect timeout)
	 */
	public ClientSession connectAndWait(String host, int port) throws IOException {
		CompletableFuture<ClientSession> f = connect(host, port);
		try {
			return f.get();
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			f.cancel(false);
			throw new InterruptedIOException("Interrupted while connecting to "+host);
		} catch (ExecutionException e) {
			Throwable cause = e.getCause();
			if( cause instanceof TimeoutException ) {
				throw new SocketTimeoutException("Connecting to "+host+":"+port+" took more than "+connectTimeout+" ms");
			}
			if( cause instanceof IOException ) {
				throw (IOException) cause;
			}
			throw new IOException("Can't connect to "+host+":"+port+": "+cause, cause);
		}
	}

	/**
	 * Close every session and stop the client's threads.
	 */
	@Override
	public void close() {
		nio.close();
		executor.shutdown();
	}

	/**
	 * @return the algorithms offered (a live object: change it before connecting)
	 */
	public SshAlgorithms getAlgorithms() {
		return algorithms;
	}

	public void setAlgorithms(SshAlgorithms algorithms) {
		this.algorithms = algorithms;
	}

	public IHostKeyVerifier getHostKeyVerifier() {
		return hostKeyVerifier;
	}

	/**
	 * @param verifier decides which host keys to trust; null (default) for ~/.ssh/known_hosts
	 * with unknown hosts refused
	 */
	public void setHostKeyVerifier(IHostKeyVerifier verifier) {
		this.hostKeyVerifier = verifier;
	}

	public String getVersion() {
		return version;
	}

	/**
	 * @param version the identification string, starting "SSH-2.0-"
	 */
	public void setVersion(String version) {
		this.version = version;
	}

	public long getKeepAliveInterval() {
		return keepAliveInterval;
	}

	/**
	 * @param milliSeconds send a keep-alive after this long without traffic, 0 (default) for 
	 * none; a session that doesn't answer three in a row is disconnected. Applies to new sessions.
	 */
	public void setKeepAliveInterval(long milliSeconds) {
		this.keepAliveInterval = milliSeconds;
		nio.setMaxIdleTime(milliSeconds);
	}

	public long getConnectTimeout() {
		return connectTimeout;
	}

	/**
	 * @param milliSeconds how long connecting and the first key exchange may take, 0 = no limit
	 */
	public void setConnectTimeout(long milliSeconds) {
		this.connectTimeout = milliSeconds;
		nio.setConnectTimeout((int) Math.min(Integer.MAX_VALUE, milliSeconds));
	}

	/**
	 * @return the framework client underneath, for socket options
	 */
	public NioClient getNioClient() {
		return nio;
	}
}
