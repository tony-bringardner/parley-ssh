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

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;

import us.bringardner.parley.core.NamedThreadFactory;
import us.bringardner.parley.net.nio.LineFrameDecoder;
import us.bringardner.parley.net.nio.NioServer;
import us.bringardner.parley.ssh.algorithms.SshAlgorithms;
import us.bringardner.parley.ssh.transport.SshTransport;

/**
 * An SSH server on the framework's non-blocking {@link NioServer}, so it is configured like
 * any Parley server (Port, BindAddress, MaxConnections, the key store settings...) and logs
 * users in with the same access control list.
 * <p>
 * <b>What it runs</b> is up to the plug-ins: {@link #setCommandFactory(ICommandFactory)} for
 * exec, {@link #setShellFactory(IShellFactory)} (or the {@value #PROPERTY_SHELL_FACTORY}
 * property) for an interactive shell,
 * {@link #addSubsystem(ISubsystemFactory)} for subsystems such as SFTP. Without them those
 * requests are refused. With an access control list, a user also needs the permission
 * ("exec", "shell", or the subsystem name).
 * <p>
 * <b>Logging in</b>: password and keyboard-interactive through the access control list (or
 * {@link #setPasswordAuthenticator(IPasswordAuthenticator)}), publickey through
 * {@link #setPublicKeyAuthenticator(IPublicKeyAuthenticator)} (e.g.
 * {@link AuthorizedKeysAuthenticator}), or any {@link IServerAuthMethod}s. At most
 * {@link #setMaxLoginAttempts(int)} failures, each answered after
 * {@link #setLoginFailureDelay(int)}, within {@link #setLoginTimeLimit(int)} (OpenSSH's
 * defaults: 6 tries, 2 minutes; 250 ms delay).
 * <p>
 * <b>Host keys</b> come from {@link #setHostKeyProvider(IHostKeyProvider)}; else from the key
 * store when KeyStoreName is set; else they are made once in the HostKeyDir property's
 * directory (default ".") like ssh-keygen -A.
 *
 * <pre>
 * SshServer server = new SshServer(2222);
 * server.setHostKeyProvider(HostKeyProviders.generated(new File("/var/myapp/ssh")));
 * server.setPublicKeyAuthenticator(AuthorizedKeysAuthenticator.forHomes(new File("/home")));
 * server.addSubsystem(new SftpSubsystemFactory(...));
 * server.startAndWait(10000);
 * </pre>
 *
 * @author Tony Bringardner
 */
public class SshServer extends NioServer {

	public static final String PROPERTY_HOST_KEY_DIR = "HostKeyDir";
	/** Class name of the {@link IShellFactory} to use (public no-argument constructor), e.g. a factory from fsh, the FileSource Shell */
	public static final String PROPERTY_SHELL_FACTORY = "ShellFactory";
	/** Like OpenSSH's MaxAuthTries: clients try each of their keys, and each refused key counts */
	public static final int DEFAULT_MAX_AUTH_TRIES = 6;
	/** Like OpenSSH's LoginGraceTime */
	public static final int DEFAULT_LOGIN_GRACE_TIME = 120000;
	/** Short, because refused keys are failures too */
	public static final int DEFAULT_AUTH_FAILURE_DELAY = 250;

	private final SecureRandom random = new SecureRandom();
	private final ExecutorService executor = Executors.newCachedThreadPool(NamedThreadFactory.numbered("SshServer-"));
	private final ScheduledExecutorService scheduler;
	private volatile SshAlgorithms algorithms = SshAlgorithms.defaults();
	private volatile String version = SshTransport.DEFAULT_VERSION;
	private volatile IHostKeyProvider hostKeyProvider;
	private volatile List<KeyPair> hostKeys = Collections.emptyList();
	private volatile List<IServerAuthMethod> authMethods;
	private volatile IPasswordAuthenticator passwordAuthenticator;
	private volatile IPublicKeyAuthenticator publicKeyAuthenticator;
	private volatile ICommandFactory commandFactory;
	private volatile IShellFactory shellFactory;
	private volatile boolean shellFactoryConfigured;
	private final Map<String, ISubsystemFactory> subsystems = new ConcurrentHashMap<String, ISubsystemFactory>();
	private volatile String banner;
	private volatile int maxChannelsPerSession = 10;
	private volatile IForwardingFilter forwardingFilter;

	public SshServer() {
		this(22);
	}

	public SshServer(int port) {
		super(port);
		ScheduledThreadPoolExecutor s = new ScheduledThreadPoolExecutor(1, new NamedThreadFactory("SshServer-scheduler"));
		s.setRemoveOnCancelPolicy(true);
		scheduler = s;
		setHandlerFactory(() -> new ServerSession(this));
		// The identification line; the transport then switches to its packet decoder
		setDecoderFactory(() -> new LineFrameDecoder(1024));
		// Logins (password hashing), commands and file access block: not on the selector threads
		setHandlerExecutor(executor);
		setMaxInputBuffer(2*1024*1024);
	}

	/**
	 * Read the host keys and the configured shell, then start.
	 *
	 * @throws IOException if there are no host keys (or they can't be read), the
	 * {@value #PROPERTY_SHELL_FACTORY} property names a class that can't be made, or the server doesn't start
	 */
	@Override
	public void startAndWait(long timeoutMillis) throws IOException {
		loadHostKeys();
		try {
			getShellFactory();
		} catch (IllegalStateException e) {
			throw new IOException(e.getMessage(), e.getCause());
		}
		super.startAndWait(timeoutMillis);
	}

	/**
	 * Read the host keys and the configured shell, then start; a problem with them is logged and
	 * the server doesn't start.
	 */
	@Override
	public synchronized void start() {
		if( hostKeys.isEmpty() ) {
			try {
				loadHostKeys();
			} catch (IOException e) {
				logError("Can't load the host keys, server "+getName()+" not started", e);
				return;
			}
		}
		try {
			getShellFactory();
		} catch (IllegalStateException e) {
			logError("Server "+getName()+" not started: "+e.getMessage());
			return;
		}
		super.start();
	}

	private synchronized void loadHostKeys() throws IOException {
		IHostKeyProvider p = hostKeyProvider;
		if( p == null ) {
			if( getKeyStoreFileName() != null ) {
				p = HostKeyProviders.fromKeyStore(this);
			} else {
				p = HostKeyProviders.generated(new File(getProperty(PROPERTY_HOST_KEY_DIR, ".")));
			}
		}
		List<KeyPair> keys = p.getHostKeys();
		if( keys == null || keys.isEmpty() ) {
			throw new IOException("No host keys");
		}
		hostKeys = Collections.unmodifiableList(new ArrayList<KeyPair>(keys));
	}

	// ------------------------------------------------------------------ authentication

	/**
	 * @return the methods offered, in order: the ones set, else publickey (with a public key
	 * authenticator), then password and keyboard-interactive (with a password authenticator
	 * or an access control list)
	 */
	public List<IServerAuthMethod> getAuthMethods() {
		List<IServerAuthMethod> m = authMethods;
		if( m != null ) {
			return m;
		}
		List<IServerAuthMethod> ret = new ArrayList<IServerAuthMethod>();
		IPublicKeyAuthenticator pk = publicKeyAuthenticator;
		if( pk != null ) {
			ret.add(new PublicKeyAuthMethod(pk));
		}
		IPasswordAuthenticator pw = passwordAuthenticator;
		if( pw == null && getAccessControl() != null ) {
			pw = aclPasswordAuthenticator();
		}
		if( pw != null ) {
			ret.add(new PasswordAuthMethod(pw));
			ret.add(new KeyboardInteractiveAuthMethod(pw));
		}
		return Collections.unmodifiableList(ret);
	}

	public void setAuthMethods(List<IServerAuthMethod> methods) {
		this.authMethods = methods == null ? null : Collections.unmodifiableList(new ArrayList<IServerAuthMethod>(methods));
	}

	IServerAuthMethod findAuthMethod(String name) {
		for (IServerAuthMethod m : getAuthMethods()) {
			if( m.getName().equals(name) ) {
				return m;
			}
		}
		return null;
	}

	/**
	 * @return passwords checked by the access control list (as the framework's servers do)
	 */
	public IPasswordAuthenticator aclPasswordAuthenticator() {
		return (user, password, context) -> {
			byte[] b = new String(password).getBytes(StandardCharsets.UTF_8);
			try {
				return authenticate(user, b);
			} finally {
				java.util.Arrays.fill(b, (byte) 0);
			}
		};
	}

	public IPasswordAuthenticator getPasswordAuthenticator() {
		return passwordAuthenticator;
	}

	public void setPasswordAuthenticator(IPasswordAuthenticator authenticator) {
		this.passwordAuthenticator = authenticator;
	}

	public IPublicKeyAuthenticator getPublicKeyAuthenticator() {
		return publicKeyAuthenticator;
	}

	public void setPublicKeyAuthenticator(IPublicKeyAuthenticator authenticator) {
		this.publicKeyAuthenticator = authenticator;
	}

	// ------------------------------------------------------------------ plug-ins

	public ICommandFactory getCommandFactory() {
		return commandFactory;
	}

	/**
	 * @param factory runs "exec" requests; null (default) refuses them
	 */
	public void setCommandFactory(ICommandFactory factory) {
		this.commandFactory = factory;
	}

	/**
	 * @return the factory set with {@link #setShellFactory(IShellFactory)}, else one made from
	 * the {@value #PROPERTY_SHELL_FACTORY} property, else null (shell requests are refused)
	 * @throws IllegalStateException if the property names a class that can't be made
	 */
	public IShellFactory getShellFactory() {
		if( shellFactory == null && !shellFactoryConfigured ) {
			synchronized (this) {
				if( shellFactory == null && !shellFactoryConfigured ) {
					String tmp = getProperty(PROPERTY_SHELL_FACTORY);
					if( tmp != null && !tmp.trim().isEmpty() ) {
						try {
							Class<?> c = Class.forName(tmp.trim());
							shellFactory = (IShellFactory) c.getDeclaredConstructor().newInstance();
						} catch (Exception e) {
							logError("Can't configure shell factory class='"+tmp+"'", e);
							throw new IllegalStateException("Can't configure shell factory class='"+tmp+"'", e);
						}
					} else {
						logInfo("No shell defined in server "+getName());
					}
					shellFactoryConfigured = true;
				}
			}
		}
		return shellFactory;
	}

	/**
	 * @param factory runs "shell" requests; null to look at the {@value #PROPERTY_SHELL_FACTORY}
	 * property again on the next use (with no property, shell requests are refused)
	 */
	public void setShellFactory(IShellFactory factory) {
		this.shellFactory = factory;
		this.shellFactoryConfigured = factory != null;
	}

	public void addSubsystem(ISubsystemFactory factory) {
		subsystems.put(factory.getName(), factory);
	}

	public void removeSubsystem(String name) {
		subsystems.remove(name);
	}

	public ISubsystemFactory getSubsystem(String name) {
		return subsystems.get(name);
	}

	// ------------------------------------------------------------------ settings

	public SshAlgorithms getAlgorithms() {
		return algorithms;
	}

	public void setAlgorithms(SshAlgorithms algorithms) {
		this.algorithms = algorithms;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public SecureRandom getRandom() {
		return random;
	}

	public IHostKeyProvider getHostKeyProvider() {
		return hostKeyProvider;
	}

	public void setHostKeyProvider(IHostKeyProvider provider) {
		this.hostKeyProvider = provider;
		this.hostKeys = Collections.emptyList();
	}

	/**
	 * @return the host keys in use (empty until the server starts)
	 */
	public List<KeyPair> getHostKeys() {
		return hostKeys;
	}

	public String getBanner() {
		return banner;
	}

	/**
	 * @param banner text shown to users before they log in (e.g. a legal notice), null for none
	 */
	public void setBanner(String banner) {
		this.banner = banner;
	}

	// The login limits are the framework's (MaxLoginAttempts, LoginFailureDelay and
	// LoginTimeLimit, set like any server setting), with OpenSSH's defaults

	@Override
	protected int getDefaultMaxLoginAttempts() {
		return DEFAULT_MAX_AUTH_TRIES;
	}

	@Override
	protected int getDefaultLoginFailureDelay() {
		return DEFAULT_AUTH_FAILURE_DELAY;
	}

	@Override
	protected int getDefaultLoginTimeLimit() {
		return DEFAULT_LOGIN_GRACE_TIME;
	}

	public IForwardingFilter getForwardingFilter() {
		return forwardingFilter;
	}

	/**
	 * @param filter which port forwarding users may do; null (default) refuses all of it
	 */
	public void setForwardingFilter(IForwardingFilter filter) {
		this.forwardingFilter = filter;
	}

	public int getMaxChannelsPerSession() {
		return maxChannelsPerSession;
	}

	/**
	 * @param n channels one connection may have open at once (OpenSSH: 10)
	 */
	public void setMaxChannelsPerSession(int n) {
		this.maxChannelsPerSession = n;
	}

	/**
	 * @return the pool that runs logins, commands and subsystems
	 */
	public ExecutorService getExecutor() {
		return executor;
	}

	/**
	 * @return for timers (login time limit, failure delay)
	 */
	public ScheduledExecutorService getScheduler() {
		return scheduler;
	}
}
