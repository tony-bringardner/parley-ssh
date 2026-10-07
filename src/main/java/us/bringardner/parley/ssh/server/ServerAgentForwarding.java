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
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.concurrent.TimeUnit;

import us.bringardner.parley.core.BaseObject;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.client.SshAgent;
import us.bringardner.parley.ssh.connection.AgentChannel;
import us.bringardner.parley.ssh.connection.UnixSockets;

/**
 * A session's forwarded agent (ssh -A), as OpenSSH's sshd does it: a Unix socket in a
 * directory only the server's account can read, named by SSH_AUTH_SOCK for the session's
 * commands; each connection to it is an "auth-agent@openssh.com" channel to the client,
 * which passes it to its agent. Java code reaches the agent with {@link #open()}. The socket
 * and its directory are removed when the session ends.
 * <p>
 * The socket needs Java 16+; on older JVMs only {@link #open()} works.
 *
 * @author Tony Bringardner
 */
final class ServerAgentForwarding extends BaseObject {

	private static final long OPEN_TIMEOUT = 30000;

	private final ServerSession session;
	private volatile boolean enabled;
	private volatile boolean closed;
	private ServerSocketChannel listener;
	private Path dir;
	private String socketPath;

	ServerAgentForwarding(ServerSession session) {
		this.session = session;
	}

	/**
	 * The client asked for it (and it is allowed).
	 *
	 * @return the socket's path, or null if this JVM can't make one
	 */
	synchronized String enable() throws IOException {
		if( closed ) {
			throw new SshException("The session is closed");
		}
		enabled = true;
		if( socketPath != null || !UnixSockets.isSupported() ) {
			return socketPath;
		}
		Path d;
		try {
			d = Files.createTempDirectory("ssh-agent-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
		} catch (UnsupportedOperationException e) {
			d = Files.createTempDirectory("ssh-agent-");
		}
		String path = d.resolve("agent.sock").toString();
		ServerSocketChannel l;
		try {
			l = UnixSockets.listen(path);
		} catch (IOException e) {
			Files.deleteIfExists(d);
			throw e;
		}
		dir = d;
		listener = l;
		socketPath = path;
		session.getServer().getExecutor().execute(this::accept);
		logDebug(() -> "Agent forwarding for "+session.getUser()+" on "+path);
		return path;
	}

	boolean isEnabled() {
		return enabled;
	}

	String getSocketPath() {
		return socketPath;
	}

	private void accept() {
		ServerSocketChannel l = listener;
		while( !closed && session.isOpen() ) {
			SocketChannel c;
			try {
				c = l.accept();
			} catch (IOException e) {
				break;
			}
			AgentChannel ch = new AgentChannel();
			ch.setOnOpen(() -> ch.bridge(UnixSockets.inputStream(c), UnixSockets.outputStream(c), c, session.getServer().getExecutor()));
			session.getConnectionService().open(ch).whenComplete((v, error) -> {
				if( error != null ) {
					try {
						c.close();
					} catch (IOException e) {
						// closed
					}
				}
			});
		}
	}

	/**
	 * @return the client's agent, through a new channel
	 * @throws SshException if agent forwarding wasn't asked for, or the client refuses
	 */
	SshAgent open() throws IOException {
		if( !enabled || closed ) {
			throw new SshException("The client didn't forward its agent");
		}
		AgentChannel ch = new AgentChannel();
		try {
			session.getConnectionService().open(ch).get(OPEN_TIMEOUT, TimeUnit.MILLISECONDS);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new java.io.InterruptedIOException("Opening the agent channel");
		} catch (Exception e) {
			throw new SshException("The client refused the agent channel: "+e.getMessage());
		}
		return SshAgent.over(ch.getInputStream(), ch.getOutputStream(), ch::close);
	}

	/**
	 * The session is over: stop listening, remove the socket.
	 */
	synchronized void close() {
		closed = true;
		if( listener != null ) {
			try {
				listener.close();
			} catch (IOException e) {
				// closed
			}
			try {
				Files.deleteIfExists(new File(socketPath).toPath());
				Files.deleteIfExists(dir);
			} catch (IOException e) {
				logDebug("Can't remove "+dir+": "+e.getMessage());
			}
			listener = null;
		}
	}
}
