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
import java.util.concurrent.TimeUnit;

import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.connection.SshChannel;

/**
 * A "session" channel (RFC 4254 6), the client side: optionally a pseudo terminal and
 * environment variables, then one of exec (a command), shell or subsystem (e.g. "sftp").
 * The program's stdin is {@link #getOutputStream()}, its stdout {@link #getInputStream()} and
 * its stderr {@link #getErrorStream()}; {@link #getExitStatus()} is set when it ends.
 *
 * <pre>
 * SessionChannel ch = session.openSession();
 * ch.exec("ls -l");
 * ... read ch.getInputStream() ...
 * Integer status = ch.waitForExit(10, TimeUnit.SECONDS);
 * </pre>
 *
 * @author Tony Bringardner
 */
public class SessionChannel extends SshChannel {

	/** TTY_OP_END: no terminal modes */
	private static final byte[] NO_MODES = {0};

	private volatile Integer exitStatus;
	private volatile String exitSignal;
	private volatile String exitSignalMessage;
	private volatile long requestTimeout = 30000;

	public SessionChannel() {
		super("session");
	}

	public SessionChannel(int window, int maxPacket) {
		super("session", window, maxPacket);
	}

	// ------------------------------------------------------------------ requests

	/**
	 * Ask for a pseudo terminal (before shell or exec), e.g. for an interactive shell.
	 *
	 * @param term e.g. "xterm-256color"
	 * @param modes encoded terminal modes (RFC 4254 8), or null for none
	 */
	public void requestPty(String term, int columns, int rows, int widthPixels, int heightPixels, byte[] modes) throws IOException {
		SshBuffer b = new SshBuffer().putString(term).putInt(columns).putInt(rows).putInt(widthPixels).putInt(heightPixels)
				.putString(modes == null ? NO_MODES : modes);
		request("pty-req", b);
	}

	public void requestPty(String term, int columns, int rows) throws IOException {
		requestPty(term, columns, rows, 0, 0, null);
	}

	/**
	 * Set an environment variable for the program (before shell or exec). Servers usually
	 * allow only a few (OpenSSH: AcceptEnv); a refusal is not an error.
	 *
	 * @return true if the server accepted it
	 */
	public boolean setEnv(String name, String value) throws IOException {
		return ask("env", new SshBuffer().putString(name).putString(value));
	}

	/**
	 * Run a command.
	 * @throws SshException if the server refuses
	 */
	public void exec(String command) throws IOException {
		request("exec", new SshBuffer().putString(command));
	}

	/**
	 * Start the user's shell.
	 */
	public void shell() throws IOException {
		request("shell", null);
	}

	/**
	 * Start a subsystem, e.g. "sftp".
	 */
	public void subsystem(String name) throws IOException {
		request("subsystem", new SshBuffer().putString(name));
	}

	/**
	 * The terminal size changed (no reply).
	 */
	public void windowChange(int columns, int rows, int widthPixels, int heightPixels) throws IOException {
		sendRequest("window-change", false, new SshBuffer().putInt(columns).putInt(rows).putInt(widthPixels).putInt(heightPixels));
	}

	/**
	 * Send a signal to the program, e.g. "INT" or "TERM" (no reply; many servers ignore it).
	 */
	public void signal(String name) throws IOException {
		sendRequest("signal", false, new SshBuffer().putString(name));
	}

	private void request(String request, SshBuffer data) throws IOException {
		if( !ask(request, data) ) {
			throw new SshException(us.bringardner.parley.ssh.SshConstants.SSH_DISCONNECT_BY_APPLICATION, "The server refused "+request);
		}
	}

	private boolean ask(String request, SshBuffer data) throws IOException {
		return ClientSession.await(sendRequest(request, true, data), requestTimeout, request);
	}

	// ------------------------------------------------------------------ exit

	@Override
	protected boolean handleRequest(String request, boolean wantReply, SshBuffer data) throws IOException {
		switch (request) {
		case "exit-status":
			exitStatus = data.getInt();
			return true;
		case "exit-signal":
			exitSignal = data.getStringUtf8();
			data.getBoolean();
			exitSignalMessage = data.getStringUtf8();
			return true;
		default:
			// e.g. keepalive@openssh.com: answered with failure, which is all it needs
			return false;
		}
	}

	/**
	 * @return the program's exit status, null until it ends (or if it was killed by a signal)
	 */
	public Integer getExitStatus() {
		return exitStatus;
	}

	/**
	 * @return the signal that killed the program (e.g. "KILL"), or null
	 */
	public String getExitSignal() {
		return exitSignal;
	}

	public String getExitSignalMessage() {
		return exitSignalMessage;
	}

	/**
	 * Wait for the channel to close (the program ended).
	 *
	 * @return the exit status, or null if it was killed by a signal or the time ran out
	 */
	public Integer waitForExit(long timeout, TimeUnit unit) throws InterruptedException {
		waitForClose(timeout, unit);
		return exitStatus;
	}

	public long getRequestTimeout() {
		return requestTimeout;
	}

	/**
	 * @param milliSeconds how long a request (exec, pty-req...) waits for the server's answer
	 */
	public void setRequestTimeout(long milliSeconds) {
		this.requestTimeout = milliSeconds;
	}
}
