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
import java.util.concurrent.atomic.AtomicBoolean;

import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.connection.SshChannel;

/**
 * The server side of a "session" channel (RFC 4254 6): records pty-req and env, then runs
 * one exec, shell or subsystem through the server's factories (refused if there is none, or
 * the user lacks the permission), and ends with exit-status, EOF and close.
 *
 * @author Tony Bringardner
 */
public class ServerSessionChannel extends SshChannel {

	private final ServerSession session;
	private final CommandEnvironment env;
	private final AtomicBoolean exited = new AtomicBoolean();
	private volatile ICommand command;
	// Made by handleRequest, started once the request is answered
	private ICommand toStart;
	private boolean started;

	public ServerSessionChannel(ServerSession session) {
		super("session");
		this.session = session;
		this.env = new CommandEnvironment(session.getServer(), session);
	}

	public CommandEnvironment getEnvironment() {
		return env;
	}

	@Override
	protected boolean handleRequest(String request, boolean wantReply, SshBuffer data) throws IOException {
		SshServer server = session.getServer();
		switch (request) {
		case "pty-req": {
			String term = data.getStringUtf8();
			int cols = data.getInt();
			int rows = data.getInt();
			data.getInt();
			data.getInt();
			env.setPty(term, cols, rows, data.getString());
			return true;
		}
		case "env":
			env.setEnv(data.getStringUtf8(), data.getStringUtf8());
			return true;
		case "exec": {
			String cmd = data.getStringUtf8();
			ICommandFactory f = server.getCommandFactory();
			return prepare(f == null ? null : f.create(cmd, env), "exec");
		}
		case "shell": {
			IShellFactory f = server.getShellFactory();
			return prepare(f == null ? null : f.create(env), "shell");
		}
		case "subsystem": {
			String name = data.getStringUtf8();
			ISubsystemFactory f = server.getSubsystem(name);
			return prepare(f == null ? null : f.create(env), name);
		}
		case "window-change": {
			int cols = data.getInt();
			int rows = data.getInt();
			env.windowChange(cols, rows);
			return true;
		}
		case "signal":
			env.signal(data.getStringUtf8());
			return true;
		default:
			return false;
		}
	}

	/**
	 * @param permission what the user needs: "exec", "shell" or the subsystem's name
	 */
	private boolean prepare(ICommand c, String permission) {
		if( started || c == null || !session.isPermitted(permission) ) {
			return false;
		}
		started = true;
		toStart = c;
		return true;
	}

	@Override
	protected void onRequestDone(String request, boolean success) throws IOException {
		ICommand c = toStart;
		if( c == null ) {
			return;
		}
		toStart = null;
		command = c;
		try {
			c.start(env, getInputStream(), getOutputStream(), getExtendedOutputStream(), this::exit);
		} catch (IOException | RuntimeException e) {
			exit(1);
			throw e;
		}
	}

	/**
	 * The command is done: exit-status, then EOF and close.
	 */
	private void exit(int status) {
		if( !exited.compareAndSet(false, true) ) {
			return;
		}
		if( isOpen() ) {
			sendRequest("exit-status", false, new SshBuffer().putInt(status & 0xffffffffL));
			try {
				sendEof();
			} catch (IOException e) {
				// closing anyway
			}
		}
		close();
	}

	@Override
	protected void onClosed() {
		ICommand c = command;
		if( c != null && !exited.get() ) {
			c.destroy();
		}
	}
}
