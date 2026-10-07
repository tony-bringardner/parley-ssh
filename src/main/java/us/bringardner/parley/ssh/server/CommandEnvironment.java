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

import java.net.SocketAddress;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

import us.bringardner.parley.net.server.IPrincipal;

/**
 * What a command, shell or subsystem knows about its session: the user, the client's
 * environment variables, the terminal (if it asked for one), and signals and window size
 * changes as they come.
 *
 * @author Tony Bringardner
 */
public class CommandEnvironment {

	private final SshServer server;
	private final ServerSession session;
	private final Map<String, String> env = new LinkedHashMap<String, String>();
	private volatile String term;
	private volatile int columns;
	private volatile int rows;
	private volatile byte[] terminalModes;
	private final List<Consumer<String>> signalListeners = new CopyOnWriteArrayList<Consumer<String>>();
	private final List<Runnable> windowListeners = new CopyOnWriteArrayList<Runnable>();

	CommandEnvironment(SshServer server, ServerSession session) {
		this.server = server;
		this.session = session;
	}

	public SshServer getServer() {
		return server;
	}

	public ServerSession getSession() {
		return session;
	}

	public String getUser() {
		return session.getUser();
	}

	public IPrincipal getPrincipal() {
		return session.getPrincipal();
	}

	public SocketAddress getRemoteAddress() {
		return session.getConnection().getRemoteAddress();
	}

	/**
	 * @return the variables the client sent with "env" requests (a copy)
	 */
	public synchronized Map<String, String> getEnv() {
		return Collections.unmodifiableMap(new LinkedHashMap<String, String>(env));
	}

	synchronized void setEnv(String name, String value) {
		env.put(name, value);
	}

	/**
	 * @return true if the client asked for a pseudo terminal
	 */
	public boolean hasPty() {
		return term != null;
	}

	/**
	 * @return the terminal type, e.g. "xterm-256color", or null without a pty
	 */
	public String getTerm() {
		return term;
	}

	public int getColumns() {
		return columns;
	}

	public int getRows() {
		return rows;
	}

	/**
	 * @return the encoded terminal modes of pty-req (RFC 4254 8)
	 */
	public byte[] getTerminalModes() {
		return terminalModes == null ? new byte[0] : terminalModes.clone();
	}

	void setPty(String term, int columns, int rows, byte[] modes) {
		this.term = term;
		this.columns = columns;
		this.rows = rows;
		this.terminalModes = modes;
	}

	void windowChange(int columns, int rows) {
		this.columns = columns;
		this.rows = rows;
		for (Runnable r : windowListeners) {
			r.run();
		}
	}

	void signal(String name) {
		for (Consumer<String> l : signalListeners) {
			l.accept(name);
		}
	}

	/**
	 * @param listener gets the signal name (e.g. "INT") when the client sends one
	 */
	public void addSignalListener(Consumer<String> listener) {
		signalListeners.add(listener);
	}

	/**
	 * @param listener runs when the terminal size changes (see getColumns, getRows)
	 */
	public void addWindowChangeListener(Runnable listener) {
		windowListeners.add(listener);
	}
}
