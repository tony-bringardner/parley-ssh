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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import us.bringardner.core.BaseObject;
import us.bringardner.io.IoUtils;
import us.bringardner.net.ssh.SshBuffer;
import us.bringardner.net.ssh.connection.ConnectionService;
import us.bringardner.net.ssh.connection.ForwardingChannel;

/**
 * Port forwarding for one server session: "direct-tcpip" channels (ssh -L: the server
 * connects for the client) and "tcpip-forward" requests (ssh -R: the server listens and
 * tells the client about each connection with a "forwarded-tcpip" channel). Only with the
 * server's {@link IForwardingFilter} saying yes (and the "forward" permission).
 *
 * @author Tony Bringardner
 */
class ServerForwarding extends BaseObject {

	private static final int CONNECT_TIMEOUT = 10000;

	private final ServerSession session;
	private final Map<String, ServerSocket> listeners = new ConcurrentHashMap<String, ServerSocket>();

	ServerForwarding(ServerSession session) {
		this.session = session;
		ConnectionService c = session.getConnectionService();
		c.addChannelFactory(ForwardingChannel.DIRECT, (type, data) -> direct(data));
		c.addGlobalRequestHandler("tcpip-forward", (request, data) -> listen(data));
		c.addGlobalRequestHandler("cancel-tcpip-forward", (request, data) -> cancel(data));
	}

	private IForwardingFilter filter() {
		IForwardingFilter f = session.getServer().getForwardingFilter();
		return f != null && session.isPermitted("forward") ? f : null;
	}

	private ForwardingChannel direct(SshBuffer data) throws IOException {
		String host = data.getStringUtf8();
		int port = data.getInt();
		String originHost = data.getStringUtf8();
		int originPort = data.getInt();
		IForwardingFilter f = filter();
		if( f == null || port < 1 || port > 65535 || !f.canConnect(session, host, port) ) {
			logInfo("Refused forwarding to "+host+":"+port+" for "+session.getUser());
			return null;
		}
		Socket socket = new Socket();
		try {
			socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT);
		} catch (IOException e) {
			IoUtils.closeQuietly(socket);
			logDebug("Forwarding to "+host+":"+port+" failed: "+e.getMessage());
			return null;
		}
		ForwardingChannel ch = new ForwardingChannel(ForwardingChannel.DIRECT, host, port, originHost, originPort);
		ch.setOnOpen(() -> ch.bridge(socket, session.getServer().getExecutor()));
		return ch;
	}

	private static String key(String bindHost, int port) {
		return bindHost+":"+port;
	}

	private SshBuffer listen(SshBuffer data) throws IOException {
		String bindHost = data.getStringUtf8();
		int port = data.getInt();
		IForwardingFilter f = filter();
		if( f == null || port < 0 || port > 65535 || !f.canListen(session, bindHost, port) ) {
			logInfo("Refused listening on "+bindHost+":"+port+" for "+session.getUser());
			return null;
		}
		ServerSocket ss = new ServerSocket();
		try {
			ss.setReuseAddress(true);
			ss.bind(new InetSocketAddress(address(bindHost), port));
		} catch (IOException e) {
			IoUtils.closeQuietly(ss);
			logDebug("Can't listen on "+bindHost+":"+port+": "+e.getMessage());
			return null;
		}
		int actual = ss.getLocalPort();
		listeners.put(key(bindHost, actual), ss);
		session.getServer().getExecutor().execute(() -> accept(ss, bindHost, actual));
		// The port is in the reply only if the client asked for any port (0)
		return port == 0 ? new SshBuffer().putInt(actual) : new SshBuffer();
	}

	/**
	 * "" , "0.0.0.0", "*" and "::" are every address; "localhost" the loopback address.
	 */
	private static InetAddress address(String bindHost) throws IOException {
		if( bindHost == null || bindHost.isEmpty() || bindHost.equals("0.0.0.0") || bindHost.equals("*") || bindHost.equals("::") ) {
			return null;
		}
		if( bindHost.equalsIgnoreCase("localhost") ) {
			return InetAddress.getLoopbackAddress();
		}
		return InetAddress.getByName(bindHost);
	}

	private void accept(ServerSocket ss, String bindHost, int port) {
		while( !ss.isClosed() ) {
			Socket s;
			try {
				s = ss.accept();
			} catch (IOException e) {
				break;
			}
			if( !session.isOpen() ) {
				IoUtils.closeQuietly(s);
				break;
			}
			ForwardingChannel ch = new ForwardingChannel(ForwardingChannel.FORWARDED, bindHost, port,
					s.getInetAddress().getHostAddress(), s.getPort());
			ch.setOnOpen(() -> ch.bridge(s, session.getServer().getExecutor()));
			session.getConnectionService().open(ch).whenComplete((c, error) -> {
				if( error != null ) {
					IoUtils.closeQuietly(s);
				}
			});
		}
	}

	private SshBuffer cancel(SshBuffer data) throws IOException {
		String bindHost = data.getStringUtf8();
		int port = data.getInt();
		ServerSocket ss = listeners.remove(key(bindHost, port));
		if( ss == null ) {
			return null;
		}
		IoUtils.closeQuietly(ss);
		return new SshBuffer();
	}

	/**
	 * The session is over: stop listening.
	 */
	void close() {
		List<ServerSocket> all = new ArrayList<ServerSocket>(listeners.values());
		listeners.clear();
		for (ServerSocket ss : all) {
			IoUtils.closeQuietly(ss);
		}
	}
}
