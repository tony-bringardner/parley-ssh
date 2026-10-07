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
package us.bringardner.net.ssh.connection;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;

import us.bringardner.net.ssh.SshBuffer;

/**
 * A port forwarding channel (RFC 4254 7): "direct-tcpip" (ssh -L, the client asks the server
 * to connect) or "forwarded-tcpip" (ssh -R, the server tells the client about a connection).
 * The open data names the two ends; {@link #bridge(Socket, Executor)} copies between the
 * channel and a socket.
 *
 * @author Tony Bringardner
 */
public class ForwardingChannel extends SshChannel {

	public static final String DIRECT = "direct-tcpip";
	public static final String FORWARDED = "forwarded-tcpip";

	private final String host;
	private final int port;
	private final String originHost;
	private final int originPort;
	private volatile Runnable onOpen;

	/**
	 * @param type DIRECT or FORWARDED
	 * @param host DIRECT: where the server should connect; FORWARDED: the address that was connected to
	 * @param port its port
	 * @param originHost where the connection comes from
	 * @param originPort its port
	 */
	public ForwardingChannel(String type, String host, int port, String originHost, int originPort) {
		super(type);
		this.host = host;
		this.port = port;
		this.originHost = originHost;
		this.originPort = originPort;
	}

	public String getHost() {
		return host;
	}

	public int getPort() {
		return port;
	}

	public String getOriginHost() {
		return originHost;
	}

	public int getOriginPort() {
		return originPort;
	}

	@Override
	protected SshBuffer getOpenData() {
		return new SshBuffer().putString(host).putInt(port).putString(originHost).putInt(originPort);
	}

	/**
	 * @param task runs once the channel is open (e.g. connect the socket and bridge)
	 */
	public void setOnOpen(Runnable task) {
		this.onOpen = task;
	}

	@Override
	protected void onOpen() {
		Runnable r = onOpen;
		if( r != null ) {
			r.run();
		}
	}

	/**
	 * Copy the socket's data to the channel and the channel's to the socket, on two threads
	 * of the executor. EOF on one side is passed on (EOF / shutdownOutput); when both
	 * directions are done, or either side fails, both are closed.
	 */
	public void bridge(Socket socket, Executor executor) {
		AtomicInteger open = new AtomicInteger(2);
		Runnable done = () -> {
			if( open.decrementAndGet() == 0 ) {
				close();
				try {
					socket.close();
				} catch (IOException e) {
					// closed
				}
			}
		};
		getCloseFuture().whenComplete((v, e) -> {
			try {
				socket.close();
			} catch (IOException ex) {
				// closed
			}
		});
		executor.execute(() -> {
			try {
				copy(socket.getInputStream(), getOutputStream());
				sendEof();
				done.run();
			} catch (IOException e) {
				fail(socket);
			}
		});
		executor.execute(() -> {
			try {
				OutputStream out = socket.getOutputStream();
				copy(getInputStream(), out);
				socket.shutdownOutput();
				done.run();
			} catch (IOException e) {
				fail(socket);
			}
		});
	}

	private void fail(Socket socket) {
		close();
		try {
			socket.close();
		} catch (IOException e) {
			// closed
		}
	}

	private static void copy(InputStream in, OutputStream out) throws IOException {
		byte[] b = new byte[32*1024];
		int n;
		while( (n = in.read(b)) > 0 ) {
			out.write(b, 0, n);
			out.flush();
		}
	}
}
