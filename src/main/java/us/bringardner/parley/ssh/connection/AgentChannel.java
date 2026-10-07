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
package us.bringardner.parley.ssh.connection;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.Executor;

/**
 * An agent forwarding channel ("auth-agent@openssh.com", OpenSSH's PROTOCOL.agent): the
 * server opens one to the client for each connection to the forwarded agent, and the client
 * connects it to its own agent. The data is the agent protocol, passed through unchanged.
 *
 * @author Tony Bringardner
 */
public class AgentChannel extends SshChannel {

	public static final String TYPE = "auth-agent@openssh.com";
	/** The session channel request that asks for agent forwarding */
	public static final String REQUEST = "auth-agent-req@openssh.com";

	private volatile Runnable onOpen;

	public AgentChannel() {
		super(TYPE);
	}

	/**
	 * @param task runs once the channel is open
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
	 * Copy between the channel and an agent connection on two threads of the executor; when
	 * either side ends, both are closed.
	 *
	 * @param closeable closes the agent connection
	 */
	public void bridge(InputStream in, OutputStream out, Closeable closeable, Executor executor) {
		// Request and answer: when either side ends there is nothing left to pass on
		Runnable done = () -> {
			close();
			closeQuietly(closeable);
		};
		getCloseFuture().whenComplete((v, e) -> closeQuietly(closeable));
		executor.execute(() -> {
			try {
				copy(in, getOutputStream());
				sendEof();
			} catch (IOException e) {
				// ended
			}
			done.run();
		});
		executor.execute(() -> {
			try {
				copy(getInputStream(), out);
			} catch (IOException e) {
				// ended
			}
			done.run();
		});
	}

	private static void closeQuietly(Closeable c) {
		try {
			c.close();
		} catch (IOException e) {
			// closed
		}
	}

	private static void copy(InputStream in, OutputStream out) throws IOException {
		byte[] b = new byte[16*1024];
		int n;
		while( (n = in.read(b)) > 0 ) {
			out.write(b, 0, n);
			out.flush();
		}
	}
}
