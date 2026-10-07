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
import java.nio.channels.ClosedChannelException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

import us.bringardner.core.BaseObject;
import us.bringardner.net.framework.server.Server;
import us.bringardner.net.ssh.SshBuffer;
import us.bringardner.net.ssh.SshConstants;
import us.bringardner.net.ssh.SshException;
import us.bringardner.net.ssh.transport.SshTransport;

/**
 * The SSH connection protocol (RFC 4254) on one transport, the same for client and server:
 * the channel table, channel messages, and global requests in both directions. The channel
 * types are {@link SshChannel} subclasses; the peer's channel opens and global requests are
 * answered by registered {@link IChannelFactory}s and {@link IGlobalRequestHandler}s.
 *
 * @author Tony Bringardner
 */
public class ConnectionService extends BaseObject {

	/** Most channels open at once on one connection */
	public static final int DEFAULT_MAX_CHANNELS = 64;

	/** RFC 4254 5.1 reason codes */
	public static final int SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1;
	public static final int SSH_OPEN_CONNECT_FAILED = 2;
	public static final int SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3;
	public static final int SSH_OPEN_RESOURCE_SHORTAGE = 4;

	private final SshTransport transport;
	private final Map<Integer, SshChannel> channels = new ConcurrentHashMap<Integer, SshChannel>();
	private final Map<String, IChannelFactory> channelFactories = new ConcurrentHashMap<String, IChannelFactory>();
	private final Map<String, IGlobalRequestHandler> globalHandlers = new ConcurrentHashMap<String, IGlobalRequestHandler>();
	private final Deque<CompletableFuture<SshBuffer>> pendingGlobal = new ArrayDeque<CompletableFuture<SshBuffer>>();
	private int nextId;
	private volatile int maxChannels = DEFAULT_MAX_CHANNELS;
	private volatile boolean closed;

	public ConnectionService(SshTransport transport) {
		this.transport = transport;
		getLogger().setLevel(Server.getDefaultLogLevel());
	}

	public SshTransport getTransport() {
		return transport;
	}

	void send(SshBuffer message) throws IOException {
		transport.send(message);
	}

	// ------------------------------------------------------------------ configuration

	public void addChannelFactory(String type, IChannelFactory factory) {
		channelFactories.put(type, factory);
	}

	public void addGlobalRequestHandler(String request, IGlobalRequestHandler handler) {
		globalHandlers.put(request, handler);
	}

	public int getMaxChannels() {
		return maxChannels;
	}

	public void setMaxChannels(int maxChannels) {
		this.maxChannels = maxChannels;
	}

	public Collection<SshChannel> getChannels() {
		return Collections.unmodifiableCollection(channels.values());
	}

	// ------------------------------------------------------------------ outgoing

	/**
	 * Open a channel.
	 *
	 * @return completes with the channel once the peer confirms it
	 */
	public <C extends SshChannel> CompletableFuture<C> open(C channel) {
		CompletableFuture<C> ret = new CompletableFuture<C>();
		try {
			register(channel);
			SshBuffer b = SshBuffer.message(SshConstants.SSH_MSG_CHANNEL_OPEN).putString(channel.getType())
					.putInt(channel.getLocalId()).putInt(channel.getLocalWindowSize()).putInt(channel.getLocalMaxPacket());
			SshBuffer data = channel.getOpenData();
			if( data != null ) {
				b.putBuffer(data);
			}
			send(b);
		} catch (IOException e) {
			channels.remove(channel.getLocalId());
			ret.completeExceptionally(e);
			return ret;
		}
		channel.getOpenFuture().whenComplete((c, error) -> {
			if( error != null ) {
				ret.completeExceptionally(error);
			} else {
				ret.complete(channel);
			}
		});
		return ret;
	}

	private synchronized void register(SshChannel channel) throws IOException {
		if( closed ) {
			throw new ClosedChannelException();
		}
		if( channels.size() >= maxChannels ) {
			throw new SshException(SshConstants.SSH_DISCONNECT_BY_APPLICATION, "Too many channels ("+maxChannels+")");
		}
		int id;
		do {
			id = nextId++ & Integer.MAX_VALUE;
		} while( channels.containsKey(id) );
		channel.opening(this, id);
		channels.put(id, channel);
	}

	/**
	 * Send a global request.
	 *
	 * @return with wantReply, completes with the success data (null for failure); without,
	 * completes at once with an empty buffer
	 */
	public CompletableFuture<SshBuffer> sendGlobalRequest(String request, boolean wantReply, SshBuffer data) {
		CompletableFuture<SshBuffer> ret = new CompletableFuture<SshBuffer>();
		SshBuffer b = SshBuffer.message(SshConstants.SSH_MSG_GLOBAL_REQUEST).putString(request).putBoolean(wantReply);
		if( data != null ) {
			b.putBuffer(data);
		}
		synchronized (pendingGlobal) {
			try {
				if( closed ) {
					throw new ClosedChannelException();
				}
				if( wantReply ) {
					pendingGlobal.add(ret);
				}
				send(b);
			} catch (IOException e) {
				pendingGlobal.remove(ret);
				ret.completeExceptionally(e);
				return ret;
			}
		}
		if( !wantReply ) {
			ret.complete(new SshBuffer());
		}
		return ret;
	}

	// ------------------------------------------------------------------ incoming (handler thread)

	/**
	 * @param msg 80 to 100
	 * @return false if the message isn't a connection protocol message
	 */
	public boolean handle(int msg, SshBuffer m) throws IOException {
		switch (msg) {
		case SshConstants.SSH_MSG_GLOBAL_REQUEST:
			globalRequest(m);
			return true;
		case SshConstants.SSH_MSG_REQUEST_SUCCESS:
		case SshConstants.SSH_MSG_REQUEST_FAILURE:
			CompletableFuture<SshBuffer> f;
			synchronized (pendingGlobal) {
				f = pendingGlobal.poll();
			}
			if( f == null ) {
				throw new SshException("Global request reply without a request");
			}
			f.complete(msg == SshConstants.SSH_MSG_REQUEST_SUCCESS ? new SshBuffer(m.toByteArray()) : null);
			return true;
		case SshConstants.SSH_MSG_CHANNEL_OPEN:
			channelOpen(m);
			return true;
		case SshConstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION: {
			SshChannel c = channel(m.getInt());
			int remote = m.getInt();
			long window = m.getUInt();
			int maxPacket = m.getInt();
			if( c.getRemoteId() != -1 ) {
				throw new SshException("Channel "+c.getLocalId()+" confirmed twice");
			}
			c.opened(remote, window, maxPacket);
			return true;
		}
		case SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE: {
			SshChannel c = channel(m.getInt());
			int reason = m.getInt();
			String text = m.getStringUtf8();
			c.openFailed(new SshException(SshConstants.SSH_DISCONNECT_BY_APPLICATION, "Channel "+c.getType()+" refused ("+reason+"): "+text));
			return true;
		}
		case SshConstants.SSH_MSG_CHANNEL_WINDOW_ADJUST:
			channel(m.getInt()).receivedWindowAdjust(m.getUInt());
			return true;
		case SshConstants.SSH_MSG_CHANNEL_DATA: {
			SshChannel c = channel(m.getInt());
			int len = m.getInt();
			if( len > m.available() ) {
				throw new SshException("Truncated channel data");
			}
			c.receivedData(m.array(), m.readPosition(), len, false);
			return true;
		}
		case SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA: {
			SshChannel c = channel(m.getInt());
			long code = m.getUInt();
			int len = m.getInt();
			if( len > m.available() ) {
				throw new SshException("Truncated channel data");
			}
			// 1 is stderr (SSH_EXTENDED_DATA_STDERR), the only code defined; any other goes to the same stream
			if( code != 1 ) {
				logDebug("Extended data type "+code+" treated as stderr");
			}
			c.receivedData(m.array(), m.readPosition(), len, true);
			return true;
		}
		case SshConstants.SSH_MSG_CHANNEL_EOF:
			channel(m.getInt()).receivedEof();
			return true;
		case SshConstants.SSH_MSG_CHANNEL_CLOSE:
			channel(m.getInt()).receivedClose();
			return true;
		case SshConstants.SSH_MSG_CHANNEL_REQUEST: {
			SshChannel c = channel(m.getInt());
			String request = m.getStringUtf8();
			boolean wantReply = m.getBoolean();
			c.receivedRequest(request, wantReply, m);
			return true;
		}
		case SshConstants.SSH_MSG_CHANNEL_SUCCESS:
		case SshConstants.SSH_MSG_CHANNEL_FAILURE:
			channel(m.getInt()).receivedReply(msg == SshConstants.SSH_MSG_CHANNEL_SUCCESS);
			return true;
		default:
			return false;
		}
	}

	private SshChannel channel(int localId) throws SshException {
		SshChannel c = channels.get(localId);
		if( c == null ) {
			throw new SshException("No channel "+localId);
		}
		return c;
	}

	private void globalRequest(SshBuffer m) throws IOException {
		String request = m.getStringUtf8();
		boolean wantReply = m.getBoolean();
		IGlobalRequestHandler h = globalHandlers.get(request);
		SshBuffer result = null;
		if( h != null ) {
			result = h.handle(request, m);
		} else {
			logDebug(() -> "Refusing global request "+request);
		}
		if( wantReply ) {
			if( result == null ) {
				send(SshBuffer.message(SshConstants.SSH_MSG_REQUEST_FAILURE));
			} else {
				send(SshBuffer.message(SshConstants.SSH_MSG_REQUEST_SUCCESS).putBuffer(result));
			}
		}
	}

	private void channelOpen(SshBuffer m) throws IOException {
		String type = m.getStringUtf8();
		int sender = m.getInt();
		long window = m.getUInt();
		int maxPacket = m.getInt();
		IChannelFactory f = channelFactories.get(type);
		int reason;
		String text;
		if( f == null ) {
			reason = SSH_OPEN_UNKNOWN_CHANNEL_TYPE;
			text = "Unknown channel type "+type;
		} else {
			SshChannel c = f.create(type, m);
			if( c != null ) {
				try {
					register(c);
				} catch (SshException e) {
					send(SshBuffer.message(SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE).putInt(sender)
							.putInt(SSH_OPEN_RESOURCE_SHORTAGE).putString(e.getMessage()).putString(""));
					return;
				}
				send(SshBuffer.message(SshConstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION).putInt(sender).putInt(c.getLocalId())
						.putInt(c.getLocalWindowSize()).putInt(c.getLocalMaxPacket()));
				c.opened(sender, window, maxPacket);
				return;
			}
			reason = SSH_OPEN_ADMINISTRATIVELY_PROHIBITED;
			text = "Channel type "+type+" not allowed";
		}
		send(SshBuffer.message(SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE).putInt(sender).putInt(reason).putString(text).putString(""));
	}

	void removed(SshChannel channel) {
		channels.remove(channel.getLocalId(), channel);
	}

	/**
	 * The transport is gone: every channel and request fails.
	 */
	public void closeAll(Throwable reason) {
		closed = true;
		List<SshChannel> all = new ArrayList<SshChannel>(channels.values());
		for (SshChannel c : all) {
			c.finish(reason);
		}
		List<CompletableFuture<SshBuffer>> pending;
		synchronized (pendingGlobal) {
			pending = new ArrayList<CompletableFuture<SshBuffer>>(pendingGlobal);
			pendingGlobal.clear();
		}
		for (CompletableFuture<SshBuffer> f : pending) {
			f.completeExceptionally(reason);
		}
	}
}
