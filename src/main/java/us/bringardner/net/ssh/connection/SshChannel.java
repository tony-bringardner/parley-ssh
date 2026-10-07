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
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.nio.channels.ClosedChannelException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import us.bringardner.net.ssh.SshBuffer;
import us.bringardner.net.ssh.SshConstants;
import us.bringardner.net.ssh.SshException;

/**
 * One channel of an SSH connection (RFC 4254 5): opening, window based flow control, data
 * and extended data, EOF, close and channel requests. Subclasses are the channel types
 * (a session, a forwarded port...); they add the open data and the requests they know.
 * <p>
 * <b>Streams.</b> {@link #getInputStream()} (data) and {@link #getErrorStream()} (extended data,
 * stderr) block until data arrives. The peer may send only as much as the window allows;
 * as the application reads, the window is opened again (SSH_MSG_CHANNEL_WINDOW_ADJUST),
 * so a slow reader slows its channel and nothing else. {@link #getOutputStream()} blocks
 * while the peer's window is closed. The two input streams share the channel's window:
 * read both, or the one not read can stop the other.
 * <p>
 * <b>Threads.</b> Incoming messages arrive on the connection's handler thread and never block
 * it; the streams are used from application threads.
 *
 * @author Tony Bringardner
 */
public abstract class SshChannel {

	/** The window offered to the peer (OpenSSH uses 2 MB) */
	public static final int DEFAULT_WINDOW = 2*1024*1024;
	/** The largest data packet accepted from the peer */
	public static final int DEFAULT_MAX_PACKET = 32*1024;
	private static final long MAX_UINT32 = 0xffffffffL;

	enum State { NEW, OPENING, OPEN, CLOSED }

	private final String type;
	private ConnectionService service;
	private int localId = -1;
	private volatile int remoteId = -1;
	private volatile State state = State.NEW;
	private final int localMaxWindow;
	private final int localMaxPacket;
	private final CompletableFuture<SshChannel> openFuture = new CompletableFuture<SshChannel>();
	private final CompletableFuture<Void> closeFuture = new CompletableFuture<Void>();
	private final Deque<CompletableFuture<Boolean>> pendingRequests = new ArrayDeque<CompletableFuture<Boolean>>();

	// Guarded by lock
	final ReentrantLock lock = new ReentrantLock();
	final Condition changed = lock.newCondition();
	private long localWindow;
	private long remoteWindow;
	private int remoteMaxPacket;
	private boolean eofSent;
	private boolean eofReceived;
	private boolean closeSent;
	private boolean closeReceived;
	private volatile Throwable failure;

	private final Buffer data = new Buffer();
	private final Buffer extended = new Buffer();
	private final ChannelInputStream in = new ChannelInputStream(data);
	private final ChannelInputStream err = new ChannelInputStream(extended);
	private final ChannelOutputStream out = new ChannelOutputStream();

	/**
	 * @param type the channel type, e.g. "session"
	 */
	protected SshChannel(String type) {
		this(type, DEFAULT_WINDOW, DEFAULT_MAX_PACKET);
	}

	protected SshChannel(String type, int window, int maxPacket) {
		this.type = type;
		this.localMaxWindow = window;
		this.localMaxPacket = maxPacket;
		this.localWindow = window;
	}

	// ------------------------------------------------------------------ for subclasses

	/**
	 * @return the type specific data of SSH_MSG_CHANNEL_OPEN (after the window and packet size),
	 * or null for none
	 */
	protected SshBuffer getOpenData() {
		return null;
	}

	/**
	 * A channel request from the peer (e.g. "exit-status"), on the handler thread.
	 *
	 * @return true for success (sent if the peer wants a reply), false for failure
	 */
	protected boolean handleRequest(String request, boolean wantReply, SshBuffer data) throws IOException {
		return false;
	}

	/**
	 * The channel is open (both sides).
	 */
	protected void onOpen() {
	}

	/**
	 * The channel has closed; data already received can still be read.
	 */
	protected void onClosed() {
	}

	// ------------------------------------------------------------------ public

	public String getType() {
		return type;
	}

	public int getLocalId() {
		return localId;
	}

	public int getRemoteId() {
		return remoteId;
	}

	public boolean isOpen() {
		return state == State.OPEN;
	}

	public boolean isClosed() {
		return state == State.CLOSED;
	}

	/**
	 * @return completes when the peer confirms the open, fails if it refuses (an SshException
	 * with the RFC 4254 reason as message)
	 */
	public CompletableFuture<SshChannel> getOpenFuture() {
		return openFuture;
	}

	/**
	 * @return completes when the channel is closed (both sides), or the connection ends
	 */
	public CompletableFuture<Void> getCloseFuture() {
		return closeFuture;
	}

	/**
	 * Data from the peer (for a session: the command's stdout).
	 */
	public InputStream getInputStream() {
		return in;
	}

	/**
	 * Extended data from the peer (for a session: stderr).
	 */
	public InputStream getErrorStream() {
		return err;
	}

	/**
	 * Data to the peer (for a session: the command's stdin). Closing it sends EOF.
	 */
	public OutputStream getOutputStream() {
		return out;
	}

	/**
	 * Send a channel request.
	 *
	 * @param request e.g. "exec"
	 * @param wantReply true to wait for the peer's success or failure
	 * @param requestData the request's data, or null
	 * @return completes with true or false (the peer's answer); with true at once without a reply
	 */
	public CompletableFuture<Boolean> sendRequest(String request, boolean wantReply, SshBuffer requestData) {
		CompletableFuture<Boolean> ret = new CompletableFuture<Boolean>();
		SshBuffer b = SshBuffer.message(SshConstants.SSH_MSG_CHANNEL_REQUEST).putInt(remoteId).putString(request).putBoolean(wantReply);
		if( requestData != null ) {
			b.putBuffer(requestData);
		}
		lock.lock();
		try {
			if( state != State.OPEN || closeSent ) {
				ret.completeExceptionally(new ClosedChannelException());
				return ret;
			}
			if( wantReply ) {
				pendingRequests.add(ret);
			}
			// Sent under the lock so replies come back in the order of pendingRequests
			service.send(b);
		} catch (IOException e) {
			pendingRequests.remove(ret);
			ret.completeExceptionally(e);
			return ret;
		} finally {
			lock.unlock();
		}
		if( !wantReply ) {
			ret.complete(true);
		}
		return ret;
	}

	/**
	 * Send EOF: no more data from this side. The channel stays open for the peer's data.
	 */
	public void sendEof() throws IOException {
		lock.lock();
		try {
			if( eofSent || closeSent || state != State.OPEN ) {
				return;
			}
			eofSent = true;
			service.send(SshBuffer.message(SshConstants.SSH_MSG_CHANNEL_EOF).putInt(remoteId));
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Close the channel (SSH_MSG_CHANNEL_CLOSE); it is gone once the peer answers.
	 * Data received before can still be read.
	 */
	public void close() {
		boolean finished = false;
		lock.lock();
		try {
			if( state == State.CLOSED || closeSent ) {
				return;
			}
			if( state == State.OPEN ) {
				closeSent = true;
				try {
					service.send(SshBuffer.message(SshConstants.SSH_MSG_CHANNEL_CLOSE).putInt(remoteId));
				} catch (IOException e) {
					// The connection is gone, so is the channel
					closeReceived = true;
				}
				finished = closeReceived;
			} else {
				finished = true;
			}
		} finally {
			lock.unlock();
		}
		if( finished ) {
			finish(null);
		}
	}

	/**
	 * Wait for the channel to close.
	 *
	 * @return false if it didn't within the time
	 */
	public boolean waitForClose(long timeout, TimeUnit unit) throws InterruptedException {
		try {
			closeFuture.get(timeout, unit);
			return true;
		} catch (java.util.concurrent.TimeoutException e) {
			return false;
		} catch (java.util.concurrent.ExecutionException e) {
			return true;
		}
	}

	/**
	 * Copy everything the peer sends (data to out, extended data to err) until it closes or
	 * sends EOF, reading both so neither can stall the other.
	 *
	 * @param timeout ms, 0 for no limit
	 * @throws IOException on a timeout (SocketTimeoutException) or a write error
	 */
	public void drain(OutputStream out, OutputStream err, long timeout) throws IOException {
		long end = timeout > 0 ? System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(timeout) : Long.MAX_VALUE;
		byte[] tmp = new byte[16*1024];
		while( true ) {
			int n1 = 0;
			int n2 = 0;
			boolean done;
			lock.lock();
			try {
				while( data.size() == 0 && extended.size() == 0 && !eofReceived && state != State.CLOSED ) {
					long left = end-System.nanoTime();
					if( left <= 0 ) {
						throw new java.net.SocketTimeoutException("No data from the channel within "+timeout+" ms");
					}
					try {
						changed.awaitNanos(left);
					} catch (InterruptedException e) {
						Thread.currentThread().interrupt();
						throw new InterruptedIOException();
					}
				}
				done = data.size() == 0 && extended.size() == 0;
			} finally {
				lock.unlock();
			}
			if( done ) {
				return;
			}
			while( (n1 = readSome(data, tmp, 0, tmp.length, false)) > 0 ) {
				out.write(tmp, 0, n1);
			}
			while( (n2 = readSome(extended, tmp, 0, tmp.length, false)) > 0 ) {
				err.write(tmp, 0, n2);
			}
		}
	}

	@Override
	public String toString() {
		return getClass().getSimpleName()+"["+type+" "+localId+"/"+remoteId+" "+state+"]";
	}

	// ------------------------------------------------------------------ from ConnectionService (handler thread)

	void opening(ConnectionService service, int localId) {
		this.service = service;
		this.localId = localId;
		this.state = State.OPENING;
	}

	int getLocalWindowSize() {
		return localMaxWindow;
	}

	int getLocalMaxPacket() {
		return localMaxPacket;
	}

	/**
	 * The peer opened the channel (we opened it), or we accept its open (it opened it).
	 */
	void opened(int remoteId, long window, int maxPacket) {
		lock.lock();
		try {
			this.remoteId = remoteId;
			this.remoteWindow = window;
			// Leave room for the message header
			this.remoteMaxPacket = Math.max(1, Math.min(maxPacket, 256*1024)-64);
			this.state = State.OPEN;
			changed.signalAll();
		} finally {
			lock.unlock();
		}
		onOpen();
		openFuture.complete(this);
	}

	void openFailed(Throwable reason) {
		state = State.CLOSED;
		openFuture.completeExceptionally(reason);
		finish(reason);
	}

	void receivedData(byte[] buf, int off, int len, boolean ext) throws SshException {
		lock.lock();
		try {
			if( eofReceived || closeReceived ) {
				throw new SshException("Channel data after EOF");
			}
			if( len > localWindow ) {
				throw new SshException("Channel data beyond the window ("+len+" > "+localWindow+")");
			}
			if( len > localMaxPacket ) {
				throw new SshException("Channel data packet too large ("+len+" > "+localMaxPacket+")");
			}
			localWindow -= len;
			(ext ? extended : data).add(buf, off, len);
			changed.signalAll();
		} finally {
			lock.unlock();
		}
	}

	void receivedWindowAdjust(long bytes) {
		lock.lock();
		try {
			remoteWindow = Math.min(MAX_UINT32, remoteWindow+bytes);
			changed.signalAll();
		} finally {
			lock.unlock();
		}
	}

	void receivedEof() {
		lock.lock();
		try {
			eofReceived = true;
			changed.signalAll();
		} finally {
			lock.unlock();
		}
	}

	void receivedClose() {
		boolean send;
		lock.lock();
		try {
			closeReceived = true;
			eofReceived = true;
			send = !closeSent && state == State.OPEN;
			closeSent = true;
			if( send ) {
				try {
					service.send(SshBuffer.message(SshConstants.SSH_MSG_CHANNEL_CLOSE).putInt(remoteId));
				} catch (IOException e) {
					// gone anyway
				}
			}
		} finally {
			lock.unlock();
		}
		finish(null);
	}

	void receivedRequest(String request, boolean wantReply, SshBuffer requestData) throws IOException {
		boolean ok = handleRequest(request, wantReply, requestData);
		if( wantReply ) {
			lock.lock();
			try {
				if( !closeSent ) {
					service.send(SshBuffer.message(ok ? SshConstants.SSH_MSG_CHANNEL_SUCCESS : SshConstants.SSH_MSG_CHANNEL_FAILURE).putInt(remoteId));
				}
			} finally {
				lock.unlock();
			}
		}
	}

	void receivedReply(boolean success) throws SshException {
		CompletableFuture<Boolean> f;
		lock.lock();
		try {
			f = pendingRequests.poll();
		} finally {
			lock.unlock();
		}
		if( f == null ) {
			throw new SshException("Channel request reply without a request");
		}
		f.complete(success);
	}

	/**
	 * The channel is gone (closed by both, refused, or the connection ended).
	 */
	void finish(Throwable reason) {
		CompletableFuture<Boolean>[] pending;
		lock.lock();
		try {
			if( state == State.CLOSED && closeFuture.isDone() ) {
				return;
			}
			if( reason != null && failure == null ) {
				failure = reason;
			}
			state = State.CLOSED;
			eofReceived = true;
			@SuppressWarnings("unchecked")
			CompletableFuture<Boolean>[] tmp = pendingRequests.toArray(new CompletableFuture[0]);
			pending = tmp;
			pendingRequests.clear();
			changed.signalAll();
		} finally {
			lock.unlock();
		}
		Throwable why = reason != null ? reason : new ClosedChannelException();
		for (CompletableFuture<Boolean> f : pending) {
			f.completeExceptionally(why);
		}
		openFuture.completeExceptionally(why);
		if( service != null ) {
			service.removed(this);
		}
		try {
			onClosed();
		} finally {
			closeFuture.complete(null);
		}
	}

	// ------------------------------------------------------------------ streams

	/**
	 * Take up to len bytes; opens the window again once half of it is used.
	 *
	 * @param block wait for data (else return 0 if none)
	 * @return bytes read, -1 at the end
	 */
	private int readSome(Buffer from, byte[] b, int off, int len, boolean block) throws IOException {
		long adjust = 0;
		int n;
		lock.lock();
		try {
			while( from.size() == 0 ) {
				if( eofReceived || state == State.CLOSED ) {
					return -1;
				}
				if( !block ) {
					return 0;
				}
				try {
					changed.await();
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					throw new InterruptedIOException();
				}
			}
			n = from.take(b, off, len);
			// The window is opened as the data is consumed, not as it arrives
			long buffered = data.size()+extended.size();
			if( state == State.OPEN && !closeSent && localWindow+buffered < localMaxWindow/2 ) {
				adjust = localMaxWindow-localWindow-buffered;
				localWindow += adjust;
				service.send(SshBuffer.message(SshConstants.SSH_MSG_CHANNEL_WINDOW_ADJUST).putInt(remoteId).putInt(adjust));
			}
		} finally {
			lock.unlock();
		}
		return n;
	}

	private int available(Buffer from) {
		lock.lock();
		try {
			return (int) Math.min(Integer.MAX_VALUE, from.size());
		} finally {
			lock.unlock();
		}
	}

	private final class ChannelInputStream extends InputStream {
		private final Buffer buffer;

		ChannelInputStream(Buffer buffer) {
			this.buffer = buffer;
		}

		@Override
		public int read() throws IOException {
			byte[] one = new byte[1];
			int n = read(one, 0, 1);
			return n < 0 ? -1 : one[0] & 0xff;
		}

		@Override
		public int read(byte[] b, int off, int len) throws IOException {
			if( len == 0 ) {
				return 0;
			}
			return readSome(buffer, b, off, len, true);
		}

		@Override
		public int available() {
			return SshChannel.this.available(buffer);
		}

		@Override
		public void close() {
			// Closing a stream doesn't close the channel; data not read is dropped as it arrives
		}
	}

	private final class ChannelOutputStream extends OutputStream {

		@Override
		public void write(int b) throws IOException {
			write(new byte[] {(byte) b}, 0, 1);
		}

		@Override
		public void write(byte[] b, int off, int len) throws IOException {
			while( len > 0 ) {
				lock.lock();
				try {
					while( remoteWindow == 0 && state == State.OPEN && !closeSent && !eofSent ) {
						try {
							changed.await();
						} catch (InterruptedException e) {
							Thread.currentThread().interrupt();
							throw new InterruptedIOException();
						}
					}
					if( state != State.OPEN || closeSent || eofSent ) {
						Throwable f = failure;
						throw f instanceof IOException ? (IOException) f : new ClosedChannelException();
					}
					int n = (int) Math.min(len, Math.min(remoteWindow, remoteMaxPacket));
					service.send(SshBuffer.message(SshConstants.SSH_MSG_CHANNEL_DATA).putInt(remoteId).putString(b, off, n));
					remoteWindow -= n;
					off += n;
					len -= n;
				} finally {
					lock.unlock();
				}
			}
		}

		@Override
		public void close() throws IOException {
			sendEof();
		}
	}

	/**
	 * Received bytes waiting to be read: a queue of chunks.
	 */
	private static final class Buffer {
		private final Deque<byte[]> chunks = new ArrayDeque<byte[]>();
		private int headOffset;
		private long size;

		void add(byte[] buf, int off, int len) {
			if( len > 0 ) {
				chunks.add(java.util.Arrays.copyOfRange(buf, off, off+len));
				size += len;
			}
		}

		long size() {
			return size;
		}

		int take(byte[] b, int off, int len) {
			int n = 0;
			while( n < len && !chunks.isEmpty() ) {
				byte[] head = chunks.peek();
				int k = Math.min(len-n, head.length-headOffset);
				System.arraycopy(head, headOffset, b, off+n, k);
				n += k;
				headOffset += k;
				if( headOffset == head.length ) {
					chunks.poll();
					headOffset = 0;
				}
			}
			size -= n;
			return n;
		}
	}
}
