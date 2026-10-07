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
package us.bringardner.net.ssh;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

import us.bringardner.core.BaseObject;

/**
 * A connection on a non-blocking SocketChannel, served by one {@link NioReactor}.
 * <p>
 * The reactor thread does all the channel I/O: it reads into the input buffer, and sends
 * what write() queued. The input is split into frames by the decoder and passed to the
 * handler through a serial dispatcher, so a connection's handler calls never overlap and
 * stay in order, whether they run on the reactor thread or on a handler executor.
 * <p>
 * Created by {@link NioServer} and {@link NioClient}.
 *
 * @author Tony Bringardner
 */
public class NioConnection extends BaseObject implements INioConnection {

	public static final int DEFAULT_INITIAL_INPUT_BUFFER = 8*1024;
	public static final int DEFAULT_MAX_INPUT_BUFFER = 1024*1024;

	private static final AtomicLong NEXT_ID = new AtomicLong();

	private final long id = NEXT_ID.incrementAndGet();
	private final SocketChannel channel;
	private final NioReactor reactor;
	private final NioServer server;
	private final INioHandler handler;
	private final SerialExecutor dispatcher;
	private final int maxInputBuffer;
	private final long maxIdleTime;
	private final Map<String,Object> attributes = new ConcurrentHashMap<String, Object>();
	private volatile IFrameDecoder decoder;
	private volatile SelectionKey key;
	private volatile CompletableFuture<INioConnection> connectFuture;

	// Input: written by the reactor, decoded by the dispatcher. Guarded by inLock.
	// At rest the buffer is ready for put(), the bytes from readIndex to position are not decoded yet.
	private final ReentrantLock inLock = new ReentrantLock();
	private ByteBuffer in;
	private int readIndex;
	// The buffer is full at its maximum size, reading waits for the dispatcher to make room
	private boolean inputFull;

	// Output: queued by any thread, written by the reactor
	private final Queue<ByteBuffer> out = new ConcurrentLinkedQueue<ByteBuffer>();
	private final AtomicLong pendingWriteBytes = new AtomicLong();
	private final AtomicBoolean flushScheduled = new AtomicBoolean();
	private final AtomicBoolean processScheduled = new AtomicBoolean();
	private final AtomicBoolean closed = new AtomicBoolean();
	private volatile boolean closeAfterFlush;
	private volatile boolean connected;
	private volatile boolean readingPaused;
	private volatile boolean idleNotified;
	// The peer closed its side, stop selecting OP_READ (EOF stays readable)
	private volatile boolean inputShutdown;

	private volatile SocketAddress remoteAddress;
	private volatile SocketAddress localAddress;
	private volatile long connectTime;
	private volatile long lastReadTime;
	private volatile long lastWriteTime;
	// Only changed on the reactor thread
	private volatile long bytesIn;
	private volatile long bytesOut;

	/**
	 * @param channel a non-blocking channel, connected or connecting
	 * @param reactor the reactor that will serve it
	 * @param server the server that accepted it, null for a client connection
	 * @param handler receives the events
	 * @param decoder splits the input into frames
	 * @param handlerExecutor runs the handler calls, null to run them on the reactor thread
	 * @param initialInputBuffer starting size of the input buffer
	 * @param maxInputBuffer the input buffer grows up to this, it must hold the largest frame
	 * @param maxIdleTime ms without reads or writes before onIdle, 0 = never
	 */
	NioConnection(SocketChannel channel, NioReactor reactor, NioServer server, INioHandler handler, IFrameDecoder decoder,
			Executor handlerExecutor, int initialInputBuffer, int maxInputBuffer, long maxIdleTime) {
		this.channel = Objects.requireNonNull(channel, "channel");
		this.reactor = Objects.requireNonNull(reactor, "reactor");
		this.handler = Objects.requireNonNull(handler, "handler");
		this.decoder = Objects.requireNonNull(decoder, "decoder");
		this.server = server;
		this.dispatcher = new SerialExecutor(handlerExecutor);
		this.maxInputBuffer = Math.max(1, maxInputBuffer);
		this.in = ByteBuffer.allocate(Math.max(1, Math.min(initialInputBuffer, this.maxInputBuffer)));
		this.maxIdleTime = maxIdleTime;
		this.connectTime = System.currentTimeMillis();
	}

	// ------------------------------------------------------------------ INioConnection

	@Override
	public long getId() {
		return id;
	}

	@Override
	public SocketAddress getRemoteAddress() {
		SocketAddress ret = remoteAddress;
		if( ret == null ) {
			try {
				ret = remoteAddress = channel.getRemoteAddress();
			} catch (IOException e) {
				// closed
			}
		}
		return ret;
	}

	@Override
	public SocketAddress getLocalAddress() {
		SocketAddress ret = localAddress;
		if( ret == null ) {
			try {
				ret = localAddress = channel.getLocalAddress();
			} catch (IOException e) {
				// closed
			}
		}
		return ret;
	}

	@Override
	public boolean isOpen() {
		return !closed.get();
	}

	@Override
	public boolean isClientMode() {
		return server == null;
	}

	@Override
	public NioServer getServer() {
		return server;
	}

	@Override
	public INioHandler getHandler() {
		return handler;
	}

	/**
	 * @return the channel, for socket options. Don't read or write it directly.
	 */
	public SocketChannel getChannel() {
		return channel;
	}

	public NioReactor getReactor() {
		return reactor;
	}

	@Override
	public void write(ByteBuffer data) throws IOException {
		Objects.requireNonNull(data, "data");
		if( closed.get() || closeAfterFlush ) {
			throw new ClosedChannelException();
		}
		int len = data.remaining();
		if( len == 0 ) {
			return;
		}
		pendingWriteBytes.addAndGet(len);
		out.add(data);
		scheduleFlush();
	}

	@Override
	public long getPendingWriteBytes() {
		return pendingWriteBytes.get();
	}

	@Override
	public void close() {
		if( !closed.compareAndSet(false, true) ) {
			return;
		}
		logDebug(() -> "Closing connection "+id+" "+remoteAddress);
		SelectionKey k = key;
		if( k != null ) {
			k.cancel();
		}
		try {
			// Safe from any thread, the selector drops the channel on its next select
			channel.close();
		} catch (IOException e) {
			logDebug("Error closing channel", e);
		}
		out.clear();
		pendingWriteBytes.set(0);
		reactor.wakeup();
		if( server != null ) {
			server.connectionClosed(this);
		}
		CompletableFuture<INioConnection> f = connectFuture;
		if( f != null ) {
			f.completeExceptionally(new ClosedChannelException());
		}
		if( connected ) {
			dispatch(() -> handler.onClose(this));
		}
	}

	@Override
	public void closeAfterFlush() {
		if( closed.get() ) {
			return;
		}
		closeAfterFlush = true;
		// the flush closes the connection once nothing is left to send
		flushScheduled.set(true);
		reactor.execute(this::flush);
	}

	@Override
	public void pauseReading() {
		readingPaused = true;
		reactor.execute(this::updateInterest);
	}

	@Override
	public void resumeReading() {
		readingPaused = false;
		reactor.execute(this::updateInterest);
	}

	@Override
	public boolean isReadingPaused() {
		return readingPaused;
	}

	@Override
	public IFrameDecoder getDecoder() {
		return decoder;
	}

	@Override
	public void setDecoder(IFrameDecoder decoder) {
		this.decoder = Objects.requireNonNull(decoder, "decoder");
		// Bytes the old decoder left are offered to the new one
		scheduleProcess();
	}

	@Override
	public Object getAttribute(String name) {
		return name == null ? null : attributes.get(name);
	}

	@Override
	public void setAttribute(String name, Object value) {
		if( name == null ) {
			return;
		}
		if( value == null ) {
			attributes.remove(name);
		} else {
			attributes.put(name, value);
		}
	}

	@Override
	public Object removeAttribute(String name) {
		return name == null ? null : attributes.remove(name);
	}

	@Override
	public Map<String, Object> getAttributes() {
		return attributes;
	}

	@Override
	public long getBytesIn() {
		return bytesIn;
	}

	@Override
	public long getBytesOut() {
		return bytesOut;
	}

	@Override
	public long getConnectTime() {
		return connectTime;
	}

	@Override
	public long getLastReadTime() {
		return Math.max(lastReadTime, connectTime);
	}

	@Override
	public long getLastWriteTime() {
		return Math.max(lastWriteTime, connectTime);
	}

	@Override
	public String toString() {
		return "NioConnection[id="+id+", remote="+getRemoteAddress()+(closed.get() ? ", closed" : "")+"]";
	}

	// ------------------------------------------------------------------ called by the reactor thread

	void setConnectFuture(CompletableFuture<INioConnection> future) {
		this.connectFuture = future;
	}

	/**
	 * The channel is registered with the reactor's selector.
	 */
	void attach(SelectionKey key) {
		this.key = key;
	}

	/**
	 * A client's OP_CONNECT fired.
	 */
	void handleConnect() throws IOException {
		if( channel.finishConnect() ) {
			fireConnected();
		}
	}

	void fireConnected() {
		if( closed.get() ) {
			return;
		}
		connected = true;
		connectTime = System.currentTimeMillis();
		updateInterest();
		dispatch(() -> handler.onConnect(this));
		CompletableFuture<INioConnection> f = connectFuture;
		if( f != null ) {
			connectFuture = null;
			f.complete(this);
		}
	}

	void handleRead() throws IOException {
		int n;
		inLock.lock();
		try {
			if( !in.hasRemaining() ) {
				makeRoom();
			}
			if( !in.hasRemaining() ) {
				// Full at the maximum: wait for the dispatcher to take frames out
				inputFull = true;
				updateInterest();
				return;
			}
			n = channel.read(in);
		} finally {
			inLock.unlock();
		}

		if( n > 0 ) {
			bytesIn += n;
			lastReadTime = System.currentTimeMillis();
			idleNotified = false;
			scheduleProcess();
		} else if( n < 0 ) {
			// End of stream: what was read is still delivered (queued first), then onClose
			logDebug(() -> "Peer closed connection "+id);
			inputShutdown = true;
			updateInterest();
			scheduleProcess();
			dispatch(this::close);
		}
	}

	void handleWrite() {
		flush();
	}

	/**
	 * Called periodically by the reactor.
	 */
	void checkIdle(long now) {
		if( maxIdleTime <= 0 || idleNotified || !connected || closed.get() ) {
			return;
		}
		long last = Math.max(getLastReadTime(), getLastWriteTime());
		if( now-last > maxIdleTime ) {
			idleNotified = true;
			logDebug(() -> "Connection "+id+" idle for "+(now-last)+" ms");
			dispatch(() -> handler.onIdle(this));
		}
	}

	/**
	 * Something failed: tell the handler and close.
	 */
	void fail(Throwable error) {
		if( closed.get() ) {
			logDebug("Error on closed connection "+id, error);
			return;
		}
		logDebug("Error on connection "+id, error);
		CompletableFuture<INioConnection> f = connectFuture;
		if( f != null ) {
			f.completeExceptionally(error);
		}
		dispatchError(error);
		close();
	}

	// ------------------------------------------------------------------ internals

	/**
	 * Interest ops from the current state. Reactor thread only.
	 */
	private void updateInterest() {
		SelectionKey k = key;
		if( k == null || !k.isValid() ) {
			return;
		}
		int ops;
		if( !connected ) {
			ops = SelectionKey.OP_CONNECT;
		} else {
			ops = 0;
			boolean full;
			inLock.lock();
			try {
				full = inputFull;
			} finally {
				inLock.unlock();
			}
			if( !readingPaused && !full && !inputShutdown ) {
				ops |= SelectionKey.OP_READ;
			}
			if( !out.isEmpty() ) {
				ops |= SelectionKey.OP_WRITE;
			}
		}
		k.interestOps(ops);
	}

	private void scheduleFlush() {
		if( flushScheduled.compareAndSet(false, true) ) {
			reactor.execute(this::flush);
		}
	}

	/**
	 * Write as much of the queue as the socket takes. Reactor thread only.
	 */
	private void flush() {
		flushScheduled.set(false);
		if( closed.get() || !connected ) {
			// a client still connecting flushes from fireConnected's updateInterest (OP_WRITE)
			return;
		}
		try {
			ByteBuffer b;
			while( (b = out.peek()) != null ) {
				int n = channel.write(b);
				if( n > 0 ) {
					bytesOut += n;
					pendingWriteBytes.addAndGet(-n);
					lastWriteTime = System.currentTimeMillis();
					idleNotified = false;
				}
				if( b.hasRemaining() ) {
					// The socket buffer is full, OP_WRITE says when to go on
					break;
				}
				out.poll();
			}
		} catch (IOException e) {
			fail(e);
			return;
		}
		if( out.isEmpty() && closeAfterFlush ) {
			close();
			return;
		}
		updateInterest();
	}

	/**
	 * Compact, then grow if still full. Called with inLock held.
	 */
	private void makeRoom() {
		if( readIndex > 0 ) {
			compact();
		}
		if( !in.hasRemaining() && in.capacity() < maxInputBuffer ) {
			int size = (int) Math.min((long) maxInputBuffer, in.capacity()*2L);
			ByteBuffer tmp = ByteBuffer.allocate(size);
			in.flip();
			tmp.put(in);
			in = tmp;
		}
	}

	/**
	 * Drop the decoded bytes. Called with inLock held.
	 */
	private void compact() {
		in.flip();
		in.position(readIndex);
		in.compact();
		readIndex = 0;
	}

	private void scheduleProcess() {
		if( processScheduled.compareAndSet(false, true) ) {
			dispatch(this::process);
		}
	}

	/**
	 * Decode frames and hand them to the handler, one at a time so a handler can change
	 * the decoder between frames. Runs on the dispatcher.
	 */
	private void process() throws Exception {
		processScheduled.set(false);
		while( !closed.get() ) {
			ByteBuffer frame;
			boolean resume = false;
			inLock.lock();
			try {
				ByteBuffer view = in.duplicate();
				view.flip();
				view.position(readIndex);
				frame = decoder.decode(view);
				readIndex = view.position();
				if( frame == null || readIndex > in.capacity()/2 ) {
					compact();
				}
				if( frame == null && !in.hasRemaining() && in.capacity() >= maxInputBuffer ) {
					throw new IOException("Frame larger than the input buffer ("+maxInputBuffer+" bytes)");
				}
				if( inputFull && in.hasRemaining() ) {
					inputFull = false;
					resume = true;
				}
			} finally {
				inLock.unlock();
			}
			if( resume ) {
				reactor.execute(this::updateInterest);
			}
			if( frame == null ) {
				return;
			}
			handler.onMessage(this, frame);
		}
	}

	private interface HandlerCall {
		void run() throws Exception;
	}

	/**
	 * Run a handler call on the dispatcher. If it throws, the handler's onError is called
	 * and the connection closed.
	 */
	private void dispatch(HandlerCall call) {
		try {
			dispatcher.execute(() -> {
				try {
					call.run();
				} catch (Throwable e) {
					fail(e);
				}
			});
		} catch (RejectedExecutionException e) {
			// The handler executor has shut down
			logError("Handler executor rejected a call for connection "+id, e);
			if( !closed.get() ) {
				close();
			}
		}
	}

	private void dispatchError(Throwable error) {
		try {
			dispatcher.execute(() -> {
				try {
					handler.onError(this, error);
				} catch (Throwable e) {
					logError("Error in onError of connection "+id, e);
				}
			});
		} catch (RejectedExecutionException e) {
			logError("Handler executor rejected onError for connection "+id, error);
		}
	}

	/**
	 * Runs tasks one at a time, in order, on the target executor (or the calling thread when
	 * there is none). A task submitted while one is running is run after it by the same drain.
	 */
	private static final class SerialExecutor implements Executor {
		private final Executor target;
		private final Queue<Runnable> tasks = new ConcurrentLinkedQueue<Runnable>();
		private final AtomicBoolean active = new AtomicBoolean();

		SerialExecutor(Executor target) {
			this.target = target;
		}

		@Override
		public void execute(Runnable task) {
			tasks.add(task);
			schedule();
		}

		private void schedule() {
			if( active.compareAndSet(false, true) ) {
				if( target == null ) {
					drain();
				} else {
					try {
						target.execute(this::drain);
					} catch (RejectedExecutionException e) {
						active.set(false);
						tasks.clear();
						throw e;
					}
				}
			}
		}

		private void drain() {
			try {
				Runnable r;
				while( (r = tasks.poll()) != null ) {
					r.run();
				}
			} finally {
				active.set(false);
			}
			// A task added after the last poll but before active was cleared
			if( !tasks.isEmpty() ) {
				schedule();
			}
		}
	}
}
