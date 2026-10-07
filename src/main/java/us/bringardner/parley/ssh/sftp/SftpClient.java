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
package us.bringardner.parley.ssh.sftp;

import java.io.Closeable;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.nio.channels.ClosedChannelException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

import us.bringardner.parley.core.BaseObject;
import us.bringardner.parley.net.server.Server;
import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.client.ClientSession;
import us.bringardner.parley.ssh.client.SessionChannel;

/**
 * An SFTP version 3 client (draft-ietf-secsh-filexfer-02, as OpenSSH speaks it) on a
 * "sftp" subsystem channel.
 * <p>
 * Requests carry ids, so many can be in flight: the client is safe to use from several
 * threads, and its streams keep several reads or writes outstanding instead of waiting a
 * round trip per chunk. Replies are parsed on the connection's handler thread as they arrive
 * (no reader thread).
 * <p>
 * Paths are as the server sees them: absolute, or relative to the login directory. OpenSSH
 * extensions are used when the server offers them ({@link #hasExtension(String)}).
 *
 * <pre>
 * try (SftpClient sftp = SftpClient.open(session)) {
 *     for (SftpDirEntry e : sftp.list(".")) ...
 *     try (InputStream in = sftp.read("file.txt", 0)) ...
 * }
 * </pre>
 *
 * @author Tony Bringardner
 */
public class SftpClient extends BaseObject implements Closeable {

	/** Bytes per read or write request (what OpenSSH's client uses) */
	public static final int DEFAULT_CHUNK = 32*1024;
	/** Requests a stream keeps in flight */
	public static final int DEFAULT_OUTSTANDING = 16;
	/** Largest reply accepted (OpenSSH's server sends at most 256 KB) */
	private static final int MAX_PACKET = 4*1024*1024;

	/**
	 * A reply: its type and data (read position after the request id).
	 */
	static final class Reply {
		final int type;
		final SshBuffer data;

		Reply(int type, SshBuffer data) {
			this.type = type;
			this.data = data;
		}
	}

	private SubsystemChannel channel;
	private final Map<Integer, CompletableFuture<Reply>> pending = new ConcurrentHashMap<Integer, CompletableFuture<Reply>>();
	private final AtomicInteger ids = new AtomicInteger();
	private final ReentrantLock sendLock = new ReentrantLock();
	private final CompletableFuture<Integer> version = new CompletableFuture<Integer>();
	private volatile Map<String, String> extensions = Collections.emptyMap();
	private volatile long timeout = 60000;
	private volatile int chunkSize = DEFAULT_CHUNK;
	private volatile int outstanding = DEFAULT_OUTSTANDING;
	private volatile boolean closed;

	/**
	 * The "sftp" subsystem channel: replies are parsed as the data arrives.
	 */
	private final class SubsystemChannel extends SessionChannel {
		private byte[] in = new byte[64*1024];
		private int inLength;

		@Override
		protected boolean onData(byte[] buf, int off, int len, boolean ext) throws IOException {
			if( ext ) {
				logDebug(() -> "sftp stderr: "+new String(buf, off, len, java.nio.charset.StandardCharsets.UTF_8));
				return true;
			}
			if( inLength+len > in.length ) {
				in = java.util.Arrays.copyOf(in, Math.max(in.length*2, inLength+len));
			}
			System.arraycopy(buf, off, in, inLength, len);
			inLength += len;
			int pos = 0;
			while( inLength-pos >= 4 ) {
				long plen = ((in[pos] & 0xffL) << 24) | ((in[pos+1] & 0xffL) << 16) | ((in[pos+2] & 0xffL) << 8) | (in[pos+3] & 0xffL);
				if( plen < 1 || plen > MAX_PACKET ) {
					throw new SshException("Bad SFTP packet length "+plen);
				}
				if( inLength-pos-4 < plen ) {
					break;
				}
				received(new SshBuffer(java.util.Arrays.copyOfRange(in, pos+4, pos+4+(int) plen)));
				pos += 4+(int) plen;
			}
			if( pos > 0 ) {
				System.arraycopy(in, pos, in, 0, inLength-pos);
				inLength -= pos;
			}
			if( in.length > 256*1024 && inLength < 64*1024 ) {
				in = java.util.Arrays.copyOf(in, 64*1024);
			}
			return true;
		}

		@Override
		protected void onClosed() {
			failAll(new ClosedChannelException());
		}
	}

	private SftpClient() {
		getLogger().setLevel(Server.getDefaultLogLevel());
	}

	/**
	 * Open an "sftp" subsystem channel on an authenticated session and say hello (version 3).
	 */
	public static SftpClient open(ClientSession session) throws IOException {
		SftpClient ret = new SftpClient();
		SubsystemChannel ch = ret.new SubsystemChannel();
		ret.channel = ch;
		session.openChannel(ch);
		try {
			ch.subsystem("sftp");
			ret.init();
			return ret;
		} catch (IOException | RuntimeException e) {
			ch.close();
			throw e;
		}
	}

	private void init() throws IOException {
		SshBuffer b = new SshBuffer();
		b.putInt(5).putByte(SftpConstants.SSH_FXP_INIT).putInt(SftpConstants.SFTP_VERSION);
		writePacket(b);
		int v = await(version, "SFTP version");
		if( v < 3 ) {
			throw new SftpException(SftpConstants.SSH_FX_OP_UNSUPPORTED, "Server speaks SFTP version "+v, null);
		}
	}

	private void received(SshBuffer packet) throws IOException {
		int type = packet.getByte();
		if( type == SftpConstants.SSH_FXP_VERSION ) {
			int v = packet.getInt();
			Map<String, String> ext = new LinkedHashMap<String, String>();
			while( packet.available() > 0 ) {
				ext.put(packet.getStringUtf8(), packet.getStringUtf8());
			}
			extensions = Collections.unmodifiableMap(ext);
			logDebug(() -> "SFTP version "+v+", extensions "+ext.keySet());
			version.complete(v);
			return;
		}
		int id = packet.getInt();
		CompletableFuture<Reply> f = pending.remove(id);
		if( f == null ) {
			throw new SshException("SFTP reply for unknown request "+id);
		}
		f.complete(new Reply(type, packet));
	}

	private void failAll(Throwable reason) {
		closed = true;
		version.completeExceptionally(reason);
		List<CompletableFuture<Reply>> all = new ArrayList<CompletableFuture<Reply>>(pending.values());
		pending.clear();
		for (CompletableFuture<Reply> f : all) {
			f.completeExceptionally(reason);
		}
	}

	// ------------------------------------------------------------------ requests

	/**
	 * Send a request.
	 *
	 * @param type the packet type
	 * @param body what follows the request id
	 * @return the reply, when it comes
	 */
	CompletableFuture<Reply> request(int type, SshBuffer body) {
		CompletableFuture<Reply> ret = new CompletableFuture<Reply>();
		if( closed ) {
			ret.completeExceptionally(new ClosedChannelException());
			return ret;
		}
		int id = ids.incrementAndGet() & Integer.MAX_VALUE;
		int len = 1+4+(body == null ? 0 : body.available());
		SshBuffer b = new SshBuffer(4+len);
		b.putInt(len).putByte(type).putInt(id);
		if( body != null ) {
			b.putBuffer(body);
		}
		pending.put(id, ret);
		try {
			writePacket(b);
		} catch (IOException e) {
			pending.remove(id);
			ret.completeExceptionally(e);
		}
		return ret;
	}

	/**
	 * Packets must not interleave on the channel: one writer at a time.
	 */
	private void writePacket(SshBuffer packet) throws IOException {
		OutputStream out = channel.getOutputStream();
		sendLock.lock();
		try {
			out.write(packet.array(), packet.readPosition(), packet.available());
		} finally {
			sendLock.unlock();
		}
	}

	<T> T await(CompletableFuture<T> f, String what) throws IOException {
		try {
			long t = timeout;
			return t > 0 ? f.get(t, TimeUnit.MILLISECONDS) : f.get();
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new InterruptedIOException(what+" interrupted");
		} catch (TimeoutException e) {
			throw new SocketTimeoutException(what+": no answer within "+timeout+" ms");
		} catch (ExecutionException e) {
			Throwable cause = e.getCause();
			throw cause instanceof IOException ? (IOException) cause : new IOException(what+": "+cause, cause);
		}
	}

	Reply call(int type, SshBuffer body, String path) throws IOException {
		return await(request(type, body), SftpConstants.statusName(type)+" "+path);
	}

	/**
	 * @throws SftpException unless the reply is SSH_FX_OK
	 */
	static void checkStatus(Reply r, String path) throws IOException {
		if( r.type != SftpConstants.SSH_FXP_STATUS ) {
			throw new SftpException(SftpConstants.SSH_FX_BAD_MESSAGE, "Expected STATUS, got "+r.type, path);
		}
		int code = r.data.getInt();
		if( code != SftpConstants.SSH_FX_OK ) {
			throw new SftpException(code, r.data.available() > 0 ? r.data.getStringUtf8() : "", path);
		}
	}

	/**
	 * @throws SftpException for a STATUS reply (the request failed) or another unexpected type
	 */
	static SshBuffer expect(Reply r, int type, String path) throws IOException {
		if( r.type == type ) {
			return r.data;
		}
		if( r.type == SftpConstants.SSH_FXP_STATUS ) {
			int code = r.data.getInt();
			throw new SftpException(code == SftpConstants.SSH_FX_OK ? SftpConstants.SSH_FX_BAD_MESSAGE : code,
					r.data.available() > 0 ? r.data.getStringUtf8() : "", path);
		}
		throw new SftpException(SftpConstants.SSH_FX_BAD_MESSAGE, "Unexpected reply type "+r.type, path);
	}

	private static SshBuffer path(String path) {
		return new SshBuffer().putString(path);
	}

	// ------------------------------------------------------------------ file system operations

	/**
	 * @return the attributes, following symbolic links
	 */
	public SftpAttrs stat(String path) throws IOException {
		return SftpAttrs.read(expect(call(SftpConstants.SSH_FXP_STAT, path(path), path), SftpConstants.SSH_FXP_ATTRS, path));
	}

	/**
	 * @return the attributes of the path itself (a link is not followed)
	 */
	public SftpAttrs lstat(String path) throws IOException {
		return SftpAttrs.read(expect(call(SftpConstants.SSH_FXP_LSTAT, path(path), path), SftpConstants.SSH_FXP_ATTRS, path));
	}

	public SftpAttrs fstat(SftpHandle handle) throws IOException {
		SshBuffer b = new SshBuffer().putString(handle.id());
		return SftpAttrs.read(expect(call(SftpConstants.SSH_FXP_FSTAT, b, handle.getPath()), SftpConstants.SSH_FXP_ATTRS, handle.getPath()));
	}

	/**
	 * Change attributes; only the fields set in attrs change.
	 */
	public void setStat(String path, SftpAttrs attrs) throws IOException {
		checkStatus(call(SftpConstants.SSH_FXP_SETSTAT, attrs.write(path(path)), path), path);
	}

	public void fsetStat(SftpHandle handle, SftpAttrs attrs) throws IOException {
		checkStatus(call(SftpConstants.SSH_FXP_FSETSTAT, attrs.write(new SshBuffer().putString(handle.id())), handle.getPath()), handle.getPath());
	}

	/**
	 * @param flags SftpConstants.SSH_FXF_...
	 * @param attrs for a file that is created (e.g. its permissions), or SftpAttrs.NONE
	 */
	public SftpHandle open(String path, int flags, SftpAttrs attrs) throws IOException {
		SshBuffer b = path(path).putInt(flags);
		attrs.write(b);
		byte[] h = expect(call(SftpConstants.SSH_FXP_OPEN, b, path), SftpConstants.SSH_FXP_HANDLE, path).getString();
		return new SftpHandle(this, h, path);
	}

	void closeHandle(SftpHandle handle) throws IOException {
		checkStatus(call(SftpConstants.SSH_FXP_CLOSE, new SshBuffer().putString(handle.id()), handle.getPath()), handle.getPath());
	}

	/**
	 * @return up to len bytes at offset (servers may return fewer), or null at the end of the file
	 */
	public byte[] read(SftpHandle handle, long offset, int len) throws IOException {
		return readData(await(readAsync(handle, offset, len), "READ "+handle.getPath()), handle.getPath());
	}

	CompletableFuture<Reply> readAsync(SftpHandle handle, long offset, int len) {
		return request(SftpConstants.SSH_FXP_READ, new SshBuffer().putString(handle.id()).putLong(offset).putInt(len));
	}

	static byte[] readData(Reply r, String path) throws IOException {
		if( r.type == SftpConstants.SSH_FXP_STATUS ) {
			int code = r.data.getInt();
			if( code == SftpConstants.SSH_FX_EOF ) {
				return null;
			}
			throw new SftpException(code, r.data.available() > 0 ? r.data.getStringUtf8() : "", path);
		}
		return expect(r, SftpConstants.SSH_FXP_DATA, path).getString();
	}

	public void write(SftpHandle handle, long offset, byte[] b, int off, int len) throws IOException {
		checkStatus(await(writeAsync(handle, offset, b, off, len), "WRITE "+handle.getPath()), handle.getPath());
	}

	CompletableFuture<Reply> writeAsync(SftpHandle handle, long offset, byte[] b, int off, int len) {
		return request(SftpConstants.SSH_FXP_WRITE, new SshBuffer(len+64).putString(handle.id()).putLong(offset).putString(b, off, len));
	}

	/**
	 * @return the directory's entries (including "." and ".." if the server lists them)
	 */
	public List<SftpDirEntry> list(String dir) throws IOException {
		byte[] h = expect(call(SftpConstants.SSH_FXP_OPENDIR, path(dir), dir), SftpConstants.SSH_FXP_HANDLE, dir).getString();
		SftpHandle handle = new SftpHandle(this, h, dir);
		List<SftpDirEntry> ret = new ArrayList<SftpDirEntry>();
		try {
			while( true ) {
				Reply r = call(SftpConstants.SSH_FXP_READDIR, new SshBuffer().putString(h), dir);
				if( r.type == SftpConstants.SSH_FXP_STATUS ) {
					int code = r.data.getInt();
					if( code == SftpConstants.SSH_FX_EOF ) {
						break;
					}
					throw new SftpException(code, r.data.available() > 0 ? r.data.getStringUtf8() : "", dir);
				}
				SshBuffer d = expect(r, SftpConstants.SSH_FXP_NAME, dir);
				int n = d.getInt();
				for (int i = 0; i < n; i++) {
					ret.add(new SftpDirEntry(d.getStringUtf8(), d.getStringUtf8(), SftpAttrs.read(d)));
				}
			}
		} finally {
			handle.close();
		}
		return ret;
	}

	public void remove(String path) throws IOException {
		checkStatus(call(SftpConstants.SSH_FXP_REMOVE, path(path), path), path);
	}

	public void mkdir(String path, SftpAttrs attrs) throws IOException {
		checkStatus(call(SftpConstants.SSH_FXP_MKDIR, attrs.write(path(path)), path), path);
	}

	public void mkdir(String path) throws IOException {
		mkdir(path, SftpAttrs.NONE);
	}

	public void rmdir(String path) throws IOException {
		checkStatus(call(SftpConstants.SSH_FXP_RMDIR, path(path), path), path);
	}

	/**
	 * Rename; version 3 servers fail if 'to' exists (see {@link #posixRename(String, String)}).
	 */
	public void rename(String from, String to) throws IOException {
		checkStatus(call(SftpConstants.SSH_FXP_RENAME, path(from).putString(to), from), from);
	}

	/**
	 * Rename, replacing 'to' atomically (posix-rename@openssh.com).
	 *
	 * @throws SftpException SSH_FX_OP_UNSUPPORTED if the server doesn't have the extension
	 */
	public void posixRename(String from, String to) throws IOException {
		extended(SftpConstants.EXT_POSIX_RENAME, path(from).putString(to), from);
	}

	/**
	 * Create a hard link 'link' to 'existing' (hardlink@openssh.com).
	 */
	public void hardlink(String existing, String link) throws IOException {
		extended(SftpConstants.EXT_HARDLINK, path(existing).putString(link), link);
	}

	/**
	 * Flush a file to disk on the server (fsync@openssh.com).
	 */
	public void fsync(SftpHandle handle) throws IOException {
		extended(SftpConstants.EXT_FSYNC, new SshBuffer().putString(handle.id()), handle.getPath());
	}

	/**
	 * @return the canonical absolute path ("." is the login directory)
	 */
	public String realpath(String path) throws IOException {
		return firstName(call(SftpConstants.SSH_FXP_REALPATH, path(path), path), path);
	}

	public String readlink(String path) throws IOException {
		return firstName(call(SftpConstants.SSH_FXP_READLINK, path(path), path), path);
	}

	/**
	 * Create the symbolic link 'link' pointing at 'target'. Sent in the order OpenSSH (and
	 * so most servers) expects, target first: the reverse of the draft.
	 */
	public void symlink(String target, String link) throws IOException {
		checkStatus(call(SftpConstants.SSH_FXP_SYMLINK, path(target).putString(link), link), link);
	}

	private static String firstName(Reply r, String path) throws IOException {
		SshBuffer d = expect(r, SftpConstants.SSH_FXP_NAME, path);
		if( d.getInt() < 1 ) {
			throw new SftpException(SftpConstants.SSH_FX_BAD_MESSAGE, "Empty NAME reply", path);
		}
		return d.getStringUtf8();
	}

	/**
	 * Send an extension request (SSH_FXP_EXTENDED) that answers with a status.
	 *
	 * @throws SftpException SSH_FX_OP_UNSUPPORTED if the server doesn't list the extension
	 */
	public void extended(String name, SshBuffer data, String path) throws IOException {
		if( !hasExtension(name) ) {
			throw new SftpException(SftpConstants.SSH_FX_OP_UNSUPPORTED, "The server doesn't support "+name, path);
		}
		SshBuffer b = new SshBuffer().putString(name).putBuffer(data);
		checkStatus(call(SftpConstants.SSH_FXP_EXTENDED, b, path), path);
	}

	// ------------------------------------------------------------------ streams

	/**
	 * @return the file from offset to its end, read with several requests in flight
	 */
	public java.io.InputStream read(String path, long offset) throws IOException {
		SftpHandle h = open(path, SftpConstants.SSH_FXF_READ, SftpAttrs.NONE);
		return new SftpInputStream(this, h, offset, true);
	}

	/**
	 * Write a file (created if needed), with several writes in flight; errors of writes still
	 * in flight are thrown by a later write or by close().
	 *
	 * @param append true to add to the end, false to replace the contents
	 */
	public OutputStream write(String path, boolean append) throws IOException {
		int flags = SftpConstants.SSH_FXF_WRITE | SftpConstants.SSH_FXF_CREAT | (append ? SftpConstants.SSH_FXF_APPEND : SftpConstants.SSH_FXF_TRUNC);
		SftpHandle h = open(path, flags, SftpAttrs.NONE);
		long offset = 0;
		if( append ) {
			// Not every server honours SSH_FXF_APPEND: write at the end explicitly as well
			try {
				offset = fstat(h).getSize();
			} catch (IOException e) {
				h.close();
				throw e;
			}
		}
		return new SftpOutputStream(this, h, offset, true);
	}

	// ------------------------------------------------------------------ settings

	public int getServerVersion() {
		return version.getNow(-1);
	}

	/**
	 * @return the extensions the server listed in its VERSION, name to version
	 */
	public Map<String, String> getExtensions() {
		return extensions;
	}

	public boolean hasExtension(String name) {
		return extensions.containsKey(name);
	}

	public long getTimeout() {
		return timeout;
	}

	/**
	 * @param milliSeconds how long a request waits for its reply, 0 for no limit
	 */
	public void setTimeout(long milliSeconds) {
		this.timeout = milliSeconds;
	}

	public int getChunkSize() {
		return chunkSize;
	}

	/**
	 * @param bytes per read or write request of the streams (servers may cap reads)
	 */
	public void setChunkSize(int bytes) {
		this.chunkSize = bytes;
	}

	public int getOutstanding() {
		return outstanding;
	}

	/**
	 * @param requests a stream keeps in flight (1 waits for each reply before the next request)
	 */
	public void setOutstanding(int requests) {
		this.outstanding = Math.max(1, requests);
	}

	public boolean isOpen() {
		return !closed && channel.isOpen();
	}

	/**
	 * Close the subsystem channel; requests still waiting fail.
	 */
	@Override
	public void close() {
		closed = true;
		channel.close();
		failAll(new ClosedChannelException());
	}

	/**
	 * Close and wait for the server to confirm. Until it does, the channel still counts 
	 * against the server's limit (OpenSSH allows 10 per connection), so one opened just 
	 * after could be refused.
	 */
	public void close(long waitMillis) {
		close();
		try {
			channel.waitForClose(waitMillis, TimeUnit.MILLISECONDS);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}
}
