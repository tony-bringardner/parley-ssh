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
package us.bringardner.net.ssh.sftp;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.CompletableFuture;

/**
 * Reads a remote file with several read requests in flight, so a stream doesn't wait one
 * round trip per chunk. It starts with 2 requests and doubles up to the client's limit as
 * the reading goes on (small files don't cost extra requests). A short read is completed
 * by asking for the rest before any later data is used, so nothing is skipped.
 * <p>
 * Not thread safe, like any InputStream.
 *
 * @author Tony Bringardner
 */
public class SftpInputStream extends InputStream {

	private static final class Pending {
		final long offset;
		final int len;
		final CompletableFuture<SftpClient.Reply> reply;

		Pending(long offset, int len, CompletableFuture<SftpClient.Reply> reply) {
			this.offset = offset;
			this.len = len;
			this.reply = reply;
		}
	}

	private final SftpClient client;
	private final SftpHandle handle;
	private final boolean closeHandle;
	private final int chunk;
	private final Deque<Pending> queue = new ArrayDeque<Pending>();
	private int window = 2;
	// Offset of the next request
	private long nextOffset;
	// Offset of the next byte returned
	private long position;
	private byte[] buf = new byte[0];
	private int pos;
	private boolean eof;
	private boolean closed;

	/**
	 * @param closeHandle true to close the handle when the stream is closed
	 */
	public SftpInputStream(SftpClient client, SftpHandle handle, long offset, boolean closeHandle) {
		this.client = client;
		this.handle = handle;
		this.closeHandle = closeHandle;
		this.chunk = client.getChunkSize();
		this.nextOffset = offset;
		this.position = offset;
	}

	/**
	 * @return the file offset of the next byte read
	 */
	public long getPosition() {
		return position;
	}

	private boolean fill() throws IOException {
		if( closed ) {
			throw new IOException("Stream closed");
		}
		while( pos >= buf.length ) {
			if( eof ) {
				return false;
			}
			while( queue.size() < window ) {
				queue.add(new Pending(nextOffset, chunk, client.readAsync(handle, nextOffset, chunk)));
				nextOffset += chunk;
			}
			Pending p = queue.poll();
			byte[] d = SftpClient.readData(client.await(p.reply, "READ "+handle.getPath()), handle.getPath());
			if( d == null || d.length == 0 ) {
				// The end; later replies (EOF too) are not needed
				eof = true;
				queue.clear();
				return false;
			}
			if( d.length > p.len ) {
				throw new SftpException(SftpConstants.SSH_FX_BAD_MESSAGE, "READ returned more than asked for", handle.getPath());
			}
			if( d.length < p.len ) {
				// A short read: the rest of this range comes before the requests already sent
				long off = p.offset+d.length;
				queue.addFirst(new Pending(off, p.len-d.length, client.readAsync(handle, off, p.len-d.length)));
			}
			buf = d;
			pos = 0;
			if( window < client.getOutstanding() ) {
				window = Math.min(window*2, client.getOutstanding());
			}
		}
		return true;
	}

	@Override
	public int read() throws IOException {
		if( !fill() ) {
			return -1;
		}
		position++;
		return buf[pos++] & 0xff;
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		java.util.Objects.checkFromIndexSize(off, len, b.length);
		if( len == 0 ) {
			return 0;
		}
		if( !fill() ) {
			return -1;
		}
		int n = Math.min(len, buf.length-pos);
		System.arraycopy(buf, pos, b, off, n);
		pos += n;
		position += n;
		return n;
	}

	@Override
	public int available() {
		return buf.length-pos;
	}

	/**
	 * Skips without reading: what is buffered or in flight is dropped and reading starts
	 * again further on.
	 */
	@Override
	public long skip(long n) throws IOException {
		if( n <= 0 || closed ) {
			return 0;
		}
		int inBuf = buf.length-pos;
		if( n <= inBuf ) {
			pos += (int) n;
			position += n;
			return n;
		}
		position += n;
		nextOffset = position;
		buf = new byte[0];
		pos = 0;
		queue.clear();
		window = 2;
		return n;
	}

	@Override
	public void close() throws IOException {
		if( closed ) {
			return;
		}
		closed = true;
		queue.clear();
		if( closeHandle ) {
			handle.close();
		}
	}
}
