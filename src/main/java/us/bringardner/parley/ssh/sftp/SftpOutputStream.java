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

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.CompletableFuture;

/**
 * Writes a remote file with several write requests in flight. A failed write is reported
 * by a later write, flush() or close(); flush() waits until the server has answered every
 * write sent.
 * <p>
 * Not thread safe, like any OutputStream.
 *
 * @author Tony Bringardner
 */
public class SftpOutputStream extends OutputStream {

	private final SftpClient client;
	private final SftpHandle handle;
	private final boolean closeHandle;
	private final byte[] buffer;
	private final Deque<CompletableFuture<SftpClient.Reply>> inFlight = new ArrayDeque<CompletableFuture<SftpClient.Reply>>();
	private int count;
	private long offset;
	private boolean closed;

	/**
	 * @param offset where the first byte goes
	 * @param closeHandle true to close the handle when the stream is closed
	 */
	public SftpOutputStream(SftpClient client, SftpHandle handle, long offset, boolean closeHandle) {
		this.client = client;
		this.handle = handle;
		this.closeHandle = closeHandle;
		this.offset = offset;
		this.buffer = new byte[client.getChunkSize()];
	}

	/**
	 * @return the file offset of the next byte written
	 */
	public long getPosition() {
		return offset+count;
	}

	@Override
	public void write(int b) throws IOException {
		if( count == buffer.length ) {
			send(buffer, 0, count);
			count = 0;
		}
		buffer[count++] = (byte) b;
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		java.util.Objects.checkFromIndexSize(off, len, b.length);
		if( closed ) {
			throw new IOException("Stream closed");
		}
		while( len > 0 ) {
			if( count == 0 && len >= buffer.length ) {
				// Whole chunks go straight from the caller's array
				send(b, off, buffer.length);
				off += buffer.length;
				len -= buffer.length;
				continue;
			}
			int n = Math.min(len, buffer.length-count);
			System.arraycopy(b, off, buffer, count, n);
			count += n;
			off += n;
			len -= n;
			if( count == buffer.length ) {
				send(buffer, 0, count);
				count = 0;
			}
		}
	}

	private void send(byte[] b, int off, int len) throws IOException {
		if( closed ) {
			throw new IOException("Stream closed");
		}
		// writeAsync copies the data into the request
		inFlight.add(client.writeAsync(handle, offset, b, off, len));
		offset += len;
		while( inFlight.size() >= client.getOutstanding() ) {
			check(inFlight.poll());
		}
	}

	private void check(CompletableFuture<SftpClient.Reply> f) throws IOException {
		SftpClient.checkStatus(client.await(f, "WRITE "+handle.getPath()), handle.getPath());
	}

	/**
	 * Send what is buffered and wait for the server to answer every write.
	 */
	@Override
	public void flush() throws IOException {
		if( count > 0 ) {
			send(buffer, 0, count);
			count = 0;
		}
		while( !inFlight.isEmpty() ) {
			check(inFlight.poll());
		}
	}

	@Override
	public void close() throws IOException {
		if( closed ) {
			return;
		}
		try {
			flush();
		} finally {
			closed = true;
			inFlight.clear();
			if( closeHandle ) {
				handle.close();
			}
		}
	}
}
