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

import java.io.Closeable;
import java.io.IOException;

/**
 * An open file or directory on the server. Closing it more than once does nothing.
 *
 * @author Tony Bringardner
 */
public final class SftpHandle implements Closeable {

	private final SftpClient client;
	private final byte[] id;
	private final String path;
	private volatile boolean closed;

	SftpHandle(SftpClient client, byte[] id, String path) {
		this.client = client;
		this.id = id;
		this.path = path;
	}

	byte[] id() {
		return id;
	}

	/**
	 * @return the path it was opened with
	 */
	public String getPath() {
		return path;
	}

	public boolean isClosed() {
		return closed;
	}

	@Override
	public void close() throws IOException {
		if( closed ) {
			return;
		}
		closed = true;
		if( client.isOpen() ) {
			client.closeHandle(this);
		}
	}

	@Override
	public String toString() {
		return "SftpHandle["+path+"]";
	}
}
