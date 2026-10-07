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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.ProtocolFamily;
import java.net.SocketAddress;
import java.net.StandardProtocolFamily;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

/**
 * Unix domain sockets (Java 16+), reached by reflection so the code still compiles for and
 * runs on Java 11, where {@link #isSupported()} is false. Used for SSH agents.
 * <p>
 * The streams read and write the channel directly: the JDK's Channels streams can block a
 * write while a read waits on the same channel, and a bridge does both at once.
 *
 * @author Tony Bringardner
 */
public final class UnixSockets {

	private static final ProtocolFamily UNIX = family();

	private UnixSockets() {
	}

	private static ProtocolFamily family() {
		try {
			SocketChannel.class.getMethod("open", ProtocolFamily.class);
			ServerSocketChannel.class.getMethod("open", ProtocolFamily.class);
			Class.forName("java.net.UnixDomainSocketAddress");
			return StandardProtocolFamily.valueOf("UNIX");
		} catch (ReflectiveOperationException | IllegalArgumentException e) {
			return null;
		}
	}

	/**
	 * @return true on Java 16 and later
	 */
	public static boolean isSupported() {
		return UNIX != null;
	}

	private static SocketAddress address(String path) throws IOException {
		try {
			Method of = Class.forName("java.net.UnixDomainSocketAddress").getMethod("of", String.class);
			return (SocketAddress) of.invoke(null, path);
		} catch (ReflectiveOperationException e) {
			throw new IOException("Unix domain sockets need Java 16 or later", e);
		}
	}

	private static void need() throws IOException {
		if( UNIX == null ) {
			throw new IOException("Unix domain sockets need Java 16 or later");
		}
	}

	/**
	 * @return a blocking channel connected to the socket
	 */
	public static SocketChannel connect(String path) throws IOException {
		need();
		SocketChannel ch;
		try {
			ch = (SocketChannel) SocketChannel.class.getMethod("open", ProtocolFamily.class).invoke(null, UNIX);
		} catch (ReflectiveOperationException e) {
			throw new IOException("Can't open a Unix domain socket", e);
		}
		try {
			ch.connect(address(path));
			return ch;
		} catch (IOException | RuntimeException e) {
			ch.close();
			throw e;
		}
	}

	/**
	 * @return a blocking channel listening on the path (which must not exist)
	 */
	public static ServerSocketChannel listen(String path) throws IOException {
		need();
		ServerSocketChannel ch;
		try {
			ch = (ServerSocketChannel) ServerSocketChannel.class.getMethod("open", ProtocolFamily.class).invoke(null, UNIX);
		} catch (ReflectiveOperationException e) {
			throw new IOException("Can't open a Unix domain socket", e);
		}
		try {
			ch.bind(address(path));
			return ch;
		} catch (IOException | RuntimeException e) {
			ch.close();
			throw e;
		}
	}

	public static InputStream inputStream(SocketChannel ch) {
		return new InputStream() {
			@Override
			public int read() throws IOException {
				byte[] b = new byte[1];
				int n = read(b, 0, 1);
				return n < 0 ? -1 : b[0] & 0xff;
			}

			@Override
			public int read(byte[] b, int off, int len) throws IOException {
				if( len == 0 ) {
					return 0;
				}
				return ch.read(ByteBuffer.wrap(b, off, len));
			}

			@Override
			public void close() throws IOException {
				ch.close();
			}
		};
	}

	public static OutputStream outputStream(SocketChannel ch) {
		return new OutputStream() {
			@Override
			public void write(int b) throws IOException {
				write(new byte[] {(byte) b}, 0, 1);
			}

			@Override
			public void write(byte[] b, int off, int len) throws IOException {
				ByteBuffer buf = ByteBuffer.wrap(b, off, len);
				while( buf.hasRemaining() ) {
					ch.write(buf);
				}
			}

			@Override
			public void close() throws IOException {
				ch.shutdownOutput();
			}
		};
	}
}
