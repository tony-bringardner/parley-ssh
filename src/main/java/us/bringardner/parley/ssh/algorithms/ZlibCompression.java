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
package us.bringardner.parley.ssh.algorithms;

import java.io.ByteArrayOutputStream;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import us.bringardner.parley.ssh.SshConstants;
import us.bringardner.parley.ssh.SshException;

/**
 * "zlib" (RFC 4253 6.2) and "zlib@openssh.com" (the same, started only after the user has
 * logged in, so data from unauthenticated clients is never inflated). One zlib stream per
 * direction, flushed at the end of each packet, kept across re-keying as OpenSSH does.
 * <p>
 * Inflating stops at a limit: a small packet can't turn into a huge one (a zip bomb).
 *
 * @author Tony Bringardner
 */
public class ZlibCompression {

	public static final String ZLIB = "zlib";
	public static final String ZLIB_OPENSSH = "zlib@openssh.com";

	private final String name;
	private final Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION);
	private final Inflater inflater = new Inflater();
	private final byte[] buf = new byte[32*1024];

	public ZlibCompression(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	/**
	 * @return true for zlib@openssh.com: only after authentication
	 */
	public boolean isDelayed() {
		return ZLIB_OPENSSH.equals(name);
	}

	public byte[] compress(byte[] data, int off, int len) {
		deflater.setInput(data, off, len);
		ByteArrayOutputStream out = new ByteArrayOutputStream(len/2+64);
		int n;
		do {
			n = deflater.deflate(buf, 0, buf.length, Deflater.SYNC_FLUSH);
			out.write(buf, 0, n);
		} while( n == buf.length );
		return out.toByteArray();
	}

	/**
	 * @param max the most bytes the packet may inflate to
	 * @throws SshException (COMPRESSION_ERROR) for bad data or a packet over the limit
	 */
	public byte[] decompress(byte[] data, int off, int len, int max) throws SshException {
		inflater.setInput(data, off, len);
		ByteArrayOutputStream out = new ByteArrayOutputStream(len*2+64);
		try {
			while( true ) {
				int n = inflater.inflate(buf);
				if( n == 0 ) {
					if( inflater.needsInput() || inflater.finished() ) {
						break;
					}
					if( inflater.needsDictionary() ) {
						throw new SshException(SshConstants.SSH_DISCONNECT_COMPRESSION_ERROR, "zlib wants a dictionary");
					}
				}
				out.write(buf, 0, n);
				if( out.size() > max ) {
					throw new SshException(SshConstants.SSH_DISCONNECT_COMPRESSION_ERROR, "Compressed packet inflates past "+max+" bytes");
				}
			}
		} catch (DataFormatException e) {
			throw new SshException(SshConstants.SSH_DISCONNECT_COMPRESSION_ERROR, "Bad compressed data: "+e.getMessage(), e);
		}
		return out.toByteArray();
	}
}
