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

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Reads and writes the SSH data types (RFC 4251 section 5): byte, boolean, uint32, uint64,
 * string, mpint and name-list.
 * <p>
 * Writing appends at the end and grows the buffer; reading takes from the front. A read past
 * the end, or a string longer than what is left, throws an SshException (a protocol error),
 * so a malformed packet can't make the reader allocate a huge array.
 * Not thread safe.
 *
 * @author Tony Bringardner
 */
public final class SshBuffer {

	private byte[] data;
	private int rpos;
	private int wpos;

	/**
	 * An empty buffer for writing.
	 */
	public SshBuffer() {
		this(256);
	}

	public SshBuffer(int capacity) {
		data = new byte[Math.max(16, capacity)];
	}

	/**
	 * A buffer for reading data (not copied).
	 */
	public SshBuffer(byte[] data) {
		this(data, 0, data.length);
	}

	/**
	 * A buffer for reading data[off..off+len) (not copied).
	 */
	public SshBuffer(byte[] data, int off, int len) {
		this.data = data;
		this.rpos = off;
		this.wpos = off+len;
	}

	/**
	 * A buffer for reading the bytes from position to limit (copied if not array backed).
	 */
	public static SshBuffer wrap(ByteBuffer in) {
		if( in.hasArray() ) {
			return new SshBuffer(in.array(), in.arrayOffset()+in.position(), in.remaining());
		}
		byte[] tmp = new byte[in.remaining()];
		in.duplicate().get(tmp);
		return new SshBuffer(tmp);
	}

	/**
	 * @return a buffer for writing that starts with the message number
	 */
	public static SshBuffer message(int msg) {
		SshBuffer ret = new SshBuffer();
		ret.putByte(msg);
		return ret;
	}

	// ------------------------------------------------------------------ state

	/**
	 * @return bytes left to read
	 */
	public int available() {
		return wpos-rpos;
	}

	public int readPosition() {
		return rpos;
	}

	public void readPosition(int pos) {
		if( pos < 0 || pos > wpos ) {
			throw new IllegalArgumentException("position "+pos);
		}
		rpos = pos;
	}

	public int writePosition() {
		return wpos;
	}

	/**
	 * @return the backing array (the data is from readPosition() to writePosition())
	 */
	public byte[] array() {
		return data;
	}

	/**
	 * @return a copy of the unread bytes
	 */
	public byte[] toByteArray() {
		return Arrays.copyOfRange(data, rpos, wpos);
	}

	/**
	 * @return the unread bytes as a ByteBuffer (shares the array)
	 */
	public ByteBuffer toByteBuffer() {
		return ByteBuffer.wrap(data, rpos, wpos-rpos);
	}

	// ------------------------------------------------------------------ writing

	private void ensure(int len) {
		if( wpos+len > data.length ) {
			long size = Math.max((long) data.length*2, (long) wpos+len);
			if( size > Integer.MAX_VALUE-16 ) {
				throw new IllegalStateException("SshBuffer too large");
			}
			data = Arrays.copyOf(data, (int) size);
		}
	}

	public SshBuffer putByte(int b) {
		ensure(1);
		data[wpos++] = (byte) b;
		return this;
	}

	public SshBuffer putBoolean(boolean b) {
		return putByte(b ? 1 : 0);
	}

	/**
	 * uint32 (the low 32 bits of the value)
	 */
	public SshBuffer putInt(long v) {
		ensure(4);
		data[wpos++] = (byte) (v >>> 24);
		data[wpos++] = (byte) (v >>> 16);
		data[wpos++] = (byte) (v >>> 8);
		data[wpos++] = (byte) v;
		return this;
	}

	/**
	 * uint64
	 */
	public SshBuffer putLong(long v) {
		putInt(v >>> 32);
		return putInt(v);
	}

	/**
	 * Raw bytes, no length.
	 */
	public SshBuffer putRaw(byte[] b) {
		return putRaw(b, 0, b.length);
	}

	public SshBuffer putRaw(byte[] b, int off, int len) {
		ensure(len);
		System.arraycopy(b, off, data, wpos, len);
		wpos += len;
		return this;
	}

	/**
	 * string: uint32 length then the bytes.
	 */
	public SshBuffer putString(byte[] b) {
		return putString(b, 0, b.length);
	}

	public SshBuffer putString(byte[] b, int off, int len) {
		putInt(len);
		return putRaw(b, off, len);
	}

	/**
	 * string, UTF-8 encoded.
	 */
	public SshBuffer putString(String s) {
		return putString(s.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * mpint: two's complement, big endian, the fewest bytes; zero is the empty string.
	 */
	public SshBuffer putMpint(BigInteger v) {
		if( v.signum() == 0 ) {
			return putInt(0);
		}
		return putString(v.toByteArray());
	}

	/**
	 * mpint of a non-negative number given as unsigned big endian bytes (e.g. a shared secret).
	 */
	public SshBuffer putMpint(byte[] unsigned) {
		return putMpint(new BigInteger(1, unsigned));
	}

	/**
	 * name-list: the names joined with commas, as a string.
	 */
	public SshBuffer putNameList(List<String> names) {
		return putString(String.join(",", names));
	}

	/**
	 * The unread bytes of another buffer.
	 */
	public SshBuffer putBuffer(SshBuffer other) {
		return putRaw(other.data, other.rpos, other.available());
	}

	// ------------------------------------------------------------------ reading

	private void need(int len) throws SshException {
		if( len < 0 || len > wpos-rpos ) {
			throw new SshException("Malformed packet: need "+(len & 0xffffffffL)+" bytes, "+(wpos-rpos)+" left");
		}
	}

	public int getByte() throws SshException {
		need(1);
		return data[rpos++] & 0xff;
	}

	public boolean getBoolean() throws SshException {
		return getByte() != 0;
	}

	/**
	 * uint32 as a long (0 to 2^32-1).
	 */
	public long getUInt() throws SshException {
		need(4);
		long ret = ((data[rpos] & 0xffL) << 24) | ((data[rpos+1] & 0xffL) << 16) | ((data[rpos+2] & 0xffL) << 8) | (data[rpos+3] & 0xffL);
		rpos += 4;
		return ret;
	}

	/**
	 * uint32 that must fit an int (0 to 2^31-1), e.g. a length or a channel number.
	 */
	public int getInt() throws SshException {
		long ret = getUInt();
		if( ret > Integer.MAX_VALUE ) {
			throw new SshException("Malformed packet: value "+ret+" is too large");
		}
		return (int) ret;
	}

	public long getLong() throws SshException {
		return (getUInt() << 32) | getUInt();
	}

	public byte[] getRaw(int len) throws SshException {
		need(len);
		byte[] ret = Arrays.copyOfRange(data, rpos, rpos+len);
		rpos += len;
		return ret;
	}

	/**
	 * string as bytes; the length is checked against what is left before anything is allocated.
	 */
	public byte[] getString() throws SshException {
		long len = getUInt();
		if( len > wpos-rpos ) {
			throw new SshException("Malformed packet: string of "+len+" bytes, "+(wpos-rpos)+" left");
		}
		return getRaw((int) len);
	}

	/**
	 * string decoded as UTF-8.
	 */
	public String getStringUtf8() throws SshException {
		return new String(getString(), StandardCharsets.UTF_8);
	}

	public BigInteger getMpint() throws SshException {
		byte[] b = getString();
		return b.length == 0 ? BigInteger.ZERO : new BigInteger(b);
	}

	public List<String> getNameList() throws SshException {
		String s = new String(getString(), StandardCharsets.US_ASCII);
		if( s.isEmpty() ) {
			return Collections.emptyList();
		}
		List<String> ret = new ArrayList<String>();
		for (String name : s.split(",", -1)) {
			if( name.isEmpty() ) {
				throw new SshException("Malformed name-list: '"+s+"'");
			}
			ret.add(name);
		}
		return ret;
	}

	/**
	 * Skip len bytes.
	 */
	public void skip(int len) throws SshException {
		need(len);
		rpos += len;
	}

	@Override
	public String toString() {
		return "SshBuffer[read="+rpos+", write="+wpos+", capacity="+data.length+"]";
	}
}
