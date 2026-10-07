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
package us.bringardner.net.ssh.keys;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * A minimal DER reader, enough for the private key formats (PKCS#1, PKCS#8, SEC1, PBES2).
 * Reads one element at a time; constructed elements return a reader for their contents.
 *
 * @author Tony Bringardner
 */
final class Der {

	static final int INTEGER = 0x02;
	static final int BIT_STRING = 0x03;
	static final int OCTET_STRING = 0x04;
	static final int NULL = 0x05;
	static final int OID = 0x06;
	static final int SEQUENCE = 0x30;

	private final byte[] data;
	private int pos;
	private final int end;

	Der(byte[] data) {
		this(data, 0, data.length);
	}

	private Der(byte[] data, int off, int len) {
		this.data = data;
		this.pos = off;
		this.end = off+len;
	}

	boolean hasMore() {
		return pos < end;
	}

	int peekTag() throws IOException {
		if( pos >= end ) {
			throw new IOException("DER: no more elements");
		}
		return data[pos] & 0xff;
	}

	/**
	 * @return the contents of the next element, which must have this tag
	 */
	private int[] element(int tag) throws IOException {
		int t = peekTag();
		if( t != tag ) {
			throw new IOException("DER: expected tag 0x"+Integer.toHexString(tag)+", found 0x"+Integer.toHexString(t));
		}
		pos++;
		if( pos >= end ) {
			throw new IOException("DER: truncated");
		}
		int len = data[pos++] & 0xff;
		if( len >= 0x80 ) {
			int n = len & 0x7f;
			if( n < 1 || n > 3 || pos+n > end ) {
				throw new IOException("DER: bad length");
			}
			len = 0;
			for (int i = 0; i < n; i++) {
				len = (len << 8) | (data[pos++] & 0xff);
			}
		}
		if( len < 0 || pos+len > end ) {
			throw new IOException("DER: element longer than its container");
		}
		int start = pos;
		pos += len;
		return new int[] {start, len};
	}

	Der sequence() throws IOException {
		int[] e = element(SEQUENCE);
		return new Der(data, e[0], e[1]);
	}

	/**
	 * @return the contents of the context specific constructed element [n], or null if the
	 * next element isn't one (it is optional)
	 */
	Der explicit(int n) throws IOException {
		if( !hasMore() || peekTag() != (0xa0 | n) ) {
			return null;
		}
		int[] e = element(0xa0 | n);
		return new Der(data, e[0], e[1]);
	}

	BigInteger integer() throws IOException {
		int[] e = element(INTEGER);
		return new BigInteger(Arrays.copyOfRange(data, e[0], e[0]+e[1]));
	}

	byte[] octetString() throws IOException {
		int[] e = element(OCTET_STRING);
		return Arrays.copyOfRange(data, e[0], e[0]+e[1]);
	}

	/**
	 * @return the bits, without the unused-bits byte (which must be 0)
	 */
	byte[] bitString() throws IOException {
		int[] e = element(BIT_STRING);
		if( e[1] < 1 || data[e[0]] != 0 ) {
			throw new IOException("DER: unsupported BIT STRING");
		}
		return Arrays.copyOfRange(data, e[0]+1, e[0]+e[1]);
	}

	/**
	 * @return the object identifier in dotted form, e.g. "1.2.840.113549.1.1.1"
	 */
	String oid() throws IOException {
		int[] e = element(OID);
		StringBuilder sb = new StringBuilder();
		long v = 0;
		boolean first = true;
		for (int i = e[0]; i < e[0]+e[1]; i++) {
			int b = data[i] & 0xff;
			v = (v << 7) | (b & 0x7f);
			if( (b & 0x80) == 0 ) {
				if( first ) {
					long a = Math.min(v/40, 2);
					sb.append(a).append('.').append(v-a*40);
					first = false;
				} else {
					sb.append('.').append(v);
				}
				v = 0;
			}
		}
		return sb.toString();
	}

	/**
	 * Skip the next element, whatever it is.
	 */
	void skip() throws IOException {
		element(peekTag());
	}
}
