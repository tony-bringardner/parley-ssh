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
package us.bringardner.net.ssh.transport;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import us.bringardner.net.framework.nio.IFrameDecoder;
import us.bringardner.net.ssh.SshConstants;
import us.bringardner.net.ssh.SshException;
import us.bringardner.net.ssh.algorithms.ISshCipher;
import us.bringardner.net.ssh.algorithms.ISshMac;

/**
 * Reads SSH binary packets (RFC 4253 6) from a connection: decrypts them, checks the MAC or
 * AEAD tag and returns each payload as a frame. A connection switches to this decoder after
 * the identification line; the transport gives it new keys on SSH_MSG_NEWKEYS.
 * <p>
 * Three layouts: no MAC or a MAC over the plain packet (the first block is decrypted to read
 * the length), encrypt-then-MAC and AEAD (the length is sent in clear). The first decrypted
 * block is kept between calls, a cipher's stream can't be rewound.
 * <p>
 * Used only on the connection's handler thread, except the counters which any thread may read.
 *
 * @author Tony Bringardner
 */
public class SshPacketDecoder implements IFrameDecoder {

	/** Largest packet accepted by default (RFC 4253 asks for at least 35000) */
	public static final int DEFAULT_MAX_PACKET = 256*1024;

	private final int maxPacket;
	private ISshCipher cipher;
	private ISshMac mac;
	private long sequence;
	// The first block of a packet, decrypted (layout 1 only), and its packet_length
	private byte[] first;
	private int length = -1;
	private volatile long bytesSinceKeys;
	private volatile long packetsSinceKeys;

	public SshPacketDecoder() {
		this(DEFAULT_MAX_PACKET);
	}

	public SshPacketDecoder(int maxPacket) {
		this.maxPacket = maxPacket;
	}

	/**
	 * Use new keys from the next packet on (SSH_MSG_NEWKEYS).
	 *
	 * @param cipher initialized for decryption, or null for none
	 * @param mac initialized, or null (none, or an AEAD cipher)
	 */
	public void setKeys(ISshCipher cipher, ISshMac mac) {
		if( first != null ) {
			throw new IllegalStateException("Keys changed in the middle of a packet");
		}
		this.cipher = cipher;
		this.mac = mac;
		bytesSinceKeys = 0;
		packetsSinceKeys = 0;
	}

	/**
	 * Strict key exchange: the sequence number starts again at 0 after each NEWKEYS.
	 */
	public void resetSequence() {
		sequence = 0;
	}

	/**
	 * @return the sequence number of the next packet
	 */
	public long getSequence() {
		return sequence;
	}

	/**
	 * @return the sequence number of the last packet returned (for SSH_MSG_UNIMPLEMENTED)
	 */
	public long getLastSequence() {
		return (sequence-1) & 0xffffffffL;
	}

	public long getBytesSinceKeys() {
		return bytesSinceKeys;
	}

	public long getPacketsSinceKeys() {
		return packetsSinceKeys;
	}

	@Override
	public ByteBuffer decode(ByteBuffer in) throws IOException {
		try {
			boolean aead = cipher != null && cipher.isAead();
			boolean etm = !aead && mac != null && mac.isEncryptThenMac();
			return (aead || etm) ? decodeClearLength(in, aead) : decodeEncryptedLength(in);
		} catch (GeneralSecurityException e) {
			throw new SshException(SshConstants.SSH_DISCONNECT_MAC_ERROR, "Corrupt packet: "+e.getMessage(), e);
		}
	}

	private int blockSize() {
		return cipher == null ? 8 : Math.max(8, cipher.getBlockSize());
	}

	private void checkLength(long len, boolean whole) throws SshException {
		if( len < 5 || len > maxPacket ) {
			throw new SshException("Bad packet length "+len);
		}
		// The packet (with the length field unless it is sent in clear) is a multiple of the block size
		if( ((whole ? len+4 : len) % blockSize()) != 0 ) {
			throw new SshException("Packet length "+len+" is not a multiple of the block size");
		}
	}

	/**
	 * No MAC, or a MAC over the plain packet: packet_length is in the first encrypted block.
	 */
	private ByteBuffer decodeEncryptedLength(ByteBuffer in) throws IOException, GeneralSecurityException {
		int bs = blockSize();
		if( first == null ) {
			if( in.remaining() < bs ) {
				return null;
			}
			byte[] tmp = new byte[bs];
			in.get(tmp);
			if( cipher != null ) {
				cipher.update(tmp, 0, bs);
			}
			long len = ((tmp[0] & 0xffL) << 24) | ((tmp[1] & 0xffL) << 16) | ((tmp[2] & 0xffL) << 8) | (tmp[3] & 0xffL);
			checkLength(len, true);
			first = tmp;
			length = (int) len;
		}
		int macSize = mac == null ? 0 : mac.getMacSize();
		int rest = 4+length-bs;
		if( in.remaining() < rest+macSize ) {
			return null;
		}
		byte[] packet = new byte[4+length];
		System.arraycopy(first, 0, packet, 0, bs);
		in.get(packet, bs, rest);
		if( cipher != null ) {
			cipher.update(packet, bs, rest);
		}
		first = null;
		if( mac != null ) {
			byte[] got = new byte[macSize];
			in.get(got);
			byte[] want = mac.compute(sequence, packet, 0, packet.length);
			if( !MessageDigest.isEqual(got, want) ) {
				throw new SshException(SshConstants.SSH_DISCONNECT_MAC_ERROR, "Corrupt MAC on input");
			}
		}
		return payload(packet, 4, length, macSize);
	}

	/**
	 * Encrypt-then-MAC and AEAD: packet_length is in clear (authenticated).
	 */
	private ByteBuffer decodeClearLength(ByteBuffer in, boolean aead) throws IOException, GeneralSecurityException {
		if( in.remaining() < 4 ) {
			return null;
		}
		int pos = in.position();
		long len = in.getInt(pos) & 0xffffffffL;
		checkLength(len, false);
		int tail = aead ? cipher.getTagSize() : mac.getMacSize();
		if( in.remaining() < 4+len+tail ) {
			return null;
		}
		byte[] packet = new byte[4+(int) len+tail];
		in.get(packet);
		if( aead ) {
			cipher.decryptAead(packet, 0, 4, 4, (int) len);
		} else {
			byte[] want = mac.compute(sequence, packet, 0, 4+(int) len);
			byte[] got = new byte[tail];
			System.arraycopy(packet, 4+(int) len, got, 0, tail);
			if( !MessageDigest.isEqual(got, want) ) {
				throw new SshException(SshConstants.SSH_DISCONNECT_MAC_ERROR, "Corrupt MAC on input");
			}
			if( cipher != null ) {
				cipher.update(packet, 4, (int) len);
			}
		}
		return payload(packet, 4, (int) len, 0);
	}

	/**
	 * @param packet the plain packet
	 * @param off where padding_length is
	 * @param len packet_length
	 */
	private ByteBuffer payload(byte[] packet, int off, int len, int macSize) throws SshException {
		int padding = packet[off] & 0xff;
		if( padding < 4 || padding > len-1 ) {
			throw new SshException("Bad padding length "+padding);
		}
		int payloadLength = len-1-padding;
		if( payloadLength < 1 ) {
			throw new SshException("Empty packet");
		}
		sequence = (sequence+1) & 0xffffffffL;
		bytesSinceKeys += 4+len+macSize;
		packetsSinceKeys++;
		return ByteBuffer.wrap(packet, off+1, payloadLength).slice();
	}
}
