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

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import us.bringardner.net.ssh.SshBuffer;
import us.bringardner.net.ssh.algorithms.ISshCipher;
import us.bringardner.net.ssh.algorithms.ISshMac;

/**
 * Builds SSH binary packets (RFC 4253 6): length, random padding to the block size, then
 * encryption and MAC (or AEAD) with the current keys and sequence number.
 * <p>
 * Not thread safe: packets must be encoded in the order they are sent, which the transport
 * does under its lock.
 *
 * @author Tony Bringardner
 */
public class SshPacketEncoder {

	private final SecureRandom random;
	private ISshCipher cipher;
	private ISshMac mac;
	private us.bringardner.net.ssh.algorithms.ZlibCompression compression;
	private long sequence;
	private volatile long bytesSinceKeys;
	private volatile long packetsSinceKeys;

	public SshPacketEncoder(SecureRandom random) {
		this.random = random;
	}

	/**
	 * Use new keys for the next packet (after sending SSH_MSG_NEWKEYS).
	 */
	public void setKeys(ISshCipher cipher, ISshMac mac) {
		this.cipher = cipher;
		this.mac = mac;
		bytesSinceKeys = 0;
		packetsSinceKeys = 0;
	}

	/**
	 * Compress every payload from the next packet on.
	 */
	public void setCompression(us.bringardner.net.ssh.algorithms.ZlibCompression compression) {
		this.compression = compression;
	}

	public boolean isCompressing() {
		return compression != null;
	}

	/**
	 * Strict key exchange: the sequence number starts again at 0 after each NEWKEYS.
	 */
	public void resetSequence() {
		sequence = 0;
	}

	public long getSequence() {
		return sequence;
	}

	public long getBytesSinceKeys() {
		return bytesSinceKeys;
	}

	public long getPacketsSinceKeys() {
		return packetsSinceKeys;
	}

	/**
	 * @param payload the message (its unread bytes)
	 * @return the packet to write
	 */
	public ByteBuffer encode(SshBuffer payload) throws GeneralSecurityException {
		if( compression != null ) {
			payload = new SshBuffer(compression.compress(payload.array(), payload.readPosition(), payload.available()));
		}
		int payloadLength = payload.available();
		boolean aead = cipher != null && cipher.isAead();
		boolean etm = !aead && mac != null && mac.isEncryptThenMac();
		boolean clearLength = aead || etm;
		int bs = cipher == null ? 8 : Math.max(8, cipher.getBlockSize());
		// What must be a multiple of the block size: the packet, without the length when it is in clear
		int aligned = (clearLength ? 0 : 4)+1+payloadLength;
		int padding = bs-(aligned % bs);
		if( padding < 4 ) {
			padding += bs;
		}
		int length = 1+payloadLength+padding;
		int tail = aead ? cipher.getTagSize() : (mac == null ? 0 : mac.getMacSize());
		byte[] packet = new byte[4+length+tail];
		packet[0] = (byte) (length >>> 24);
		packet[1] = (byte) (length >>> 16);
		packet[2] = (byte) (length >>> 8);
		packet[3] = (byte) length;
		packet[4] = (byte) padding;
		System.arraycopy(payload.array(), payload.readPosition(), packet, 5, payloadLength);
		byte[] pad = new byte[padding];
		random.nextBytes(pad);
		System.arraycopy(pad, 0, packet, 5+payloadLength, padding);

		if( aead ) {
			cipher.setSequence(sequence);
			cipher.encryptAead(packet, 0, 4, 4, length);
		} else if( etm ) {
			if( cipher != null ) {
				cipher.update(packet, 4, length);
			}
			byte[] m = mac.compute(sequence, packet, 0, 4+length);
			System.arraycopy(m, 0, packet, 4+length, m.length);
		} else {
			if( mac != null ) {
				byte[] m = mac.compute(sequence, packet, 0, 4+length);
				System.arraycopy(m, 0, packet, 4+length, m.length);
			}
			if( cipher != null ) {
				cipher.update(packet, 0, 4+length);
			}
		}
		sequence = (sequence+1) & 0xffffffffL;
		bytesSinceKeys += packet.length;
		packetsSinceKeys++;
		return ByteBuffer.wrap(packet);
	}
}
