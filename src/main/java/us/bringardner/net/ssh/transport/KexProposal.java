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

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import us.bringardner.net.ssh.SshBuffer;
import us.bringardner.net.ssh.SshConstants;
import us.bringardner.net.ssh.SshException;

/**
 * An SSH_MSG_KEXINIT (RFC 4253 7.1): a random cookie, ten name-lists and the
 * first_kex_packet_follows flag. The payload is kept, it goes into the exchange hash as is.
 *
 * @author Tony Bringardner
 */
public final class KexProposal {

	public static final int KEX = 0;
	public static final int HOST_KEY = 1;
	public static final int CIPHER_C2S = 2;
	public static final int CIPHER_S2C = 3;
	public static final int MAC_C2S = 4;
	public static final int MAC_S2C = 5;
	public static final int COMPRESSION_C2S = 6;
	public static final int COMPRESSION_S2C = 7;
	public static final int LANGUAGE_C2S = 8;
	public static final int LANGUAGE_S2C = 9;
	private static final int LISTS = 10;

	private final List<List<String>> lists;
	private final boolean firstKexPacketFollows;
	private final byte[] payload;

	private KexProposal(List<List<String>> lists, boolean firstKexPacketFollows, byte[] payload) {
		this.lists = lists;
		this.firstKexPacketFollows = firstKexPacketFollows;
		this.payload = payload;
	}

	/**
	 * @param lists the ten name-lists, in order (KEX ... LANGUAGE_S2C)
	 */
	public static KexProposal create(SecureRandom random, List<List<String>> lists) {
		if( lists.size() != LISTS ) {
			throw new IllegalArgumentException("A KEXINIT has "+LISTS+" name-lists");
		}
		byte[] cookie = new byte[16];
		random.nextBytes(cookie);
		SshBuffer b = SshBuffer.message(SshConstants.SSH_MSG_KEXINIT);
		b.putRaw(cookie);
		List<List<String>> copy = new ArrayList<List<String>>();
		for (List<String> list : lists) {
			b.putNameList(list);
			copy.add(Collections.unmodifiableList(new ArrayList<String>(list)));
		}
		b.putBoolean(false);
		// reserved
		b.putInt(0);
		return new KexProposal(Collections.unmodifiableList(copy), false, b.toByteArray());
	}

	/**
	 * @param payload a whole SSH_MSG_KEXINIT payload, starting with the message number
	 */
	public static KexProposal parse(byte[] payload) throws SshException {
		SshBuffer b = new SshBuffer(payload);
		if( b.getByte() != SshConstants.SSH_MSG_KEXINIT ) {
			throw new SshException("Not a KEXINIT");
		}
		b.skip(16);
		List<List<String>> lists = new ArrayList<List<String>>();
		for (int i = 0; i < LISTS; i++) {
			lists.add(Collections.unmodifiableList(b.getNameList()));
		}
		boolean follows = b.getBoolean();
		b.getUInt();
		return new KexProposal(Collections.unmodifiableList(lists), follows, payload);
	}

	public List<String> get(int index) {
		return lists.get(index);
	}

	public boolean isFirstKexPacketFollows() {
		return firstKexPacketFollows;
	}

	/**
	 * @return the payload as sent (shared, don't change it)
	 */
	public byte[] getPayload() {
		return payload;
	}

	@Override
	public String toString() {
		return "KexProposal"+lists;
	}
}
