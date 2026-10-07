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

import java.security.GeneralSecurityException;

/**
 * A packet MAC (RFC 4253 section 6.4): computed over the packet's sequence number and the
 * packet, either before encryption or, for the "-etm@openssh.com" variants
 * (encrypt-then-MAC), over the encrypted packet.
 * <p>
 * An instance holds the key of one direction of one connection.
 *
 * @author Tony Bringardner
 */
public interface ISshMac {

	String getName();

	/** Key length in bytes */
	int getKeySize();

	/** MAC length in bytes */
	int getMacSize();

	/**
	 * @return true for encrypt-then-MAC: the packet length is sent in clear and the MAC covers
	 * the encrypted packet
	 */
	boolean isEncryptThenMac();

	void init(byte[] key) throws GeneralSecurityException;

	/**
	 * @return the MAC of uint32 sequence number || data[off..off+len)
	 */
	byte[] compute(long sequence, byte[] data, int off, int len);
}
