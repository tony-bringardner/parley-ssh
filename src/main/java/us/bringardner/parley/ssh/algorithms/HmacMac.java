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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * hmac-sha2-256, hmac-sha2-512 (RFC 6668) and their -etm@openssh.com variants.
 * hmac-sha1 is available for old peers but not offered by default.
 *
 * @author Tony Bringardner
 */
public class HmacMac implements ISshMac {

	private final String name;
	private final String jceName;
	private final int size;
	private final boolean etm;
	private Mac mac;

	/**
	 * @param name the SSH name
	 * @param jceName the JCE name (HmacSHA256...)
	 * @param size key and MAC length in bytes
	 * @param etm true for encrypt-then-MAC
	 */
	public HmacMac(String name, String jceName, int size, boolean etm) {
		this.name = name;
		this.jceName = jceName;
		this.size = size;
		this.etm = etm;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int getKeySize() {
		return size;
	}

	@Override
	public int getMacSize() {
		return size;
	}

	@Override
	public boolean isEncryptThenMac() {
		return etm;
	}

	@Override
	public void init(byte[] key) throws GeneralSecurityException {
		Mac tmp = Mac.getInstance(jceName);
		tmp.init(new SecretKeySpec(key, 0, size, jceName));
		mac = tmp;
	}

	@Override
	public byte[] compute(long sequence, byte[] data, int off, int len) {
		mac.update((byte) (sequence >>> 24));
		mac.update((byte) (sequence >>> 16));
		mac.update((byte) (sequence >>> 8));
		mac.update((byte) sequence);
		mac.update(data, off, len);
		return mac.doFinal();
	}
}
