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

import java.security.PrivateKey;

/**
 * A security key in software: signs like a FIDO device (PROTOCOL.u2f), with fixed flags and
 * a counter. For tests and emulation only: a real security key's private key never leaves
 * the device, which signs (through ssh-agent and OpenSSH's middleware).
 *
 * @author Tony Bringardner
 */
public final class SkSoftwareKey implements PrivateKey {

	private static final long serialVersionUID = 1L;

	private final PrivateKey key;
	private final String application;
	private final int flags;
	private int counter;

	/**
	 * @param key the EC P-256 or Ed25519 private key
	 * @param application as in the public key
	 * @param flags what the device reports, e.g. {@link SkSignature#FLAG_USER_PRESENT}
	 */
	public SkSoftwareKey(PrivateKey key, String application, int flags) {
		this.key = key;
		this.application = application;
		this.flags = flags;
	}

	public PrivateKey getKey() {
		return key;
	}

	public String getApplication() {
		return application;
	}

	public int getFlags() {
		return flags;
	}

	/** @return the next signature counter */
	synchronized int nextCounter() {
		return ++counter;
	}

	@Override
	public String getAlgorithm() {
		return key.getAlgorithm();
	}

	@Override
	public String getFormat() {
		return null;
	}

	@Override
	public byte[] getEncoded() {
		return null;
	}
}
