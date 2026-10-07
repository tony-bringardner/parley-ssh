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

import java.security.PublicKey;
import java.util.Arrays;

/**
 * The public key of a FIDO security key (OpenSSH's PROTOCOL.u2f): an ECDSA P-256 or
 * Ed25519 key, and the application it was made for ("ssh:" for ssh-keygen -t ecdsa-sk /
 * ed25519-sk). Key types sk-ecdsa-sha2-nistp256@openssh.com and sk-ssh-ed25519@openssh.com.
 * The private key never leaves the device; servers only check its signatures.
 *
 * @author Tony Bringardner
 */
public final class SkPublicKey implements PublicKey {

	private static final long serialVersionUID = 1L;

	public static final String SK_ECDSA = "sk-ecdsa-sha2-nistp256@openssh.com";
	public static final String SK_ED25519 = "sk-ssh-ed25519@openssh.com";
	/** What ssh-keygen uses */
	public static final String DEFAULT_APPLICATION = "ssh:";

	private final String type;
	private final PublicKey key;
	private final String application;

	/**
	 * @param key an EC P-256 or an Ed25519 key
	 * @param application e.g. "ssh:"
	 */
	public SkPublicKey(PublicKey key, String application) {
		this.key = key;
		this.application = application;
		this.type = Ed25519.isEd25519(key) ? SK_ED25519 : SK_ECDSA;
		if( type.equals(SK_ECDSA) && !"ecdsa-sha2-nistp256".equals(SshPublicKeys.keyType(key)) ) {
			throw new IllegalArgumentException("Security keys are ECDSA P-256 or Ed25519, not "+SshPublicKeys.keyType(key));
		}
	}

	/**
	 * @return true for a security key type
	 */
	public static boolean isSkType(String type) {
		return SK_ECDSA.equals(type) || SK_ED25519.equals(type);
	}

	/** @return {@link #SK_ECDSA} or {@link #SK_ED25519} */
	public String getType() {
		return type;
	}

	/** @return the EC or Ed25519 key */
	public PublicKey getKey() {
		return key;
	}

	public String getApplication() {
		return application;
	}

	@Override
	public String getAlgorithm() {
		return type;
	}

	/** @return "SSH": the encoding is the SSH key blob */
	@Override
	public String getFormat() {
		return "SSH";
	}

	@Override
	public byte[] getEncoded() {
		return SshPublicKeys.encode(this);
	}

	@Override
	public boolean equals(Object o) {
		return o instanceof SkPublicKey && Arrays.equals(getEncoded(), ((SkPublicKey) o).getEncoded());
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(getEncoded());
	}

	@Override
	public String toString() {
		return type+" "+SshPublicKeys.fingerprint(this)+" ("+application+")";
	}
}
