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
package us.bringardner.parley.ssh.client;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import us.bringardner.parley.ssh.algorithms.SshPublicKeys;

/**
 * Simple host key verifiers.
 *
 * @author Tony Bringardner
 */
public final class HostKeyVerifiers {

	private HostKeyVerifiers() {
	}

	/**
	 * Trusts every key: anyone between the client and the server can pretend to be the server.
	 * For tests only.
	 */
	public static IHostKeyVerifier acceptAll() {
		return (host, port, key) -> true;
	}

	/**
	 * Trusts only these keys (pinned), whatever the host.
	 */
	public static IHostKeyVerifier only(PublicKey... keys) {
		List<PublicKey> trusted = Arrays.asList(keys.clone());
		return new IHostKeyVerifier() {
			@Override
			public boolean verify(String host, int port, PublicKey key) {
				byte[] blob = SshPublicKeys.encode(key);
				for (PublicKey t : trusted) {
					if( Arrays.equals(blob, SshPublicKeys.encode(t)) ) {
						return true;
					}
				}
				return false;
			}

			@Override
			public List<String> getKnownKeyTypes(String host, int port) {
				String[] types = new String[trusted.size()];
				for (int i = 0; i < types.length; i++) {
					types[i] = SshPublicKeys.keyType(trusted.get(i));
				}
				return Collections.unmodifiableList(Arrays.asList(types));
			}
		};
	}
}
