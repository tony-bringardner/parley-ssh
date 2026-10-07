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

import java.util.function.Supplier;

/**
 * Makes an algorithm by its SSH name (e.g. "aes128-ctr"). Every algorithm kind (key exchange,
 * cipher, MAC, host key signature) is registered in {@link SshAlgorithms} as one of these, so
 * new algorithms are added without changing the transport.
 *
 * @param <T> the algorithm type
 * @author Tony Bringardner
 */
public interface NamedFactory<T> {

	/**
	 * @return the algorithm's name, as sent in SSH_MSG_KEXINIT
	 */
	String getName();

	/**
	 * @return a new instance (instances keep state, e.g. a cipher's keys, so they are not shared)
	 */
	T create();

	/**
	 * @return true if this JVM can run the algorithm (e.g. Ed25519 needs Java 15). Unsupported
	 * algorithms are left out of the proposal.
	 */
	default boolean isSupported() {
		return true;
	}

	static <T> NamedFactory<T> of(String name, Supplier<T> supplier) {
		return new NamedFactory<T>() {
			@Override
			public String getName() {
				return name;
			}

			@Override
			public T create() {
				return supplier.get();
			}

			@Override
			public String toString() {
				return name;
			}
		};
	}
}
