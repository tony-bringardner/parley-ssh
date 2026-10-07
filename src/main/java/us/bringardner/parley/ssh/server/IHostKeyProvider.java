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
package us.bringardner.parley.ssh.server;

import java.io.IOException;
import java.security.KeyPair;
import java.util.Collections;
import java.util.List;

import us.bringardner.parley.ssh.algorithms.SshCertificate;

/**
 * The server's host keys: what proves to clients that they reached this server.
 * Read when the server starts.
 *
 * @author Tony Bringardner
 * @see HostKeyProviders
 */
@FunctionalInterface
public interface IHostKeyProvider {

	/**
	 * @return the host key pairs (RSA and/or ECDSA), at least one
	 */
	List<KeyPair> getHostKeys() throws IOException;

	/**
	 * @return host certificates for some of the keys (OpenSSH's HostCertificate), so clients
	 * that trust the certificate authority trust this server without knowing its keys; none
	 * by default
	 */
	default List<SshCertificate> getHostCertificates() throws IOException {
		return Collections.emptyList();
	}
}
