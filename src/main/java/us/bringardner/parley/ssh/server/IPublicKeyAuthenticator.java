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
import java.security.PublicKey;

import us.bringardner.parley.net.server.IPrincipal;
import us.bringardner.parley.ssh.algorithms.SshCertificate;

/**
 * Decides whether a public key may log in as a user (for "publickey"). The signature is
 * checked by the method; this only says whose key it is.
 *
 * @author Tony Bringardner
 * @see AuthorizedKeysAuthenticator
 * @see UserCertificateAuthenticator
 */
@FunctionalInterface
public interface IPublicKeyAuthenticator {

	/**
	 * @return the user, if the key may log in as them; null if not
	 */
	IPrincipal authenticate(String user, PublicKey key, IServerAuthContext context) throws IOException;

	/**
	 * A key offered with an OpenSSH certificate. The certificate's restrictions
	 * (force-command, permit-pty...) are applied to the session by the server.
	 *
	 * @return the user, if the certificate may log in as them; null (the default: no
	 * certificate authorities) if not
	 */
	default IPrincipal authenticate(String user, SshCertificate certificate, IServerAuthContext context) throws IOException {
		return null;
	}

	/**
	 * @return an authenticator that asks this one, then the other: e.g. authorized_keys or a
	 * trusted certificate authority
	 */
	default IPublicKeyAuthenticator or(IPublicKeyAuthenticator other) {
		IPublicKeyAuthenticator first = this;
		return new IPublicKeyAuthenticator() {
			@Override
			public IPrincipal authenticate(String user, PublicKey key, IServerAuthContext context) throws IOException {
				IPrincipal p = first.authenticate(user, key, context);
				return p != null ? p : other.authenticate(user, key, context);
			}

			@Override
			public IPrincipal authenticate(String user, SshCertificate certificate, IServerAuthContext context) throws IOException {
				IPrincipal p = first.authenticate(user, certificate, context);
				return p != null ? p : other.authenticate(user, certificate, context);
			}
		};
	}
}
