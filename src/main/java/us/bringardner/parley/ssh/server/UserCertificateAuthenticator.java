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

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

import us.bringardner.parley.core.BaseObject;
import us.bringardner.parley.core.util.AddressMatcher;
import us.bringardner.parley.net.server.IPrincipal;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.SshCertificate;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;

/**
 * Users log in with OpenSSH user certificates signed by a trusted certificate authority
 * (OpenSSH's TrustedUserCAKeys): no list of keys per user. A certificate may log in as a
 * user if:
 * <ul>
 * <li>its CA is one of these, and the signature is valid</li>
 * <li>it is a user certificate, valid now</li>
 * <li>it names one of the user's principals: the user name, unless
 * {@link #setPrincipals(Function)} says otherwise (OpenSSH's AuthorizedPrincipalsFile)</li>
 * <li>it has no critical option the server doesn't know, and source-address (if given)
 * lists the client's address</li>
 * </ul>
 * force-command and the permit-* extensions are applied to the session by the server.
 * <p>
 * Plain keys are not accepted; combine with authorized_keys with
 * {@code AuthorizedKeysAuthenticator.forHomes(dir).or(cas)}.
 *
 * @author Tony Bringardner
 */
public class UserCertificateAuthenticator extends BaseObject implements IPublicKeyAuthenticator {

	private static final List<String> KNOWN_CRITICAL = Arrays.asList(SshCertificate.FORCE_COMMAND, SshCertificate.SOURCE_ADDRESS);

	private final List<byte[]> cas;
	private volatile Function<String, Collection<String>> principals = Collections::singletonList;

	/**
	 * @param cas the trusted certificate authorities' keys
	 */
	public UserCertificateAuthenticator(Collection<PublicKey> cas) {
		List<byte[]> tmp = new ArrayList<byte[]>();
		for (PublicKey k : cas) {
			tmp.add(SshPublicKeys.encode(k));
		}
		this.cas = Collections.unmodifiableList(tmp);
	}

	/**
	 * @param file one CA public key per line ("type base64 comment"), as OpenSSH's TrustedUserCAKeys
	 */
	public static UserCertificateAuthenticator fromFile(File file) throws IOException {
		List<PublicKey> keys = new ArrayList<PublicKey>();
		for (String line : Files.readAllLines(file.toPath(), StandardCharsets.UTF_8)) {
			String l = line.trim();
			if( !l.isEmpty() && !l.startsWith("#") ) {
				keys.add(SshPublicKeys.fromOpenSsh(l));
			}
		}
		if( keys.isEmpty() ) {
			throw new SshException("No CA keys in "+file);
		}
		return new UserCertificateAuthenticator(keys);
	}

	/**
	 * @param principals the names a user's certificates may carry to log in as them (the
	 * user name by default); null or empty: the user can't log in with a certificate
	 */
	public UserCertificateAuthenticator setPrincipals(Function<String, Collection<String>> principals) {
		this.principals = principals;
		return this;
	}

	/**
	 * Plain keys: never.
	 */
	@Override
	public IPrincipal authenticate(String user, PublicKey key, IServerAuthContext context) {
		return null;
	}

	@Override
	public IPrincipal authenticate(String user, SshCertificate cert, IServerAuthContext context) throws IOException {
		String why = refusal(user, cert, context.getRemoteAddress());
		if( why != null ) {
			logInfo("Certificate refused for "+user+" ("+cert+"): "+why);
			return null;
		}
		return AuthorizedKeysAuthenticator.principal(user, context);
	}

	/**
	 * @return null if the certificate may log in as the user, else why not
	 */
	String refusal(String user, SshCertificate cert, SocketAddress from) {
		boolean trusted = false;
		byte[] ca = cert.getCaKeyBlob();
		for (byte[] c : cas) {
			trusted |= Arrays.equals(c, ca);
		}
		if( !trusted ) {
			return "its CA is not trusted";
		}
		Collection<String> names = principals.apply(user);
		if( names == null || names.isEmpty() ) {
			return "the user has no principals";
		}
		long now = System.currentTimeMillis()/1000;
		String why = null;
		for (String name : names) {
			why = cert.check(SshCertificate.USER, name, now);
			if( why == null ) {
				break;
			}
		}
		if( why != null ) {
			return why;
		}
		for (String option : cert.getCriticalOptions().keySet()) {
			if( !KNOWN_CRITICAL.contains(option) ) {
				return "unknown critical option "+option;
			}
		}
		String sources = cert.getCriticalOptions().get(SshCertificate.SOURCE_ADDRESS);
		if( sources != null ) {
			AddressMatcher m;
			try {
				m = AddressMatcher.parse(sources);
			} catch (IllegalArgumentException e) {
				return "bad source-address "+sources;
			}
			if( !(from instanceof InetSocketAddress) || ((InetSocketAddress) from).getAddress() == null
					|| !m.matches(((InetSocketAddress) from).getAddress()) ) {
				return "source-address "+sources+" doesn't allow "+from;
			}
		}
		return null;
	}
}
