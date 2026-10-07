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
import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshConstants;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.ISignatureAlgorithm;
import us.bringardner.parley.ssh.algorithms.SkPublicKey;
import us.bringardner.parley.ssh.algorithms.SkSignature;
import us.bringardner.parley.ssh.algorithms.SshCertificate;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;

/**
 * "publickey" (RFC 4252 7): a query (no signature) is answered with PK_OK if the key may
 * log in; a signed request is checked against the session id and the request, then the
 * authenticator decides whose key it is. Only the server's signature algorithms are
 * accepted (SHA-1 ssh-rsa only if turned on). A key with an OpenSSH certificate goes to the
 * authenticator's certificate method.
 *
 * @author Tony Bringardner
 */
public class PublicKeyAuthMethod implements IServerAuthMethod {

	/** The auth context attribute that holds the certificate the user logged in with */
	public static final String CERTIFICATE = PublicKeyAuthMethod.class.getName()+".certificate";
	/** The auth context attribute that holds the logged in key's {@link KeyRestrictions} */
	public static final String RESTRICTIONS = PublicKeyAuthMethod.class.getName()+".restrictions";

	private final IPublicKeyAuthenticator authenticator;

	public PublicKeyAuthMethod(IPublicKeyAuthenticator authenticator) {
		this.authenticator = authenticator;
	}

	@Override
	public String getName() {
		return "publickey";
	}

	/**
	 * A security key's signature says whether the user touched it and was verified: what the
	 * key, its certificate and the server require (PROTOCOL.u2f, as OpenSSH's sshd checks).
	 */
	private static boolean securityKeyFlagsOk(SshServer server, KeyRestrictions r, int flags, String user) {
		boolean touch = r.isTouchRequired() || server.isSecurityKeyTouchRequired();
		boolean verify = r.isVerifyRequired() || server.isSecurityKeyVerifyRequired();
		if( touch && (flags & SkSignature.FLAG_USER_PRESENT) == 0 ) {
			server.logInfo("Security key login refused for "+user+": the key wasn't touched");
			return false;
		}
		if( verify && (flags & SkSignature.FLAG_USER_VERIFIED) == 0 ) {
			server.logInfo("Security key login refused for "+user+": the user wasn't verified (PIN)");
			return false;
		}
		return true;
	}

	@Override
	public Result request(IServerAuthContext context, String user, SshBuffer data) throws IOException {
		boolean signed = data.getBoolean();
		String alg = data.getStringUtf8();
		byte[] blob = data.getString();
		ISignatureAlgorithm sig = context.getServer().getAlgorithms().findHostKeyAlgorithm(alg);
		if( sig == null || !sig.getKeyType().equals(SshPublicKeys.blobType(blob)) ) {
			return Result.FAILURE;
		}
		PublicKey key;
		SshCertificate cert = null;
		try {
			if( SshCertificate.isCertificateType(sig.getKeyType()) ) {
				cert = SshCertificate.decode(blob);
				key = cert.getPublicKey();
			} else {
				key = SshPublicKeys.decode(blob);
			}
		} catch (SshException e) {
			return Result.FAILURE;
		}
		us.bringardner.parley.ssh.keys.KeyRevocationList revoked = context.getServer().getRevokedKeys();
		if( revoked != null && (cert != null ? revoked.isRevoked(cert) : revoked.isRevoked(blob)) ) {
			context.getServer().logInfo("Revoked "+(cert != null ? "certificate "+cert : "key "+SshPublicKeys.fingerprint(blob))+" refused for "+user);
			return Result.FAILURE;
		}
		// The authenticator may say what the key may do (authorized_keys options)
		context.getAttributes().remove(KeyRestrictions.ATTRIBUTE);
		IPrincipal p = cert != null ? authenticator.authenticate(user, cert, context) : authenticator.authenticate(user, key, context);
		KeyRestrictions line = (KeyRestrictions) context.getAttributes().remove(KeyRestrictions.ATTRIBUTE);
		KeyRestrictions r;
		if( cert != null ) {
			// The certificate's, and the cert-authority line's when there is one
			r = line == null ? KeyRestrictions.of(cert) : line.and(KeyRestrictions.of(cert));
			if( r == null ) {
				// The certificate and the authorized_keys line force different commands
				return Result.FAILURE;
			}
		} else {
			r = line == null ? KeyRestrictions.NONE : line;
		}
		if( p == null ) {
			return Result.FAILURE;
		}
		if( !signed ) {
			context.send(SshBuffer.message(SshConstants.SSH_MSG_USERAUTH_60).putString(alg).putString(blob));
			return Result.PENDING;
		}
		byte[] signature = data.getString();
		SshBuffer b = new SshBuffer();
		b.putString(context.getSessionId());
		b.putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
		b.putString(user);
		b.putString(context.getService());
		b.putString(getName());
		b.putBoolean(true);
		b.putString(alg);
		b.putString(blob);
		if( !sig.verify(key, b.toByteArray(), signature) ) {
			return Result.FAILURE;
		}
		if( key instanceof SkPublicKey && !securityKeyFlagsOk(context.getServer(), r, SkSignature.flags(signature), user) ) {
			return Result.FAILURE;
		}
		if( cert != null ) {
			context.getAttributes().put(CERTIFICATE, cert);
		}
		// The session applies them (see ServerSession.getKeyRestrictions)
		context.getAttributes().put(RESTRICTIONS, r);
		return Result.success(p);
	}
}
