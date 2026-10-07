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
package us.bringardner.net.ssh.server;

import java.io.IOException;
import java.security.PublicKey;

import us.bringardner.net.framework.server.IPrincipal;
import us.bringardner.net.ssh.SshBuffer;
import us.bringardner.net.ssh.SshConstants;
import us.bringardner.net.ssh.SshException;
import us.bringardner.net.ssh.algorithms.ISignatureAlgorithm;
import us.bringardner.net.ssh.algorithms.SshPublicKeys;

/**
 * "publickey" (RFC 4252 7): a query (no signature) is answered with PK_OK if the key may
 * log in; a signed request is checked against the session id and the request, then the
 * authenticator decides whose key it is. Only the server's signature algorithms are
 * accepted (SHA-1 ssh-rsa only if turned on).
 *
 * @author Tony Bringardner
 */
public class PublicKeyAuthMethod implements IServerAuthMethod {

	private final IPublicKeyAuthenticator authenticator;

	public PublicKeyAuthMethod(IPublicKeyAuthenticator authenticator) {
		this.authenticator = authenticator;
	}

	@Override
	public String getName() {
		return "publickey";
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
		try {
			key = SshPublicKeys.decode(blob);
		} catch (SshException e) {
			return Result.FAILURE;
		}
		IPrincipal p = authenticator.authenticate(user, key, context);
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
		return sig.verify(key, b.toByteArray(), signature) ? Result.success(p) : Result.FAILURE;
	}
}
