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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshConstants;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.ISignatureAlgorithm;
import us.bringardner.parley.ssh.algorithms.SshAlgorithms;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;

/**
 * "publickey" authentication (RFC 4252 7). For each key in turn, ask whether the server
 * would accept it (no signature, so keys the server doesn't know are never used to sign);
 * on SSH_MSG_USERAUTH_PK_OK, send the signed request.
 * <p>
 * RSA keys sign with rsa-sha2-512 or rsa-sha2-256 (RFC 8332), whichever the server's
 * server-sig-algs lists first in that order; rsa-sha2-256 if it doesn't say. SHA-1 "ssh-rsa"
 * is used only if the server lists nothing else and it is in the session's host key
 * algorithms (turned on by name).
 *
 * @author Tony Bringardner
 */
public class PublicKeyAuth implements IClientAuthMethod {

	private final List<KeyPair> keys;
	private int next;
	private KeyPair current;
	private String currentAlgorithm;
	private byte[] currentBlob;

	public PublicKeyAuth(KeyPair... keys) {
		this(Arrays.asList(keys));
	}

	public PublicKeyAuth(Collection<KeyPair> keys) {
		this.keys = new ArrayList<KeyPair>(keys);
	}

	@Override
	public String getName() {
		return "publickey";
	}

	@Override
	public boolean start(IClientAuthContext context) throws IOException {
		return tryNext(context);
	}

	@Override
	public boolean retry(IClientAuthContext context) throws IOException {
		return tryNext(context);
	}

	private boolean tryNext(IClientAuthContext context) throws IOException {
		while( next < keys.size() ) {
			KeyPair key = keys.get(next++);
			String alg = algorithm(key, context);
			if( alg == null ) {
				continue;
			}
			current = key;
			currentAlgorithm = alg;
			currentBlob = SshPublicKeys.encode(key.getPublic());
			context.send(context.newRequest(getName()).putBoolean(false).putString(alg).putString(currentBlob));
			return true;
		}
		return false;
	}

	/**
	 * @return the signature algorithm for the key, or null if it can't be used
	 */
	static String algorithm(KeyPair key, IClientAuthContext context) {
		String type;
		try {
			type = SshPublicKeys.keyType(key.getPublic());
		} catch (IllegalArgumentException e) {
			return null;
		}
		if( !SshPublicKeys.SSH_RSA.equals(type) ) {
			return SshAlgorithms.findSignature(type) == null ? null : type;
		}
		List<String> server = context.getServerSignatureAlgorithms();
		if( server.isEmpty() ) {
			return "rsa-sha2-256";
		}
		for (String alg : new String[] {"rsa-sha2-512", "rsa-sha2-256"}) {
			if( server.contains(alg) ) {
				return alg;
			}
		}
		if( server.contains("ssh-rsa") && context.getAlgorithms().findHostKeyAlgorithm("ssh-rsa") != null ) {
			return "ssh-rsa";
		}
		return null;
	}

	@Override
	public boolean handle(int msg, SshBuffer message, IClientAuthContext context) throws IOException {
		if( msg != SshConstants.SSH_MSG_USERAUTH_60 || current == null ) {
			return false;
		}
		// PK_OK: the server would accept this key, now prove we hold it
		String alg = message.getStringUtf8();
		byte[] blob = message.getString();
		if( !alg.equals(currentAlgorithm) || !Arrays.equals(blob, currentBlob) ) {
			throw new SshException("PK_OK for a key that wasn't offered");
		}
		ISignatureAlgorithm sig = SshAlgorithms.findSignature(alg);
		SshBuffer signed = new SshBuffer();
		signed.putString(context.getSessionId());
		signed.putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
		signed.putString(context.getUser());
		signed.putString(context.getService());
		signed.putString(getName());
		signed.putBoolean(true);
		signed.putString(alg);
		signed.putString(blob);
		byte[] signature;
		try {
			signature = sig.sign(current.getPrivate(), signed.toByteArray());
		} catch (GeneralSecurityException e) {
			throw new SshException(SshConstants.SSH_DISCONNECT_BY_APPLICATION, "Can't sign with the "+alg+" key: "+e.getMessage(), e);
		}
		context.send(context.newRequest(getName()).putBoolean(true).putString(alg).putString(blob).putString(signature));
		current = null;
		return true;
	}
}
