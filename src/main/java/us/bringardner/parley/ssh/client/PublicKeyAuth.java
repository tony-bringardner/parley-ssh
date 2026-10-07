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
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshConstants;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.ISignatureAlgorithm;
import us.bringardner.parley.ssh.algorithms.SshAlgorithms;
import us.bringardner.parley.ssh.algorithms.SshCertificate;
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
 * <p>
 * A key can also be offered with its OpenSSH certificate ({@link #addCertificate}), for
 * servers that trust the certificate authority instead of listing keys; certificates are
 * tried before plain keys, as OpenSSH does. The keys of an SSH agent sign in the agent
 * ({@link #fromAgent(SshAgent)}, {@link #addAgent(SshAgent)}).
 *
 * @author Tony Bringardner
 */
public class PublicKeyAuth implements IClientAuthMethod {

	/**
	 * A key to offer: its public key, the blob sent (a certificate's for a certificate), and
	 * what signs: the private key, or the agent.
	 */
	private static final class Identity {
		final PublicKey key;
		final SshCertificate certificate;
		final KeyPair pair;
		final SshAgent agent;
		final byte[] agentBlob;

		Identity(PublicKey key, SshCertificate certificate, KeyPair pair, SshAgent agent, byte[] agentBlob) {
			this.key = key;
			this.certificate = certificate;
			this.pair = pair;
			this.agent = agent;
			this.agentBlob = agentBlob;
		}

		byte[] blob() {
			return certificate != null ? certificate.getBlob() : SshPublicKeys.encode(key);
		}
	}

	private final List<Identity> identities = new ArrayList<Identity>();
	private int next;
	private Identity current;
	private String currentAlgorithm;
	private byte[] currentBlob;

	public PublicKeyAuth(KeyPair... keys) {
		this(Arrays.asList(keys));
	}

	public PublicKeyAuth(Collection<KeyPair> keys) {
		for (KeyPair kp : keys) {
			identities.add(new Identity(kp.getPublic(), null, kp, null, null));
		}
	}

	/**
	 * @return the keys (and certificates) of an SSH agent, which signs for them
	 */
	public static PublicKeyAuth fromAgent(SshAgent agent) throws IOException {
		return new PublicKeyAuth().addAgent(agent);
	}

	/**
	 * Offer the agent's keys too, after the ones already added (its certificates before plain
	 * keys). Keys of types this library doesn't support are skipped.
	 */
	public synchronized PublicKeyAuth addAgent(SshAgent agent) throws IOException {
		for (SshAgent.Identity id : agent.getIdentities()) {
			try {
				SshCertificate cert = id.isCertificate() ? SshCertificate.decode(id.getBlob()) : null;
				add(new Identity(id.getPublicKey(), cert, null, agent, id.getBlob()));
			} catch (SshException e) {
				// e.g. a security key (sk-*) or DSA key
			}
		}
		return this;
	}

	/**
	 * Offer the key with its certificate (before the plain keys).
	 *
	 * @throws IllegalArgumentException if the certificate isn't for this key
	 */
	public synchronized PublicKeyAuth addCertificate(KeyPair key, SshCertificate certificate) {
		if( !Arrays.equals(SshPublicKeys.encode(key.getPublic()), certificate.getPublicKeyBlob()) ) {
			throw new IllegalArgumentException("The certificate is for another key");
		}
		add(new Identity(key.getPublic(), certificate, key, null, null));
		return this;
	}

	/** Certificates go after the other certificates, plain keys at the end */
	private void add(Identity id) {
		int at = identities.size();
		if( id.certificate != null ) {
			at = 0;
			while( at < identities.size() && identities.get(at).certificate != null ) {
				at++;
			}
		}
		identities.add(at, id);
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

	private synchronized boolean tryNext(IClientAuthContext context) throws IOException {
		while( next < identities.size() ) {
			Identity id = identities.get(next++);
			String alg = algorithm(id.key, context);
			if( alg != null && id.certificate != null ) {
				// rsa-sha2-512 with a certificate is rsa-sha2-512-cert-v01@openssh.com
				alg = SshCertificate.certificateType(alg);
				if( SshAlgorithms.findSignature(alg) == null ) {
					alg = null;
				}
			}
			if( alg == null ) {
				continue;
			}
			current = id;
			currentAlgorithm = alg;
			currentBlob = id.blob();
			context.send(context.newRequest(getName()).putBoolean(false).putString(alg).putString(currentBlob));
			return true;
		}
		return false;
	}

	/**
	 * @return the signature algorithm for the key, or null if it can't be used
	 */
	static String algorithm(KeyPair key, IClientAuthContext context) {
		return algorithm(key.getPublic(), context);
	}

	static String algorithm(PublicKey key, IClientAuthContext context) {
		String type;
		try {
			type = SshPublicKeys.keyType(key);
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

	/**
	 * @return the agent's flag for the RSA signature algorithm (0: the key's own)
	 */
	private static int agentFlags(String alg) {
		if( alg.startsWith("rsa-sha2-512") ) {
			return SshAgent.SSH_AGENT_RSA_SHA2_512;
		}
		if( alg.startsWith("rsa-sha2-256") ) {
			return SshAgent.SSH_AGENT_RSA_SHA2_256;
		}
		return 0;
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
		if( current.agent != null ) {
			signature = current.agent.sign(current.agentBlob, signed.toByteArray(), agentFlags(alg));
			String made = new SshBuffer(signature).getStringUtf8();
			String want = sig instanceof us.bringardner.parley.ssh.algorithms.CertSignature
					? ((us.bringardner.parley.ssh.algorithms.CertSignature) sig).getPlain().getName() : alg;
			if( !made.equals(want) ) {
				throw new SshException(SshConstants.SSH_DISCONNECT_BY_APPLICATION, "The SSH agent signed with "+made+", not "+want);
			}
		} else {
			try {
				signature = sig.sign(current.pair.getPrivate(), signed.toByteArray());
			} catch (GeneralSecurityException e) {
				throw new SshException(SshConstants.SSH_DISCONNECT_BY_APPLICATION, "Can't sign with the "+alg+" key: "+e.getMessage(), e);
			}
		}
		context.send(context.newRequest(getName()).putBoolean(true).putString(alg).putString(blob).putString(signature));
		current = null;
		return true;
	}
}
