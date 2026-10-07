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
package us.bringardner.net.ssh.algorithms;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.function.Supplier;

import us.bringardner.net.ssh.SshBuffer;
import us.bringardner.net.ssh.SshConstants;
import us.bringardner.net.ssh.SshException;

/**
 * The one round trip key exchange shared by Diffie-Hellman on a fixed group (RFC 4253 8,
 * RFC 8268), ECDH (RFC 5656 4) and curve25519 (RFC 8731): the client sends its public value
 * (message 30), the server answers with its host key, its public value and its signature of
 * the exchange hash (message 31).
 * <p>
 * H = HASH(V_C || V_S || I_C || I_S || K_S || client value || server value || K), with the
 * values as strings (an mpint is a string with the number's bytes) and K as an mpint.
 * Only the math differs, which the {@link IKeyAgreement} provides.
 *
 * @author Tony Bringardner
 */
public class EphemeralKeyExchange implements IKeyExchange {

	private final String name;
	private final String hash;
	private final Supplier<IKeyAgreement> agreements;
	private IKexContext ctx;
	private IKeyAgreement agreement;
	private byte[] clientValue;
	private byte[] h;
	private byte[] k;

	/**
	 * @param name the method name, e.g. "curve25519-sha256"
	 * @param hash the JCE hash name, e.g. "SHA-256"
	 * @param agreements makes the key agreement
	 */
	public EphemeralKeyExchange(String name, String hash, Supplier<IKeyAgreement> agreements) {
		this.name = name;
		this.hash = hash;
		this.agreements = agreements;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getHashAlgorithm() {
		return hash;
	}

	@Override
	public void start(IKexContext context) throws IOException {
		this.ctx = context;
		this.agreement = agreements.get();
		if( ctx.isClient() ) {
			try {
				clientValue = agreement.init(ctx.getRandom());
			} catch (GeneralSecurityException e) {
				throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, name+": "+e.getMessage(), e);
			}
			ctx.send(SshBuffer.message(SshConstants.SSH_MSG_KEXDH_INIT).putString(clientValue));
		}
	}

	@Override
	public boolean handle(int msg, SshBuffer message) throws IOException {
		try {
			if( ctx.isClient() && msg == SshConstants.SSH_MSG_KEXDH_REPLY ) {
				byte[] hostKey = message.getString();
				byte[] serverValue = message.getString();
				byte[] signature = message.getString();
				k = agreement.agree(serverValue);
				h = exchangeHash(hostKey, clientValue, serverValue);
				ctx.verifyHostKey(hostKey, signature, h);
				return true;
			}
			if( !ctx.isClient() && msg == SshConstants.SSH_MSG_KEXDH_INIT ) {
				clientValue = message.getString();
				byte[] serverValue = agreement.init(ctx.getRandom());
				k = agreement.agree(clientValue);
				byte[] hostKey = ctx.getHostKey();
				h = exchangeHash(hostKey, clientValue, serverValue);
				byte[] signature = ctx.signExchangeHash(h);
				ctx.send(SshBuffer.message(SshConstants.SSH_MSG_KEXDH_REPLY)
						.putString(hostKey).putString(serverValue).putString(signature));
				return true;
			}
		} catch (GeneralSecurityException e) {
			throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, name+": "+e.getMessage(), e);
		}
		throw new SshException("Unexpected "+SshConstants.messageName(msg)+" in "+name);
	}

	private byte[] exchangeHash(byte[] hostKey, byte[] clientValue, byte[] serverValue) throws GeneralSecurityException {
		SshBuffer b = new SshBuffer(2048);
		b.putString(ctx.getClientVersion());
		b.putString(ctx.getServerVersion());
		b.putString(ctx.getClientKexInit());
		b.putString(ctx.getServerKexInit());
		b.putString(hostKey);
		b.putString(clientValue);
		b.putString(serverValue);
		b.putMpint(k);
		MessageDigest md = MessageDigest.getInstance(hash);
		md.update(b.array(), b.readPosition(), b.available());
		return md.digest();
	}

	@Override
	public byte[] getExchangeHash() {
		return h;
	}

	@Override
	public byte[] getSharedSecret() {
		return k;
	}
}
