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

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

import javax.crypto.KeyAgreement;

import us.bringardner.parley.ssh.SshException;

/**
 * ECDH on nistp256, nistp384 or nistp521 for ecdh-sha2-nistp* (RFC 5656 4). The peer's point
 * is checked to be on the curve before it is used.
 *
 * @author Tony Bringardner
 */
public class EcdhAgreement implements IKeyAgreement {

	private final String curve;
	private ECParameterSpec params;
	private KeyPair pair;

	/**
	 * @param curve nistp256, nistp384 or nistp521
	 */
	public EcdhAgreement(String curve) {
		this.curve = curve;
	}

	@Override
	public byte[] init(SecureRandom random) throws GeneralSecurityException {
		try {
			params = SshPublicKeys.curveParams(curve);
		} catch (SshException e) {
			throw new GeneralSecurityException(e.getMessage(), e);
		}
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
		g.initialize(params, random);
		pair = g.generateKeyPair();
		return SshPublicKeys.encodePoint(((ECPublicKey) pair.getPublic()).getW(), params);
	}

	@Override
	public byte[] agree(byte[] peer) throws SshException, GeneralSecurityException {
		ECPoint w = SshPublicKeys.decodePoint(peer, params);
		PublicKey key = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, params));
		KeyAgreement ka = KeyAgreement.getInstance("ECDH");
		ka.init(pair.getPrivate());
		ka.doPhase(key, true);
		return ka.generateSecret();
	}
}
