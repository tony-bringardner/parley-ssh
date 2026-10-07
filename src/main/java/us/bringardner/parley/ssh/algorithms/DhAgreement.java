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

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import us.bringardner.parley.ssh.SshConstants;
import us.bringardner.parley.ssh.SshException;

/**
 * Diffie-Hellman on a fixed group for diffie-hellman-group14-sha256 and
 * diffie-hellman-group16-sha512 (RFC 8268): the RFC 3526 MODP groups (2048 and 4096 bits,
 * generator 2). The peer's value must be in 1 &lt; f &lt; p-1.
 *
 * @author Tony Bringardner
 */
public class DhAgreement implements IKeyAgreement {

	private static final String GROUP14_P = 
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
			"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
			"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
			"98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
			"9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
			"3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

	private static final String GROUP16_P = 
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
			"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
			"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
			"98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
			"9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
			"3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33" +
			"A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
			"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864" +
			"D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2" +
			"08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" +
			"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8" +
			"DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2" +
			"233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" +
			"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF";

	/** RFC 3526 group 14, 2048 bits */
	public static final BigInteger GROUP14 = new BigInteger(GROUP14_P, 16);
	/** RFC 3526 group 16, 4096 bits */
	public static final BigInteger GROUP16 = new BigInteger(GROUP16_P, 16);
	public static final BigInteger GENERATOR = BigInteger.valueOf(2);

	private final BigInteger p;
	private final int privateBits;
	private KeyPair pair;

	/**
	 * @param p the group's prime (generator 2)
	 * @param privateBits size of the private exponent; RFC 8268 asks for at least twice the 
	 * hash size (512 bits for SHA-256, 1024 for SHA-512)
	 */
	public DhAgreement(BigInteger p, int privateBits) {
		this.p = p;
		this.privateBits = privateBits;
	}

	@Override
	public byte[] init(SecureRandom random) throws GeneralSecurityException {
		KeyPairGenerator g = KeyPairGenerator.getInstance("DH");
		g.initialize(new DHParameterSpec(p, GENERATOR, privateBits), random);
		pair = g.generateKeyPair();
		BigInteger e = ((DHPublicKey) pair.getPublic()).getY();
		return e.toByteArray();
	}

	@Override
	public byte[] agree(byte[] peer) throws SshException, GeneralSecurityException {
		BigInteger f = peer.length == 0 ? BigInteger.ZERO : new BigInteger(peer);
		if( f.compareTo(BigInteger.ONE) <= 0 || f.compareTo(p.subtract(BigInteger.ONE)) >= 0 ) {
			throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Diffie-Hellman value out of range");
		}
		PublicKey key = KeyFactory.getInstance("DH").generatePublic(new DHPublicKeySpec(f, p, GENERATOR));
		KeyAgreement ka = KeyAgreement.getInstance("DH");
		ka.init(pair.getPrivate());
		ka.doPhase(key, true);
		return ka.generateSecret();
	}
}
