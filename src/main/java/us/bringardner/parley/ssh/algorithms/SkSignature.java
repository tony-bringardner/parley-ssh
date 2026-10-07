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
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshException;

/**
 * Signatures of FIDO security keys (OpenSSH's PROTOCOL.u2f): sk-ecdsa-sha2-nistp256@openssh.com
 * and sk-ssh-ed25519@openssh.com. The device signs
 * <pre>
 * SHA-256(application) || byte flags || uint32 counter || SHA-256(message)
 * </pre>
 * (ECDSA with SHA-256 over that, or Ed25519 of it) and the signature blob carries the flags
 * and counter after the signature. The flags say whether the user touched the key
 * ({@link #FLAG_USER_PRESENT}) and was verified, e.g. with a PIN ({@link #FLAG_USER_VERIFIED});
 * {@link #verify} only checks the signature, servers decide what the flags must be
 * ({@link #flags(byte[])}).
 *
 * @author Tony Bringardner
 */
public final class SkSignature implements ISignatureAlgorithm {

	public static final int FLAG_USER_PRESENT = 0x01;
	public static final int FLAG_USER_VERIFIED = 0x04;

	private final String type;

	/**
	 * @param type {@link SkPublicKey#SK_ECDSA} or {@link SkPublicKey#SK_ED25519}
	 */
	public SkSignature(String type) {
		if( !SkPublicKey.isSkType(type) ) {
			throw new IllegalArgumentException("Not a security key type "+type);
		}
		this.type = type;
	}

	@Override
	public String getName() {
		return type;
	}

	@Override
	public String getKeyType() {
		return type;
	}

	@Override
	public boolean isSupported() {
		return !SkPublicKey.SK_ED25519.equals(type) || Ed25519.isSupported();
	}

	private static byte[] sha256(byte[] b) throws GeneralSecurityException {
		return MessageDigest.getInstance("SHA-256").digest(b);
	}

	/**
	 * @return what the device signs
	 */
	private static byte[] signed(String application, int flags, long counter, byte[] data) throws GeneralSecurityException {
		SshBuffer b = new SshBuffer();
		b.putRaw(sha256(application.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
		b.putByte(flags);
		b.putInt(counter);
		b.putRaw(sha256(data));
		return b.toByteArray();
	}

	@Override
	public boolean verify(PublicKey key, byte[] data, byte[] signature) throws SshException {
		if( !(key instanceof SkPublicKey) || !((SkPublicKey) key).getType().equals(type) ) {
			return false;
		}
		SkPublicKey sk = (SkPublicKey) key;
		SshBuffer b = new SshBuffer(signature);
		if( !type.equals(b.getStringUtf8()) ) {
			return false;
		}
		byte[] sig = b.getString();
		int flags = b.getByte();
		long counter = b.getUInt();
		if( b.available() != 0 ) {
			throw new SshException("Extra data after the "+type+" signature");
		}
		try {
			byte[] msg = signed(sk.getApplication(), flags, counter, data);
			if( SkPublicKey.SK_ED25519.equals(type) ) {
				if( sig.length != 64 ) {
					return false;
				}
				Signature v = Signature.getInstance("Ed25519");
				v.initVerify(sk.getKey());
				v.update(msg);
				return v.verify(sig);
			}
			SshBuffer rs = new SshBuffer(sig);
			BigInteger r = rs.getMpint();
			BigInteger s = rs.getMpint();
			if( rs.available() != 0 || r.signum() <= 0 || s.signum() <= 0 ) {
				return false;
			}
			Signature v = Signature.getInstance("SHA256withECDSA");
			v.initVerify(sk.getKey());
			v.update(msg);
			return v.verify(EcdsaSignature.toDer(r, s));
		} catch (GeneralSecurityException e) {
			return false;
		}
	}

	/**
	 * @return the flags the device reported in a signature blob
	 */
	public static int flags(byte[] signature) throws SshException {
		SshBuffer b = new SshBuffer(signature);
		b.getString();
		b.getString();
		return b.getByte();
	}

	/**
	 * Sign as the device would, with a {@link SkSoftwareKey} (for tests and emulation).
	 */
	@Override
	public byte[] sign(PrivateKey key, byte[] data) throws GeneralSecurityException {
		if( !(key instanceof SkSoftwareKey) ) {
			throw new GeneralSecurityException(type+" signs on the security key itself (through an SSH agent)");
		}
		SkSoftwareKey sk = (SkSoftwareKey) key;
		int counter = sk.nextCounter();
		byte[] msg = signed(sk.getApplication(), sk.getFlags(), counter, data);
		byte[] sig;
		if( SkPublicKey.SK_ED25519.equals(type) ) {
			Signature s = Signature.getInstance("Ed25519");
			s.initSign(sk.getKey());
			s.update(msg);
			sig = s.sign();
		} else {
			Signature s = Signature.getInstance("SHA256withECDSA");
			s.initSign(sk.getKey());
			s.update(msg);
			BigInteger[] rs = EcdsaSignature.fromDer(s.sign());
			sig = new SshBuffer().putMpint(rs[0]).putMpint(rs[1]).toByteArray();
		}
		return new SshBuffer().putString(type).putString(sig).putByte(sk.getFlags()).putInt(counter & 0xffffffffL).toByteArray();
	}

	@Override
	public String toString() {
		return type;
	}

	@Override
	public boolean equals(Object o) {
		return o instanceof SkSignature && ((SkSignature) o).type.equals(type);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(type.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
	}
}
