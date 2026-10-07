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

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshException;

/**
 * ecdsa-sha2-nistp256, -nistp384 and -nistp521 (RFC 5656 3.1.2). The SSH signature is
 * string(mpint r, mpint s); Java's is DER, so this converts between them.
 *
 * @author Tony Bringardner
 */
public class EcdsaSignature implements ISignatureAlgorithm {

	private final String name;
	private final String curve;
	private final String jceName;

	/**
	 * @param curve nistp256, nistp384 or nistp521
	 * @param jceName SHA256withECDSA, SHA384withECDSA or SHA512withECDSA
	 */
	public EcdsaSignature(String curve, String jceName) {
		this.name = "ecdsa-sha2-"+curve;
		this.curve = curve;
		this.jceName = jceName;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getKeyType() {
		return name;
	}

	@Override
	public boolean verify(PublicKey key, byte[] data, byte[] signature) throws SshException {
		if( !(key instanceof ECPublicKey) || !curve.equals(SshPublicKeys.curveName(((ECPublicKey) key).getParams())) ) {
			return false;
		}
		SshBuffer b = new SshBuffer(signature);
		if( !name.equals(b.getStringUtf8()) ) {
			return false;
		}
		SshBuffer rs = new SshBuffer(b.getString());
		BigInteger r = rs.getMpint();
		BigInteger s = rs.getMpint();
		if( r.signum() <= 0 || s.signum() <= 0 ) {
			return false;
		}
		try {
			Signature sig = Signature.getInstance(jceName);
			sig.initVerify(key);
			sig.update(data);
			return sig.verify(toDer(r, s));
		} catch (GeneralSecurityException e) {
			return false;
		}
	}

	@Override
	public byte[] sign(PrivateKey key, byte[] data) throws GeneralSecurityException {
		Signature sig = Signature.getInstance(jceName);
		sig.initSign(key);
		sig.update(data);
		BigInteger[] rs = fromDer(sig.sign());
		byte[] inner = new SshBuffer().putMpint(rs[0]).putMpint(rs[1]).toByteArray();
		return new SshBuffer().putString(name).putString(inner).toByteArray();
	}

	@Override
	public String toString() {
		return name;
	}

	// ------------------------------------------------------------------ DER SEQUENCE { INTEGER r, INTEGER s }

	static byte[] toDer(BigInteger r, BigInteger s) {
		byte[] rb = r.toByteArray();
		byte[] sb = s.toByteArray();
		ByteArrayOutputStream body = new ByteArrayOutputStream();
		derItem(body, 0x02, rb);
		derItem(body, 0x02, sb);
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		derItem(out, 0x30, body.toByteArray());
		return out.toByteArray();
	}

	private static void derItem(ByteArrayOutputStream out, int tag, byte[] value) {
		out.write(tag);
		int len = value.length;
		if( len < 128 ) {
			out.write(len);
		} else if( len < 256 ) {
			out.write(0x81);
			out.write(len);
		} else {
			out.write(0x82);
			out.write(len >>> 8);
			out.write(len);
		}
		out.write(value, 0, value.length);
	}

	static BigInteger[] fromDer(byte[] der) throws GeneralSecurityException {
		int[] pos = {0};
		if( der.length < 2 || (der[pos[0]++] & 0xff) != 0x30 ) {
			throw new GeneralSecurityException("Bad ECDSA signature");
		}
		int seqLen = derLength(der, pos);
		if( pos[0]+seqLen != der.length ) {
			throw new GeneralSecurityException("Bad ECDSA signature");
		}
		BigInteger r = derInteger(der, pos);
		BigInteger s = derInteger(der, pos);
		return new BigInteger[] {r, s};
	}

	private static BigInteger derInteger(byte[] der, int[] pos) throws GeneralSecurityException {
		if( pos[0] >= der.length || (der[pos[0]++] & 0xff) != 0x02 ) {
			throw new GeneralSecurityException("Bad ECDSA signature");
		}
		int len = derLength(der, pos);
		if( len <= 0 || pos[0]+len > der.length ) {
			throw new GeneralSecurityException("Bad ECDSA signature");
		}
		byte[] v = new byte[len];
		System.arraycopy(der, pos[0], v, 0, len);
		pos[0] += len;
		return new BigInteger(v);
	}

	private static int derLength(byte[] der, int[] pos) throws GeneralSecurityException {
		if( pos[0] >= der.length ) {
			throw new GeneralSecurityException("Bad ECDSA signature");
		}
		int b = der[pos[0]++] & 0xff;
		if( b < 128 ) {
			return b;
		}
		int n = b & 0x7f;
		if( n < 1 || n > 2 || pos[0]+n > der.length ) {
			throw new GeneralSecurityException("Bad ECDSA signature");
		}
		int len = 0;
		for (int i = 0; i < n; i++) {
			len = (len << 8) | (der[pos[0]++] & 0xff);
		}
		return len;
	}
}
