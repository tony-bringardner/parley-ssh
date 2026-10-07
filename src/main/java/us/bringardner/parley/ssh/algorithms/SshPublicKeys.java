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
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;

import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshException;

/**
 * The SSH public key formats (RFC 4253 6.6, RFC 5656 3.1): the key blob sent in the key
 * exchange and in public key authentication, and the "type base64 comment" text of
 * known_hosts and authorized_keys files. Also SHA256 fingerprints as OpenSSH shows them.
 * <p>
 * Supports ssh-rsa, ecdsa-sha2-nistp256/384/521 and (Java 15+) ssh-ed25519.
 *
 * @author Tony Bringardner
 */
public final class SshPublicKeys {

	public static final String SSH_RSA = "ssh-rsa";
	public static final String ECDSA_P256 = "ecdsa-sha2-nistp256";
	public static final String ECDSA_P384 = "ecdsa-sha2-nistp384";
	public static final String ECDSA_P521 = "ecdsa-sha2-nistp521";

	private SshPublicKeys() {
	}

	/**
	 * @return the SSH key type of the key, e.g. "ssh-rsa" or "ecdsa-sha2-nistp256"
	 * @throws IllegalArgumentException for an unsupported key
	 */
	public static String keyType(PublicKey key) {
		if( Ed25519.isEd25519(key) ) {
			return Ed25519.SSH_ED25519;
		}
		if( key instanceof RSAPublicKey ) {
			return SSH_RSA;
		}
		if( key instanceof ECPublicKey ) {
			return "ecdsa-sha2-"+curveName(((ECPublicKey) key).getParams());
		}
		throw new IllegalArgumentException("Unsupported key type "+key.getAlgorithm());
	}

	/**
	 * @return the key blob (string type, then the key's fields)
	 */
	public static byte[] encode(PublicKey key) {
		SshBuffer b = new SshBuffer();
		if( Ed25519.isEd25519(key) ) {
			b.putString(Ed25519.SSH_ED25519);
			b.putString(Ed25519.publicBytes(key));
		} else if( key instanceof RSAPublicKey ) {
			RSAPublicKey rsa = (RSAPublicKey) key;
			b.putString(SSH_RSA);
			b.putMpint(rsa.getPublicExponent());
			b.putMpint(rsa.getModulus());
		} else if( key instanceof ECPublicKey ) {
			ECPublicKey ec = (ECPublicKey) key;
			String curve = curveName(ec.getParams());
			b.putString("ecdsa-sha2-"+curve);
			b.putString(curve);
			b.putString(encodePoint(ec.getW(), ec.getParams()));
		} else {
			throw new IllegalArgumentException("Unsupported key type "+key.getAlgorithm());
		}
		return b.toByteArray();
	}

	/**
	 * @param blob a key blob
	 * @return the key
	 * @throws SshException if the blob is malformed or the key type isn't supported
	 */
	public static PublicKey decode(byte[] blob) throws SshException {
		SshBuffer b = new SshBuffer(blob);
		String type = b.getStringUtf8();
		try {
			PublicKey ret;
			if( SSH_RSA.equals(type) ) {
				BigInteger e = b.getMpint();
				BigInteger n = b.getMpint();
				if( e.signum() <= 0 || n.signum() <= 0 ) {
					throw new SshException("Invalid RSA key");
				}
				ret = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
			} else if( Ed25519.SSH_ED25519.equals(type) ) {
				if( !Ed25519.isSupported() ) {
					throw new SshException("ssh-ed25519 keys need Java 15 or later");
				}
				ret = Ed25519.publicKey(b.getString());
			} else if( type.startsWith("ecdsa-sha2-") ) {
				String curve = b.getStringUtf8();
				if( !type.equals("ecdsa-sha2-"+curve) ) {
					throw new SshException("Key type "+type+" with curve "+curve);
				}
				ECParameterSpec params = curveParams(curve);
				ECPoint w = decodePoint(b.getString(), params);
				ret = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, params));
			} else {
				throw new SshException("Unsupported key type "+type);
			}
			if( b.available() != 0 ) {
				throw new SshException("Extra data after the "+type+" key");
			}
			return ret;
		} catch (GeneralSecurityException e) {
			throw new SshException(us.bringardner.parley.ssh.SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Invalid "+type+" key: "+e.getMessage(), e);
		}
	}

	/**
	 * @return the key type named at the start of a key blob
	 */
	public static String blobType(byte[] blob) throws SshException {
		return new SshBuffer(blob).getStringUtf8();
	}

	/**
	 * @return the OpenSSH fingerprint, e.g. "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"
	 */
	public static String fingerprint(PublicKey key) {
		return fingerprint(encode(key));
	}

	public static String fingerprint(byte[] blob) {
		try {
			byte[] hash = MessageDigest.getInstance("SHA-256").digest(blob);
			return "SHA256:"+Base64.getEncoder().withoutPadding().encodeToString(hash);
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	/**
	 * @return "type base64", the format of known_hosts and authorized_keys
	 */
	public static String toOpenSsh(PublicKey key) {
		return keyType(key)+" "+Base64.getEncoder().encodeToString(encode(key));
	}

	/**
	 * @param text "type base64 [comment]"
	 * @return the key
	 * @throws SshException if the text is not a supported key, or the type doesn't match the blob
	 */
	public static PublicKey fromOpenSsh(String text) throws SshException {
		String[] parts = text.trim().split("\\s+");
		if( parts.length < 2 ) {
			throw new SshException("Not a public key: '"+text+"'");
		}
		byte[] blob;
		try {
			blob = Base64.getDecoder().decode(parts[1].getBytes(StandardCharsets.US_ASCII));
		} catch (IllegalArgumentException e) {
			throw new SshException("Not a public key (bad base64): '"+text+"'");
		}
		if( !parts[0].equals(blobType(blob)) ) {
			throw new SshException("Key type "+parts[0]+" doesn't match the key ("+blobType(blob)+")");
		}
		return decode(blob);
	}

	// ------------------------------------------------------------------ elliptic curves

	/**
	 * @return the SSH curve name (nistp256, nistp384, nistp521)
	 */
	public static String curveName(ECParameterSpec params) {
		int bits = params.getCurve().getField().getFieldSize();
		switch (bits) {
		case 256: return "nistp256";
		case 384: return "nistp384";
		case 521: return "nistp521";
		default: throw new IllegalArgumentException("Unsupported curve of "+bits+" bits");
		}
	}

	/**
	 * @param curve nistp256, nistp384 or nistp521
	 */
	public static ECParameterSpec curveParams(String curve) throws SshException {
		String std;
		switch (curve) {
		case "nistp256": std = "secp256r1"; break;
		case "nistp384": std = "secp384r1"; break;
		case "nistp521": std = "secp521r1"; break;
		default: throw new SshException("Unsupported curve "+curve);
		}
		try {
			AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
			ap.init(new ECGenParameterSpec(std));
			return ap.getParameterSpec(ECParameterSpec.class);
		} catch (GeneralSecurityException e) {
			throw new SshException(us.bringardner.parley.ssh.SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Curve "+curve+" not available", e);
		}
	}

	/**
	 * @return the uncompressed point encoding (SEC1): 0x04 || x || y, each the field size
	 */
	public static byte[] encodePoint(ECPoint w, ECParameterSpec params) {
		int size = (params.getCurve().getField().getFieldSize()+7)/8;
		byte[] ret = new byte[1+2*size];
		ret[0] = 4;
		unsigned(w.getAffineX(), ret, 1, size);
		unsigned(w.getAffineY(), ret, 1+size, size);
		return ret;
	}

	/**
	 * @return the point, checked to be on the curve (an invalid point is a known attack on ECDH)
	 */
	public static ECPoint decodePoint(byte[] data, ECParameterSpec params) throws SshException {
		int size = (params.getCurve().getField().getFieldSize()+7)/8;
		if( data.length != 1+2*size || data[0] != 4 ) {
			throw new SshException("Invalid EC point (only uncompressed points are supported)");
		}
		BigInteger x = new BigInteger(1, Arrays.copyOfRange(data, 1, 1+size));
		BigInteger y = new BigInteger(1, Arrays.copyOfRange(data, 1+size, data.length));
		ECPoint ret = new ECPoint(x, y);
		checkOnCurve(ret, params);
		return ret;
	}

	/**
	 * @throws SshException unless y^2 = x^3 + ax + b (mod p) with x and y in the field
	 */
	public static void checkOnCurve(ECPoint w, ECParameterSpec params) throws SshException {
		BigInteger p = ((ECFieldFp) params.getCurve().getField()).getP();
		BigInteger x = w.getAffineX();
		BigInteger y = w.getAffineY();
		if( x.signum() < 0 || x.compareTo(p) >= 0 || y.signum() < 0 || y.compareTo(p) >= 0 ) {
			throw new SshException("EC point is outside the field");
		}
		BigInteger left = y.multiply(y).mod(p);
		BigInteger right = x.pow(3).add(params.getCurve().getA().multiply(x)).add(params.getCurve().getB()).mod(p);
		if( !left.equals(right) ) {
			throw new SshException("EC point is not on the curve");
		}
	}

	/**
	 * Write v as exactly len unsigned big endian bytes.
	 */
	static void unsigned(BigInteger v, byte[] out, int off, int len) {
		byte[] b = v.toByteArray();
		int start = (b.length > len && b[0] == 0) ? 1 : 0;
		int n = b.length-start;
		if( n > len ) {
			throw new IllegalArgumentException("Value too large for "+len+" bytes");
		}
		System.arraycopy(b, start, out, off+len-n, n);
	}
}
