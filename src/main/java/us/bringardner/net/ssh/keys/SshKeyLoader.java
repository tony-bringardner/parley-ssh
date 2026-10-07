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
package us.bringardner.net.ssh.keys;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import us.bringardner.net.ssh.SshBuffer;
import us.bringardner.net.ssh.SshException;
import us.bringardner.net.ssh.algorithms.Ed25519;
import us.bringardner.net.ssh.algorithms.SshPublicKeys;

/**
 * Loads key pairs for public key authentication (and later server host keys) from the files
 * ssh-keygen and OpenSSL write:
 * <ul>
 * <li>OpenSSH ("BEGIN OPENSSH PRIVATE KEY", ssh-keygen's default), plain or passphrase protected</li>
 * <li>PKCS#8 ("BEGIN PRIVATE KEY", and "BEGIN ENCRYPTED PRIVATE KEY" with PBES2:
 * PBKDF2 and AES-CBC, as ssh-keygen -m PKCS8 and OpenSSL write)</li>
 * <li>Traditional PEM ("BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY"), plain or with a
 * passphrase (DEK-Info AES-128/192/256-CBC or DES-EDE3-CBC), as ssh-keygen -m PEM writes</li>
 * <li>a Java KeyStore (PKCS12, JKS): every RSA and EC private key entry</li>
 * </ul>
 * RSA and ECDSA (nistp256/384/521) keys. Passphrase protected OpenSSH format keys need
 * bcrypt-pbkdf, which is not supported yet: convert them with {@code ssh-keygen -p -m PEM}.
 *
 * @author Tony Bringardner
 */
public final class SshKeyLoader {

	private static final String OID_RSA = "1.2.840.113549.1.1.1";
	private static final String OID_EC = "1.2.840.10045.2.1";
	private static final String OID_ED25519 = "1.3.101.112";
	private static final String OID_PBES2 = "1.2.840.113549.1.5.13";
	private static final String OID_PBKDF2 = "1.2.840.113549.1.5.12";
	private static final Map<String, String> CURVES = new LinkedHashMap<String, String>();
	private static final Map<String, String> PRFS = new LinkedHashMap<String, String>();
	private static final Map<String, Integer> AES_CBC = new LinkedHashMap<String, Integer>();
	private static final byte[] OPENSSH_MAGIC = "openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII);

	static {
		CURVES.put("1.2.840.10045.3.1.7", "nistp256");
		CURVES.put("1.3.132.0.34", "nistp384");
		CURVES.put("1.3.132.0.35", "nistp521");
		PRFS.put("1.2.840.113549.2.7", "PBKDF2WithHmacSHA1");
		PRFS.put("1.2.840.113549.2.9", "PBKDF2WithHmacSHA256");
		PRFS.put("1.2.840.113549.2.10", "PBKDF2WithHmacSHA384");
		PRFS.put("1.2.840.113549.2.11", "PBKDF2WithHmacSHA512");
		AES_CBC.put("2.16.840.1.101.3.4.1.2", 16);
		AES_CBC.put("2.16.840.1.101.3.4.1.22", 24);
		AES_CBC.put("2.16.840.1.101.3.4.1.42", 32);
	}

	private SshKeyLoader() {
	}

	/**
	 * @param file a private key file
	 * @param passphrase for an encrypted key, null if it isn't
	 */
	public static KeyPair load(File file, char[] passphrase) throws IOException {
		return parse(new String(Files.readAllBytes(file.toPath()), StandardCharsets.US_ASCII), passphrase);
	}

	/**
	 * @param text the contents of a private key file
	 * @param passphrase for an encrypted key, null if it isn't
	 * @throws IOException (an SshException) for an unsupported format or key, a missing or wrong passphrase
	 */
	public static KeyPair parse(String text, char[] passphrase) throws IOException {
		Pem pem = Pem.parse(text);
		try {
			switch (pem.type) {
			case "OPENSSH PRIVATE KEY":
				return openSsh(pem.body, passphrase);
			case "PRIVATE KEY":
				return pkcs8(pem.body);
			case "ENCRYPTED PRIVATE KEY":
				return pkcs8(decryptPbes2(pem.body, need(passphrase)));
			case "RSA PRIVATE KEY":
				return pkcs1(pem.encrypted() ? pem.decrypt(need(passphrase)) : pem.body);
			case "EC PRIVATE KEY":
				return sec1(pem.encrypted() ? pem.decrypt(need(passphrase)) : pem.body, null);
			default:
				throw new SshException("Unsupported key file: BEGIN "+pem.type);
			}
		} catch (GeneralSecurityException e) {
			throw new SshException("Can't load the "+pem.type+" ("+e.getMessage()+"): wrong passphrase?");
		} catch (SshException e) {
			throw e;
		} catch (IOException | RuntimeException e) {
			// A wrong passphrase can decrypt to garbage that fails to parse
			boolean encrypted = pem.encrypted() || "ENCRYPTED PRIVATE KEY".equals(pem.type);
			throw new SshException("Can't read the "+pem.type+" ("+e.getMessage()+")"+(encrypted ? ": wrong passphrase?" : ""));
		}
	}

	/**
	 * @return true if the file needs a passphrase
	 */
	public static boolean isEncrypted(String text) throws IOException {
		Pem pem = Pem.parse(text);
		if( "OPENSSH PRIVATE KEY".equals(pem.type) ) {
			SshBuffer b = new SshBuffer(pem.body);
			b.skip(OPENSSH_MAGIC.length);
			return !"none".equals(b.getStringUtf8());
		}
		return "ENCRYPTED PRIVATE KEY".equals(pem.type) || pem.encrypted();
	}

	/**
	 * @return the public key of an "type base64 comment" file (id_rsa.pub)
	 */
	public static PublicKey loadPublic(File file) throws IOException {
		return SshPublicKeys.fromOpenSsh(new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8));
	}

	/**
	 * @return every RSA and EC private key in the key store with a certificate (for its public key)
	 */
	public static List<KeyPair> fromKeyStore(KeyStore ks, char[] password) throws IOException {
		List<KeyPair> ret = new ArrayList<KeyPair>();
		try {
			for (Enumeration<String> e = ks.aliases(); e.hasMoreElements();) {
				String alias = e.nextElement();
				if( !ks.isKeyEntry(alias) ) {
					continue;
				}
				Key key = ks.getKey(alias, password);
				Certificate cert = ks.getCertificate(alias);
				if( key instanceof PrivateKey && cert != null && ("RSA".equals(key.getAlgorithm()) || "EC".equals(key.getAlgorithm())) ) {
					ret.add(new KeyPair(cert.getPublicKey(), (PrivateKey) key));
				}
			}
		} catch (GeneralSecurityException e) {
			throw new SshException("Can't read the key store: "+e.getMessage());
		}
		return ret;
	}

	/**
	 * The keys OpenSSH tries by default that this library supports and that need no
	 * passphrase: ~/.ssh/id_ecdsa and ~/.ssh/id_rsa. Files that are missing, encrypted or
	 * unsupported are skipped.
	 */
	public static List<KeyPair> defaultIdentities() {
		File dir = new File(System.getProperty("user.home"), ".ssh");
		List<KeyPair> ret = new ArrayList<KeyPair>();
		for (String name : new String[] {"id_ed25519", "id_ecdsa", "id_rsa"}) {
			File f = new File(dir, name);
			try {
				if( f.canRead() ) {
					String text = new String(Files.readAllBytes(f.toPath()), StandardCharsets.US_ASCII);
					if( !isEncrypted(text) ) {
						ret.add(parse(text, null));
					}
				}
			} catch (IOException e) {
				// skipped
			}
		}
		return Collections.unmodifiableList(ret);
	}

	private static char[] need(char[] passphrase) throws SshException {
		if( passphrase == null ) {
			throw new SshException("The key is encrypted, a passphrase is needed");
		}
		return passphrase;
	}

	// ------------------------------------------------------------------ OpenSSH (PROTOCOL.key)

	private static KeyPair openSsh(byte[] data, char[] passphrase) throws IOException, GeneralSecurityException {
		if( data.length < OPENSSH_MAGIC.length || !Arrays.equals(OPENSSH_MAGIC, Arrays.copyOf(data, OPENSSH_MAGIC.length)) ) {
			throw new SshException("Not an OpenSSH private key");
		}
		SshBuffer b = new SshBuffer(data);
		b.skip(OPENSSH_MAGIC.length);
		String cipher = b.getStringUtf8();
		String kdf = b.getStringUtf8();
		byte[] kdfOptions = b.getString();
		if( b.getInt() != 1 ) {
			throw new SshException("Only OpenSSH key files with one key are supported");
		}
		b.getString();
		byte[] section = b.getString();
		if( !"none".equals(cipher) ) {
			section = decryptOpenSsh(cipher, kdf, kdfOptions, section, need(passphrase));
		}
		SshBuffer p = new SshBuffer(section);
		if( p.getUInt() != p.getUInt() ) {
			throw new SshException("none".equals(cipher) ? "Corrupt OpenSSH private key" : "Wrong passphrase");
		}
		String type = p.getStringUtf8();
		if( SshPublicKeys.SSH_RSA.equals(type) ) {
			BigInteger n = p.getMpint();
			BigInteger e = p.getMpint();
			BigInteger d = p.getMpint();
			BigInteger iqmp = p.getMpint();
			BigInteger pp = p.getMpint();
			BigInteger q = p.getMpint();
			return rsa(n, e, d, pp, q, d.mod(pp.subtract(BigInteger.ONE)), d.mod(q.subtract(BigInteger.ONE)), iqmp);
		}
		if( type.startsWith("ecdsa-sha2-") ) {
			String curve = p.getStringUtf8();
			ECParameterSpec params = SshPublicKeys.curveParams(curve);
			ECPoint w = SshPublicKeys.decodePoint(p.getString(), params);
			BigInteger d = p.getMpint();
			return ec(params, d, w);
		}
		if( Ed25519.SSH_ED25519.equals(type) ) {
			if( !Ed25519.isSupported() ) {
				throw new SshException("ssh-ed25519 keys need Java 15 or later");
			}
			byte[] pub = p.getString();
			byte[] priv = p.getString();
			// 64 bytes: the seed, then the public key again
			if( priv.length != 64 || !Arrays.equals(pub, Arrays.copyOfRange(priv, 32, 64)) ) {
				throw new SshException("Corrupt ssh-ed25519 private key");
			}
			return new KeyPair(Ed25519.publicKey(pub), Ed25519.privateKey(Arrays.copyOf(priv, 32)));
		}
		throw new SshException("Unsupported key type "+type+" (supported: RSA, ECDSA nistp256/384/521, Ed25519 on Java 15+)");
	}

	/**
	 * The private section of a passphrase protected OpenSSH key: bcrypt_pbkdf makes the key 
	 * and IV of an AES cipher (ssh-keygen's default is aes256-ctr).
	 */
	private static byte[] decryptOpenSsh(String cipher, String kdf, byte[] kdfOptions, byte[] data, char[] passphrase)
			throws IOException, GeneralSecurityException {
		if( !"bcrypt".equals(kdf) ) {
			throw new SshException("Unsupported key derivation "+kdf);
		}
		int keySize;
		String transform;
		switch (cipher) {
		case "aes128-ctr": keySize = 16; transform = "AES/CTR/NoPadding"; break;
		case "aes192-ctr": keySize = 24; transform = "AES/CTR/NoPadding"; break;
		case "aes256-ctr": keySize = 32; transform = "AES/CTR/NoPadding"; break;
		case "aes128-cbc": keySize = 16; transform = "AES/CBC/NoPadding"; break;
		case "aes192-cbc": keySize = 24; transform = "AES/CBC/NoPadding"; break;
		case "aes256-cbc": keySize = 32; transform = "AES/CBC/NoPadding"; break;
		default: throw new SshException("Unsupported key cipher "+cipher+" (supported: aes-ctr, aes-cbc)");
		}
		SshBuffer o = new SshBuffer(kdfOptions);
		byte[] salt = o.getString();
		int rounds = o.getInt();
		if( rounds < 1 || rounds > 100_000 ) {
			throw new SshException("Unreasonable bcrypt rounds "+rounds);
		}
		if( data.length % 16 != 0 ) {
			throw new SshException("Corrupt encrypted OpenSSH key");
		}
		byte[] pass = new String(passphrase).getBytes(StandardCharsets.UTF_8);
		byte[] keyIv = BcryptPbkdf.derive(pass, salt, rounds, keySize+16);
		Arrays.fill(pass, (byte) 0);
		try {
			Cipher c = Cipher.getInstance(transform);
			c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyIv, 0, keySize, "AES"), new IvParameterSpec(keyIv, keySize, 16));
			return c.doFinal(data);
		} finally {
			Arrays.fill(keyIv, (byte) 0);
		}
	}

	// ------------------------------------------------------------------ PKCS#8, PKCS#1, SEC1

	private static KeyPair pkcs8(byte[] der) throws IOException, GeneralSecurityException {
		Der info = new Der(der).sequence();
		info.integer();
		Der alg = info.sequence();
		String oid = alg.oid();
		if( OID_RSA.equals(oid) ) {
			PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
			RSAPrivateCrtKey k = (RSAPrivateCrtKey) key;
			PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(k.getModulus(), k.getPublicExponent()));
			return new KeyPair(pub, key);
		}
		if( OID_EC.equals(oid) ) {
			return sec1(info.octetString(), curve(alg));
		}
		if( OID_ED25519.equals(oid) ) {
			throw new SshException("PKCS#8 Ed25519 keys have no public key: use the OpenSSH format (ssh-keygen's default for Ed25519)");
		}
		throw new SshException("Unsupported key algorithm "+oid);
	}

	/**
	 * RSAPrivateKey (PKCS#1): version, n, e, d, p, q, dp, dq, qinv
	 */
	private static KeyPair pkcs1(byte[] der) throws IOException, GeneralSecurityException {
		Der s = new Der(der).sequence();
		s.integer();
		return rsa(s.integer(), s.integer(), s.integer(), s.integer(), s.integer(), s.integer(), s.integer(), s.integer());
	}

	/**
	 * ECPrivateKey (SEC1): version, d, [0] curve, [1] public point
	 *
	 * @param curve the curve from the PKCS#8 wrapper, or null to read it from [0]
	 */
	private static KeyPair sec1(byte[] der, String curve) throws IOException, GeneralSecurityException {
		Der s = new Der(der).sequence();
		s.integer();
		BigInteger d = new BigInteger(1, s.octetString());
		Der params = s.explicit(0);
		if( params != null ) {
			curve = curve(params);
		}
		if( curve == null ) {
			throw new SshException("The EC key doesn't name its curve");
		}
		ECParameterSpec spec = SshPublicKeys.curveParams(curve);
		Der pub = s.explicit(1);
		ECPoint w = pub != null ? SshPublicKeys.decodePoint(pub.bitString(), spec) : multiply(spec.getGenerator(), d, spec);
		return ec(spec, d, w);
	}

	/**
	 * The curve of an EC key: a named curve OID, or explicit parameters (some OpenSSL and 
	 * LibreSSL builds write those), matched to a known curve by its prime and order.
	 */
	private static String curve(Der d) throws IOException {
		if( d.peekTag() == Der.OID ) {
			String c = CURVES.get(d.oid());
			if( c == null ) {
				throw new SshException("Unsupported EC curve");
			}
			return c;
		}
		// ECParameters: version, fieldID (prime-field, p), curve (a, b), base, order, cofactor
		Der ecp = d.sequence();
		ecp.integer();
		Der field = ecp.sequence();
		field.oid();
		BigInteger p = field.integer();
		ecp.skip();
		ecp.skip();
		BigInteger order = ecp.integer();
		for (String c : CURVES.values()) {
			ECParameterSpec spec = SshPublicKeys.curveParams(c);
			if( ((ECFieldFp) spec.getCurve().getField()).getP().equals(p) && spec.getOrder().equals(order) ) {
				return c;
			}
		}
		throw new SshException("Unsupported EC curve (explicit parameters)");
	}

	private static KeyPair rsa(BigInteger n, BigInteger e, BigInteger d, BigInteger p, BigInteger q, BigInteger dp, BigInteger dq, BigInteger qinv)
			throws GeneralSecurityException {
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey priv = kf.generatePrivate(new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qinv));
		PublicKey pub = kf.generatePublic(new RSAPublicKeySpec(n, e));
		return new KeyPair(pub, priv);
	}

	private static KeyPair ec(ECParameterSpec params, BigInteger d, ECPoint w) throws GeneralSecurityException, SshException {
		// The public point must belong to the private value, or signatures would fail later
		if( !multiply(params.getGenerator(), d, params).equals(w) ) {
			throw new SshException("The EC public key doesn't match the private key");
		}
		KeyFactory kf = KeyFactory.getInstance("EC");
		PrivateKey priv = kf.generatePrivate(new ECPrivateKeySpec(d, params));
		PublicKey pub = kf.generatePublic(new ECPublicKeySpec(w, params));
		return new KeyPair(pub, priv);
	}

	/**
	 * k * P on the curve (affine double and add). Only for loading keys, where it runs once.
	 */
	static ECPoint multiply(ECPoint point, BigInteger k, ECParameterSpec params) {
		BigInteger p = ((ECFieldFp) params.getCurve().getField()).getP();
		BigInteger a = params.getCurve().getA();
		ECPoint result = ECPoint.POINT_INFINITY;
		ECPoint addend = point;
		for (int i = 0; i < k.bitLength(); i++) {
			if( k.testBit(i) ) {
				result = add(result, addend, p, a);
			}
			addend = add(addend, addend, p, a);
		}
		return result;
	}

	private static ECPoint add(ECPoint q, ECPoint r, BigInteger p, BigInteger a) {
		if( q.equals(ECPoint.POINT_INFINITY) ) {
			return r;
		}
		if( r.equals(ECPoint.POINT_INFINITY) ) {
			return q;
		}
		BigInteger x1 = q.getAffineX(), y1 = q.getAffineY(), x2 = r.getAffineX(), y2 = r.getAffineY();
		BigInteger lambda;
		if( x1.equals(x2) ) {
			if( !y1.equals(y2) || y1.signum() == 0 ) {
				return ECPoint.POINT_INFINITY;
			}
			lambda = x1.pow(2).multiply(BigInteger.valueOf(3)).add(a).multiply(y1.shiftLeft(1).modInverse(p)).mod(p);
		} else {
			lambda = y2.subtract(y1).multiply(x2.subtract(x1).modInverse(p)).mod(p);
		}
		BigInteger x3 = lambda.pow(2).subtract(x1).subtract(x2).mod(p);
		BigInteger y3 = lambda.multiply(x1.subtract(x3)).subtract(y1).mod(p);
		return new ECPoint(x3, y3);
	}

	// ------------------------------------------------------------------ PBES2 (RFC 8018)

	/**
	 * EncryptedPrivateKeyInfo with PBES2 (PBKDF2 and AES-CBC), as OpenSSL and ssh-keygen -m PKCS8 write.
	 */
	private static byte[] decryptPbes2(byte[] der, char[] passphrase) throws IOException, GeneralSecurityException {
		Der epki = new Der(der).sequence();
		Der alg = epki.sequence();
		if( !OID_PBES2.equals(alg.oid()) ) {
			throw new SshException("Only PBES2 encrypted keys are supported");
		}
		Der params = alg.sequence();
		Der kdf = params.sequence();
		if( !OID_PBKDF2.equals(kdf.oid()) ) {
			throw new SshException("Only PBKDF2 is supported");
		}
		Der kdfParams = kdf.sequence();
		byte[] salt = kdfParams.octetString();
		int iterations = kdfParams.integer().intValueExact();
		if( iterations < 1 || iterations > 10_000_000 ) {
			throw new SshException("Unreasonable PBKDF2 iteration count "+iterations);
		}
		String prf = "PBKDF2WithHmacSHA1";
		if( kdfParams.hasMore() && kdfParams.peekTag() == Der.INTEGER ) {
			kdfParams.integer();
		}
		if( kdfParams.hasMore() ) {
			prf = PRFS.get(kdfParams.sequence().oid());
			if( prf == null ) {
				throw new SshException("Unsupported PBKDF2 PRF");
			}
		}
		Der enc = params.sequence();
		Integer keySize = AES_CBC.get(enc.oid());
		if( keySize == null ) {
			throw new SshException("Only AES-CBC encrypted keys are supported");
		}
		byte[] iv = enc.octetString();
		byte[] data = epki.octetString();
		byte[] key = SecretKeyFactory.getInstance(prf).generateSecret(new PBEKeySpec(passphrase, salt, iterations, keySize*8)).getEncoded();
		Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
		return c.doFinal(data);
	}

	// ------------------------------------------------------------------ PEM

	private static final class Pem {
		String type;
		final Map<String, String> headers = new LinkedHashMap<String, String>();
		byte[] body;

		static Pem parse(String text) throws SshException {
			Pem ret = new Pem();
			StringBuilder b64 = new StringBuilder();
			boolean in = false;
			for (String raw : text.split("\r?\n")) {
				String line = raw.trim();
				if( !in ) {
					if( line.startsWith("-----BEGIN ") && line.endsWith("-----") ) {
						ret.type = line.substring(11, line.length()-5);
						in = true;
					}
				} else if( line.startsWith("-----END ") ) {
					break;
				} else if( line.contains(":") ) {
					int i = line.indexOf(':');
					ret.headers.put(line.substring(0, i).trim(), line.substring(i+1).trim());
				} else {
					b64.append(line);
				}
			}
			if( ret.type == null ) {
				throw new SshException("Not a PEM key file (no BEGIN line)");
			}
			try {
				ret.body = Base64.getDecoder().decode(b64.toString());
			} catch (IllegalArgumentException e) {
				throw new SshException("Bad base64 in the key file");
			}
			return ret;
		}

		boolean encrypted() {
			String pt = headers.get("Proc-Type");
			return pt != null && pt.contains("ENCRYPTED");
		}

		/**
		 * OpenSSL's traditional encryption: DEK-Info names the cipher and IV; the key is
		 * EVP_BytesToKey(MD5, passphrase, the IV's first 8 bytes, 1 round).
		 */
		byte[] decrypt(char[] passphrase) throws IOException, GeneralSecurityException {
			String dek = headers.get("DEK-Info");
			if( dek == null || dek.indexOf(',') < 0 ) {
				throw new SshException("Encrypted key without DEK-Info");
			}
			String alg = dek.substring(0, dek.indexOf(',')).trim().toUpperCase(java.util.Locale.ROOT);
			byte[] iv = hex(dek.substring(dek.indexOf(',')+1).trim());
			String transform;
			String keyAlg;
			int keySize;
			switch (alg) {
			case "AES-128-CBC": transform = "AES/CBC/PKCS5Padding"; keyAlg = "AES"; keySize = 16; break;
			case "AES-192-CBC": transform = "AES/CBC/PKCS5Padding"; keyAlg = "AES"; keySize = 24; break;
			case "AES-256-CBC": transform = "AES/CBC/PKCS5Padding"; keyAlg = "AES"; keySize = 32; break;
			case "DES-EDE3-CBC": transform = "DESede/CBC/PKCS5Padding"; keyAlg = "DESede"; keySize = 24; break;
			default: throw new SshException("Unsupported key encryption "+alg);
			}
			byte[] pass = new String(passphrase).getBytes(StandardCharsets.UTF_8);
			byte[] salt = Arrays.copyOf(iv, 8);
			byte[] key = new byte[keySize];
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			byte[] prev = new byte[0];
			int filled = 0;
			while( filled < keySize ) {
				md5.update(prev);
				md5.update(pass);
				md5.update(salt);
				prev = md5.digest();
				int n = Math.min(prev.length, keySize-filled);
				System.arraycopy(prev, 0, key, filled, n);
				filled += n;
			}
			Cipher c = Cipher.getInstance(transform);
			c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, keyAlg), new IvParameterSpec(iv));
			return c.doFinal(body);
		}

		private static byte[] hex(String s) throws SshException {
			if( (s.length() & 1) != 0 ) {
				throw new SshException("Bad IV in DEK-Info");
			}
			byte[] ret = new byte[s.length()/2];
			for (int i = 0; i < ret.length; i++) {
				ret[i] = (byte) Integer.parseInt(s.substring(2*i, 2*i+2), 16);
			}
			return ret;
		}
	}

	/**
	 * @return the key pair of an RSA or EC private key whose public key isn't at hand
	 * (e.g. from a key store entry without a certificate)
	 */
	public static KeyPair fromPrivate(PrivateKey key) throws IOException {
		try {
			if( key instanceof RSAPrivateCrtKey ) {
				RSAPrivateCrtKey k = (RSAPrivateCrtKey) key;
				return new KeyPair(KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(k.getModulus(), k.getPublicExponent())), key);
			}
			if( key instanceof ECPrivateKey ) {
				ECPrivateKey k = (ECPrivateKey) key;
				ECPoint w = multiply(k.getParams().getGenerator(), k.getS(), k.getParams());
				return new KeyPair(KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, k.getParams())), key);
			}
		} catch (GeneralSecurityException e) {
			throw new SshException("Can't make the public key: "+e.getMessage());
		}
		throw new SshException("Unsupported private key "+key.getAlgorithm());
	}
}
