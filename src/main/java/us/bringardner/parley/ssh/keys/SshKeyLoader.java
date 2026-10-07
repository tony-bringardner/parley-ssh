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
package us.bringardner.parley.ssh.keys;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import us.bringardner.parley.core.util.Pem;
import us.bringardner.parley.core.util.PrivateKeys;
import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.Ed25519;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;

/**
 * Loads key pairs for public key authentication and server host keys from the files
 * ssh-keygen and OpenSSL write:
 * <ul>
 * <li>OpenSSH ("BEGIN OPENSSH PRIVATE KEY", ssh-keygen's default), plain or passphrase
 * protected (bcrypt_pbkdf with AES-CTR or AES-CBC)</li>
 * <li>the PEM formats parley-core's {@link PrivateKeys} reads: PKCS#8 (plain or PBES2
 * encrypted) and traditional PEM ("BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY")</li>
 * <li>a Java KeyStore (PKCS12, JKS): every RSA and EC private key entry</li>
 * </ul>
 * RSA, ECDSA (nistp256/384/521) and, on Java 15+, Ed25519 keys (OpenSSH format only).
 * Problems are reported as {@link SshException}s.
 *
 * @author Tony Bringardner
 */
public final class SshKeyLoader {

	private static final byte[] OPENSSH_MAGIC = "openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII);

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
		Pem pem = pem(text);
		if( !"OPENSSH PRIVATE KEY".equals(pem.getType()) ) {
			try {
				return PrivateKeys.parse(pem, passphrase);
			} catch (IOException e) {
				throw new SshException(e.getMessage());
			}
		}
		try {
			return openSsh(pem.getBody(), passphrase);
		} catch (GeneralSecurityException e) {
			throw new SshException("Can't load the OPENSSH PRIVATE KEY ("+e.getMessage()+"): wrong passphrase?");
		} catch (SshException e) {
			throw e;
		} catch (IOException | RuntimeException e) {
			throw new SshException("Can't read the OPENSSH PRIVATE KEY ("+e.getMessage()+")"+(isEncrypted(text) ? ": wrong passphrase?" : ""));
		}
	}

	private static Pem pem(String text) throws SshException {
		try {
			return Pem.parse(text);
		} catch (IOException e) {
			throw new SshException(e.getMessage());
		}
	}

	/**
	 * @return true if the file needs a passphrase
	 */
	public static boolean isEncrypted(String text) throws IOException {
		Pem pem = pem(text);
		if( "OPENSSH PRIVATE KEY".equals(pem.getType()) ) {
			SshBuffer b = new SshBuffer(pem.getBody());
			b.skip(OPENSSH_MAGIC.length);
			return !"none".equals(b.getStringUtf8());
		}
		return PrivateKeys.isEncrypted(pem);
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
		try {
			return PrivateKeys.fromKeyStore(ks, password);
		} catch (IOException e) {
			throw new SshException(e.getMessage());
		}
	}

	/**
	 * The keys OpenSSH tries by default that this library supports and that need no
	 * passphrase: ~/.ssh/id_ed25519, id_ecdsa and id_rsa. Files that are missing, encrypted or
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

	/**
	 * @return the key pair of an RSA or EC private key whose public key isn't at hand
	 * (e.g. from a key store entry without a certificate)
	 */
	public static KeyPair fromPrivate(PrivateKey key) throws IOException {
		try {
			return PrivateKeys.fromPrivate(key);
		} catch (IOException e) {
			throw new SshException(e.getMessage());
		}
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
			return PrivateKeys.rsa(n, e, d, pp, q, d.mod(pp.subtract(BigInteger.ONE)), d.mod(q.subtract(BigInteger.ONE)), iqmp);
		}
		if( type.startsWith("ecdsa-sha2-") ) {
			String curve = p.getStringUtf8();
			ECParameterSpec params = SshPublicKeys.curveParams(curve);
			ECPoint w = SshPublicKeys.decodePoint(p.getString(), params);
			BigInteger d = p.getMpint();
			try {
				return PrivateKeys.ec(params, d, w);
			} catch (PrivateKeys.KeyFormatException x) {
				throw new SshException(x.getMessage());
			}
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
}
