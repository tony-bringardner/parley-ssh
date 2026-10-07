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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermissions;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Base64;

import us.bringardner.net.ssh.SshBuffer;
import us.bringardner.net.ssh.algorithms.SshPublicKeys;

/**
 * Writes keys in formats {@link SshKeyLoader}, OpenSSH and JSch read: the private key as
 * unencrypted PKCS#8 PEM or OpenSSH's own format (ssh-keygen's default), the public key as
 * "type base64 comment".
 *
 * @author Tony Bringardner
 */
public final class SshKeyWriter {

	private SshKeyWriter() {
	}

	/**
	 * @return "-----BEGIN PRIVATE KEY-----" PEM of the key's PKCS#8 encoding
	 */
	public static String toPkcs8Pem(PrivateKey key) {
		String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(key.getEncoded());
		return "-----BEGIN PRIVATE KEY-----\n"+b64+"\n-----END PRIVATE KEY-----\n";
	}

	/**
	 * @return the key in OpenSSH's format ("-----BEGIN OPENSSH PRIVATE KEY-----", PROTOCOL.key),
	 * unencrypted
	 */
	public static String toOpenSsh(KeyPair pair, String comment) {
		SshBuffer priv = new SshBuffer();
		int check = new SecureRandom().nextInt();
		priv.putInt(check).putInt(check);
		if( pair.getPrivate() instanceof RSAPrivateCrtKey ) {
			RSAPrivateCrtKey k = (RSAPrivateCrtKey) pair.getPrivate();
			priv.putString(SshPublicKeys.SSH_RSA).putMpint(k.getModulus()).putMpint(k.getPublicExponent())
					.putMpint(k.getPrivateExponent()).putMpint(k.getCrtCoefficient()).putMpint(k.getPrimeP()).putMpint(k.getPrimeQ());
		} else if( pair.getPrivate() instanceof ECPrivateKey ) {
			ECPublicKey pub = (ECPublicKey) pair.getPublic();
			String curve = SshPublicKeys.curveName(pub.getParams());
			BigInteger d = ((ECPrivateKey) pair.getPrivate()).getS();
			priv.putString("ecdsa-sha2-"+curve).putString(curve).putString(SshPublicKeys.encodePoint(pub.getW(), pub.getParams())).putMpint(d);
		} else {
			throw new IllegalArgumentException("Unsupported key "+pair.getPrivate().getAlgorithm());
		}
		priv.putString(comment == null ? "" : comment);
		// Padded with 1, 2, 3... to the cipher block size (8 for "none")
		for (int i = 1; priv.available() % 8 != 0; i++) {
			priv.putByte(i);
		}
		SshBuffer b = new SshBuffer();
		b.putRaw("openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII));
		b.putString("none").putString("none").putString(new byte[0]).putInt(1);
		b.putString(SshPublicKeys.encode(pair.getPublic()));
		b.putString(priv.toByteArray());
		String b64 = Base64.getMimeEncoder(70, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(b.toByteArray());
		return "-----BEGIN OPENSSH PRIVATE KEY-----\n"+b64+"\n-----END OPENSSH PRIVATE KEY-----\n";
	}

	/**
	 * Write the private key (readable by the owner only where the file system allows) and
	 * file.pub with the public key.
	 */
	public static void write(KeyPair pair, File file, String comment) throws IOException {
		write(pair, file, comment, false);
	}

	/**
	 * @param openSshFormat true for OpenSSH's format, false for PKCS#8 PEM
	 */
	public static void write(KeyPair pair, File file, String comment, boolean openSshFormat) throws IOException {
		File dir = file.getAbsoluteFile().getParentFile();
		if( dir != null && !dir.exists() && !dir.mkdirs() ) {
			throw new IOException("Can't create "+dir);
		}
		// Created empty with owner-only permissions first, so the key is never readable by others
		Files.deleteIfExists(file.toPath());
		try {
			Files.createFile(file.toPath(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
		} catch (UnsupportedOperationException e) {
			// Not a POSIX file system (Windows): rely on the directory's permissions
			Files.createFile(file.toPath());
		}
		String text = openSshFormat ? toOpenSsh(pair, comment) : toPkcs8Pem(pair.getPrivate());
		Files.write(file.toPath(), text.getBytes(StandardCharsets.US_ASCII));
		String pub = SshPublicKeys.toOpenSsh(pair.getPublic())+(comment == null ? "" : " "+comment)+"\n";
		Files.write(new File(file.getPath()+".pub").toPath(), pub.getBytes(StandardCharsets.US_ASCII));
	}
}
