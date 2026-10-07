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
package us.bringardner.parley.ssh.server;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import us.bringardner.parley.core.SecureBaseObject;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.SshCertificate;
import us.bringardner.parley.ssh.keys.SshKeyLoader;
import us.bringardner.parley.ssh.keys.SshKeyWriter;

/**
 * Where host keys come from.
 *
 * @author Tony Bringardner
 */
public final class HostKeyProviders {

	private HostKeyProviders() {
	}

	/**
	 * The RSA and EC key entries of a SecureBaseObject's key store (the KeyStoreName,
	 * KeyStorePassword and KeyStoreType settings, as for the framework's TLS servers).
	 */
	public static IHostKeyProvider fromKeyStore(SecureBaseObject config) {
		return () -> {
			String pw = config.getKeyStorePassword();
			char[] password = pw == null ? null : pw.toCharArray();
			List<KeyPair> ret = SshKeyLoader.fromKeyStore(config.getKeyStore(password), password);
			if( ret.isEmpty() ) {
				throw new SshException("The key store "+config.getKeyStoreFileName()+" has no RSA or EC key entries");
			}
			return ret;
		};
	}

	/**
	 * Private key files (PEM, PKCS#8 or OpenSSH, unencrypted), e.g. /etc/ssh/ssh_host_ecdsa_key,
	 * with the host certificate of each that has one ("key-cert.pub", as ssh-keygen -s -h writes).
	 */
	public static IHostKeyProvider fromFiles(File... files) {
		List<File> list = Arrays.asList(files.clone());
		return new IHostKeyProvider() {
			@Override
			public List<KeyPair> getHostKeys() throws IOException {
				List<KeyPair> ret = new ArrayList<KeyPair>();
				for (File f : list) {
					ret.add(SshKeyLoader.load(f, null));
				}
				return ret;
			}

			@Override
			public List<SshCertificate> getHostCertificates() throws IOException {
				return certificates(list);
			}
		};
	}

	/**
	 * The keys of another provider, with these host certificates.
	 */
	public static IHostKeyProvider withCertificates(IHostKeyProvider keys, SshCertificate... certificates) {
		List<SshCertificate> list = Collections.unmodifiableList(Arrays.asList(certificates.clone()));
		return new IHostKeyProvider() {
			@Override
			public List<KeyPair> getHostKeys() throws IOException {
				return keys.getHostKeys();
			}

			@Override
			public List<SshCertificate> getHostCertificates() throws IOException {
				List<SshCertificate> ret = new ArrayList<SshCertificate>(keys.getHostCertificates());
				ret.addAll(list);
				return ret;
			}
		};
	}

	/**
	 * @return the "-cert.pub" files next to the key files
	 */
	private static List<SshCertificate> certificates(List<File> keyFiles) throws IOException {
		List<SshCertificate> ret = new ArrayList<SshCertificate>();
		for (File f : keyFiles) {
			File cert = new File(f.getPath()+"-cert.pub");
			if( cert.isFile() ) {
				ret.add(SshCertificate.load(cert));
			}
		}
		return ret;
	}

	/**
	 * Keys in a directory, made the first time like OpenSSH's ssh-keygen -A:
	 * ssh_host_ecdsa_key (P-256) and ssh_host_rsa_key (3072 bits), with their .pub files.
	 * Later starts read the same keys, so clients that trust them keep trusting the server.
	 */
	public static IHostKeyProvider generated(File dir) {
		List<String> names = new ArrayList<String>(Arrays.asList("ssh_host_ecdsa_key", "ssh_host_rsa_key"));
		if( us.bringardner.parley.ssh.algorithms.Ed25519.isSupported() ) {
			names.add(0, "ssh_host_ed25519_key");
		}
		List<File> files = new ArrayList<File>();
		for (String name : names) {
			files.add(new File(dir, name));
		}
		return new IHostKeyProvider() {
			@Override
			public List<KeyPair> getHostKeys() throws IOException {
				List<KeyPair> ret = new ArrayList<KeyPair>();
				for (File f : files) {
					if( !f.exists() ) {
						String name = f.getName();
						KeyPair kp = name.contains("ed25519") ? ed25519() : name.contains("ecdsa") ? ec() : rsa();
						SshKeyWriter.write(kp, f, "parley-ssh host key");
					}
					ret.add(SshKeyLoader.load(f, null));
				}
				return ret;
			}

			/** ssh_host_*_key-cert.pub, when a CA has signed one */
			@Override
			public List<SshCertificate> getHostCertificates() throws IOException {
				return certificates(files);
			}
		};
	}

	/**
	 * New keys in memory, different on every start: clients see a new host key each time.
	 * For tests.
	 */
	public static IHostKeyProvider ephemeral() {
		List<KeyPair> keys;
		try {
			List<KeyPair> tmp = new ArrayList<KeyPair>(Arrays.asList(ec(), rsa()));
			if( us.bringardner.parley.ssh.algorithms.Ed25519.isSupported() ) {
				tmp.add(0, ed25519());
			}
			keys = Collections.unmodifiableList(tmp);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
		return () -> keys;
	}

	/**
	 * These keys.
	 */
	public static IHostKeyProvider of(KeyPair... keys) {
		List<KeyPair> list = Collections.unmodifiableList(Arrays.asList(keys.clone()));
		return () -> list;
	}

	private static KeyPair ec() throws IOException {
		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
			g.initialize(new ECGenParameterSpec("secp256r1"));
			return g.generateKeyPair();
		} catch (GeneralSecurityException e) {
			throw new IOException(e);
		}
	}

	private static KeyPair ed25519() throws IOException {
		try {
			return us.bringardner.parley.ssh.algorithms.Ed25519.generate();
		} catch (GeneralSecurityException e) {
			throw new IOException(e);
		}
	}

	private static KeyPair rsa() throws IOException {
		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
			g.initialize(3072);
			return g.generateKeyPair();
		} catch (GeneralSecurityException e) {
			throw new IOException(e);
		}
	}
}
