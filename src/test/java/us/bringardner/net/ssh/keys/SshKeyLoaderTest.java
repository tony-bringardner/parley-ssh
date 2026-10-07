package us.bringardner.net.ssh.keys;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.net.ssh.SshException;
import us.bringardner.net.ssh.algorithms.ISignatureAlgorithm;
import us.bringardner.net.ssh.algorithms.SshAlgorithms;
import us.bringardner.net.ssh.algorithms.SshPublicKeys;

/**
 * Keys written by the local ssh-keygen in every format it has, loaded and checked against
 * the .pub file it wrote, then used to sign.
 */
public class SshKeyLoaderTest {

	@TempDir
	File dir;

	private static boolean haveKeygen() {
		try {
			return new ProcessBuilder("ssh-keygen", "-?").redirectErrorStream(true).start().waitFor(10, TimeUnit.SECONDS);
		} catch (Exception e) {
			return false;
		}
	}

	private File keygen(String name, String passphrase, String... args) throws Exception {
		File f = new File(dir, name);
		List<String> cmd = new ArrayList<String>();
		cmd.add("ssh-keygen");
		cmd.add("-q");
		cmd.add("-f");
		cmd.add(f.getPath());
		cmd.add("-N");
		cmd.add(passphrase);
		cmd.add("-C");
		cmd.add("test");
		for (String a : args) {
			cmd.add(a);
		}
		Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
		assertTrue(p.waitFor(60, TimeUnit.SECONDS));
		String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		assertEquals(0, p.exitValue(), "ssh-keygen "+cmd+": "+out);
		return f;
	}

	private static void check(File f, KeyPair kp) throws Exception {
		PublicKey pub = SshKeyLoader.loadPublic(new File(f.getPath()+".pub"));
		assertArrayEquals(SshPublicKeys.encode(pub), SshPublicKeys.encode(kp.getPublic()), f.getName()+": public key");
		String type = SshPublicKeys.keyType(pub);
		ISignatureAlgorithm sig = SshAlgorithms.findSignature(type.equals("ssh-rsa") ? "rsa-sha2-256" : type);
		byte[] data = "to be signed".getBytes(StandardCharsets.UTF_8);
		assertTrue(sig.verify(pub, data, sig.sign(kp.getPrivate(), data)), f.getName()+": signature");
	}

	@Test
	public void everyFormatSshKeygenWrites() throws Exception {
		Assumptions.assumeTrue(haveKeygen(), "ssh-keygen not found");
		String[][] keys = {
				{"-t", "rsa", "-b", "2048"},
				{"-t", "ecdsa", "-b", "256"},
				{"-t", "ecdsa", "-b", "384"},
				{"-t", "ecdsa", "-b", "521"},
		};
		int n = 0;
		for (String[] k : keys) {
			for (String format : new String[] {null, "PEM", "PKCS8"}) {
				String name = "key"+(n++);
				List<String> args = new ArrayList<String>(java.util.Arrays.asList(k));
				if( format != null ) {
					args.add("-m");
					args.add(format);
				}
				File plain = keygen(name, "", args.toArray(new String[0]));
				check(plain, SshKeyLoader.load(plain, null));
				assertFalse(SshKeyLoader.isEncrypted(new String(Files.readAllBytes(plain.toPath()), StandardCharsets.US_ASCII)));

				File enc = keygen(name+"e", "pass phrase", args.toArray(new String[0]));
				String text = new String(Files.readAllBytes(enc.toPath()), StandardCharsets.US_ASCII);
				assertTrue(SshKeyLoader.isEncrypted(text), name+" "+format);
				if( format == null ) {
					// OpenSSH's own encryption needs bcrypt-pbkdf: a clear message for now
					SshException e = assertThrows(SshException.class, () -> SshKeyLoader.load(enc, "pass phrase".toCharArray()));
					assertTrue(e.getMessage().contains("ssh-keygen -p -m PEM"), e.getMessage());
				} else {
					check(enc, SshKeyLoader.load(enc, "pass phrase".toCharArray()));
					assertThrows(SshException.class, () -> SshKeyLoader.load(enc, "wrong".toCharArray()));
					assertThrows(SshException.class, () -> SshKeyLoader.load(enc, null));
				}
			}
		}
	}

	@Test
	public void keyStoreAndPrivateOnly() throws Exception {
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
		g.initialize(new ECGenParameterSpec("secp384r1"));
		KeyPair kp = g.generateKeyPair();
		// The public key is worked out from the private one
		KeyPair again = SshKeyLoader.fromPrivate(kp.getPrivate());
		assertArrayEquals(SshPublicKeys.encode(kp.getPublic()), SshPublicKeys.encode(again.getPublic()));

		// A PKCS12 store the framework's test key store tooling writes: one RSA key with a certificate
		KeyStore ks = KeyStore.getInstance("PKCS12");
		try (java.io.InputStream in = getClass().getResourceAsStream("/test-keystore.p12")) {
			Assumptions.assumeTrue(in != null, "no test key store");
			ks.load(in, "changeit".toCharArray());
		}
		List<KeyPair> keys = SshKeyLoader.fromKeyStore(ks, "changeit".toCharArray());
		assertEquals(1, keys.size());
		assertEquals("ssh-rsa", SshPublicKeys.keyType(keys.get(0).getPublic()));
	}
}
