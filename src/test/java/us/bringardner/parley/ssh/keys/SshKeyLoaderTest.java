package us.bringardner.parley.ssh.keys;

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

import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.ISignatureAlgorithm;
import us.bringardner.parley.ssh.algorithms.SshAlgorithms;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;

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
		assertTrue(sig != null, type);
		byte[] data = "to be signed".getBytes(StandardCharsets.UTF_8);
		assertTrue(sig.verify(pub, data, sig.sign(kp.getPrivate(), data)), f.getName()+": signature");
	}

	@Test
	public void everyFormatSshKeygenWrites() throws Exception {
		Assumptions.assumeTrue(haveKeygen(), "ssh-keygen not found");
		String[][] keys = {
				{"-t", "ed25519"},
				{"-t", "rsa", "-b", "2048"},
				{"-t", "ecdsa", "-b", "256"},
				{"-t", "ecdsa", "-b", "384"},
				{"-t", "ecdsa", "-b", "521"},
		};
		int n = 0;
		for (String[] k : keys) {
			// ssh-keygen writes Ed25519 keys only in its own format
			boolean ed = k[1].equals("ed25519");
			for (String format : ed ? new String[] {null} : new String[] {null, "PEM", "PKCS8"}) {
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
				// OpenSSH's own format is encrypted with bcrypt_pbkdf and aes256-ctr
				check(enc, SshKeyLoader.load(enc, "pass phrase".toCharArray()));
				SshException wrong = assertThrows(SshException.class, () -> SshKeyLoader.load(enc, "wrong".toCharArray()));
				if( format == null ) {
					assertEquals("Wrong passphrase", wrong.getMessage());
				}
				assertThrows(SshException.class, () -> SshKeyLoader.load(enc, null));
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

	/** What SshKeyWriter writes loads again, and ssh-keygen reads it (prints the same public key) */
	@Test
	public void writerRoundTrip() throws Exception {
		KeyPairGenerator rg = KeyPairGenerator.getInstance("RSA");
		rg.initialize(2048);
		KeyPairGenerator eg = KeyPairGenerator.getInstance("EC");
		for (String curve : new String[] {"secp256r1", "secp384r1", "secp521r1"}) {
			eg.initialize(new ECGenParameterSpec(curve));
			roundTrip(eg.generateKeyPair());
		}
		roundTrip(rg.generateKeyPair());
		roundTrip(us.bringardner.parley.ssh.algorithms.Ed25519.generate());
	}

	private void roundTrip(KeyPair kp) throws Exception {
		boolean ed = us.bringardner.parley.ssh.algorithms.Ed25519.isEd25519(kp.getPublic());
		for (boolean openSsh : ed ? new boolean[] {true} : new boolean[] {true, false}) {
			File f = new File(dir, "w"+System.nanoTime());
			us.bringardner.parley.ssh.keys.SshKeyWriter.write(kp, f, "round trip", openSsh);
			KeyPair back = SshKeyLoader.load(f, null);
			assertArrayEquals(SshPublicKeys.encode(kp.getPublic()), SshPublicKeys.encode(back.getPublic()));
			check(f, back);
			if( haveKeygen() ) {
				Process p = new ProcessBuilder("ssh-keygen", "-y", "-f", f.getPath()).redirectErrorStream(true).start();
				String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
				assertEquals(0, p.waitFor(), out);
				assertEquals(SshPublicKeys.toOpenSsh(kp.getPublic()), out.split(" ")[0]+" "+out.split(" ")[1], (openSsh ? "OpenSSH" : "PKCS#8")+" read by ssh-keygen");
			}
		}
	}

	/** Other ciphers and round counts ssh-keygen can use for its own format */
	@Test
	public void openSshKeyCiphers() throws Exception {
		Assumptions.assumeTrue(haveKeygen(), "ssh-keygen not found");
		for (String cipher : new String[] {"aes128-ctr", "aes256-cbc"}) {
			File f = keygen("c-"+cipher, "secret", "-t", "ecdsa", "-Z", cipher, "-a", "4");
			check(f, SshKeyLoader.load(f, "secret".toCharArray()));
		}
	}
}
