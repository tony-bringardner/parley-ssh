package us.bringardner.parley.ssh.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.SshCertificate;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;
import us.bringardner.parley.ssh.client.ClientSession;
import us.bringardner.parley.ssh.client.KnownHosts;
import us.bringardner.parley.ssh.client.PublicKeyAuth;
import us.bringardner.parley.ssh.client.SshClient;
import us.bringardner.parley.ssh.server.AuthorizedKeysAuthenticator;
import us.bringardner.parley.ssh.server.HostKeyProviders;
import us.bringardner.parley.ssh.server.SshServer;
import us.bringardner.parley.ssh.server.UserCertificateAuthenticator;

/**
 * OpenSSH key revocation lists made by ssh-keygen -k, and plain lists of keys; checked
 * against ssh-keygen -Q.
 */
public class KeyRevocationListTest {

	@TempDir
	File dir;

	private int run(String... cmd) throws Exception {
		Process p;
		try {
			p = new ProcessBuilder(cmd).directory(dir).redirectErrorStream(true).start();
		} catch (java.io.IOException e) {
			assumeTrue(false, "no ssh-keygen");
			return -1;
		}
		p.getInputStream().readAllBytes();
		assertTrue(p.waitFor(60, TimeUnit.SECONDS));
		return p.exitValue();
	}

	private File f(String name) {
		return new File(dir, name);
	}

	private void write(String name, String text) throws Exception {
		Files.write(f(name).toPath(), text.getBytes(StandardCharsets.UTF_8));
	}

	/** @return ssh-keygen -Q's verdict: true if revoked */
	private boolean opensshSaysRevoked(String krl, String pub) throws Exception {
		return run("ssh-keygen", "-Q", "-f", krl, pub) != 0;
	}

	@Test
	public void certificateSections() throws Exception {
		assumeTrue(run("ssh-keygen", "-q", "-t", "ecdsa", "-N", "", "-f", "ca") == 0, "no ssh-keygen");
		assertEquals(0, run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "u"));
		// Serials as a bitmap (5, 10-20, and every other one from 31 to 99), and a key id
		StringBuilder spec = new StringBuilder("serial: 5\nserial: 10-20\nid: bad-id\n");
		for (int i = 31; i < 100; i += 2) {
			spec.append("serial: ").append(i).append('\n');
		}
		write("spec", spec.toString());
		assertEquals(0, run("ssh-keygen", "-q", "-k", "-f", "krl", "-s", "ca.pub", "spec"));
		// And a list of separate serials (far apart, so not a bitmap)
		write("spec2", "serial: 1000000\nserial: 5000000000\nserial: 2000000-3000000\n");
		assertEquals(0, run("ssh-keygen", "-q", "-k", "-f", "krl2", "-s", "ca.pub", "spec2"));
		KeyRevocationList krl = KeyRevocationList.load(f("krl"));
		KeyRevocationList krl2 = KeyRevocationList.load(f("krl2"));

		long[] serials = {4, 5, 6, 10, 15, 20, 21, 31, 32, 33, 99, 100, 1000000, 5000000000L, 5000000001L, 1999999, 2000000, 2500000, 3000000, 3000001};
		for (long serial : serials) {
			File cert = f("u-cert.pub");
			cert.delete();
			assertEquals(0, run("ssh-keygen", "-q", "-s", "ca", "-I", "id-"+serial, "-n", "alice", "-z", ""+serial, "u.pub"));
			SshCertificate c = SshCertificate.load(cert);
			assertEquals(serial, c.getSerial());
			assertEquals(opensshSaysRevoked("krl", "u-cert.pub"), krl.isRevoked(c), "serial "+serial);
			assertEquals(opensshSaysRevoked("krl2", "u-cert.pub"), krl2.isRevoked(c), "serial "+serial+" (list)");
		}
		assertTrue(krl2.isRevoked(SshCertificate.load(f("u-cert.pub"))) == false);

		f("u-cert.pub").delete();
		assertEquals(0, run("ssh-keygen", "-q", "-s", "ca", "-I", "bad-id", "-n", "alice", "-z", "7", "u.pub"));
		assertTrue(krl.isRevoked(SshCertificate.load(f("u-cert.pub"))), "by key id");
		assertFalse(krl.isRevoked(SshPublicKeys.encode(SshKeyLoader.loadPublic(f("u.pub")))), "the plain key isn't");

		// Another CA's certificate with a revoked serial is not revoked
		assertEquals(0, run("ssh-keygen", "-q", "-t", "ecdsa", "-N", "", "-f", "ca2"));
		f("u-cert.pub").delete();
		assertEquals(0, run("ssh-keygen", "-q", "-s", "ca2", "-I", "x", "-n", "alice", "-z", "5", "u.pub"));
		assertFalse(krl.isRevoked(SshCertificate.load(f("u-cert.pub"))));
	}

	@Test
	public void keysAndFingerprints() throws Exception {
		assumeTrue(run("ssh-keygen", "-q", "-t", "ecdsa", "-N", "", "-f", "ca") == 0, "no ssh-keygen");
		assertEquals(0, run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "bad"));
		assertEquals(0, run("ssh-keygen", "-q", "-t", "rsa", "-N", "", "-f", "byhash"));
		assertEquals(0, run("ssh-keygen", "-q", "-t", "ecdsa", "-N", "", "-f", "good"));
		byte[] bad = SshPublicKeys.encode(SshKeyLoader.loadPublic(f("bad.pub")));
		byte[] byHash = SshPublicKeys.encode(SshKeyLoader.loadPublic(f("byhash.pub")));
		byte[] good = SshPublicKeys.encode(SshKeyLoader.loadPublic(f("good.pub")));

		assertEquals(0, run("ssh-keygen", "-q", "-k", "-f", "keys.krl", "bad.pub"));
		write("hashes", "hash: "+SshPublicKeys.fingerprint(byHash)+"\n");
		assertEquals(0, run("ssh-keygen", "-q", "-k", "-u", "-f", "keys.krl", "hashes"));
		KeyRevocationList krl = KeyRevocationList.load(f("keys.krl"));
		assertTrue(krl.isRevoked(bad), "explicit key");
		assertTrue(krl.isRevoked(byHash), "SHA-256 fingerprint");
		assertFalse(krl.isRevoked(good));
		assertTrue(opensshSaysRevoked("keys.krl", "byhash.pub"));

		// A certificate of a revoked key is revoked; so is every certificate of a revoked CA
		assertEquals(0, run("ssh-keygen", "-q", "-s", "ca", "-I", "c", "-n", "alice", "bad.pub"));
		assertTrue(krl.isRevoked(SshCertificate.load(f("bad-cert.pub"))));
		assertEquals(0, run("ssh-keygen", "-q", "-s", "ca", "-I", "c", "-n", "alice", "good.pub"));
		SshCertificate goodCert = SshCertificate.load(f("good-cert.pub"));
		assertFalse(krl.isRevoked(goodCert));
		assertEquals(0, run("ssh-keygen", "-q", "-k", "-f", "ca.krl", "ca.pub"));
		assertTrue(KeyRevocationList.load(f("ca.krl")).isRevoked(goodCert), "its CA is revoked");
	}

	@Test
	public void plainListsAndReloading() throws Exception {
		KeyPair a = us.bringardner.parley.ssh.server.CertificateTest.ec("secp256r1");
		KeyPair b = us.bringardner.parley.ssh.server.CertificateTest.ec("secp256r1");
		write("revoked", "# revoked\n"+SshPublicKeys.toOpenSsh(a.getPublic())+" old laptop\n");
		KeyRevocationList list = KeyRevocationList.load(f("revoked"));
		assertTrue(list.isRevoked(SshPublicKeys.encode(a.getPublic())));
		assertFalse(list.isRevoked(SshPublicKeys.encode(b.getPublic())));
		// Changed: read again
		Thread.sleep(1100);
		write("revoked", SshPublicKeys.toOpenSsh(b.getPublic())+"\n"+SshPublicKeys.toOpenSsh(a.getPublic())+"\n");
		assertTrue(list.isRevoked(SshPublicKeys.encode(b.getPublic())), "reloaded");
		// Gone: everything is revoked, as OpenSSH refuses all keys when it can't read the file
		assertTrue(f("revoked").delete());
		assertTrue(list.isRevoked(SshPublicKeys.encode(us.bringardner.parley.ssh.server.CertificateTest.ec("secp256r1").getPublic())));
		assertThrows(SshException.class, () -> KeyRevocationList.of("not a key\n".getBytes(StandardCharsets.UTF_8)));
	}

	@Test
	public void serverAndClient() throws Exception {
		KeyPair ok = us.bringardner.parley.ssh.server.CertificateTest.ec("secp256r1");
		KeyPair bad = us.bringardner.parley.ssh.server.CertificateTest.ec("secp256r1");
		KeyPair ca = us.bringardner.parley.ssh.server.CertificateTest.ec("secp256r1");
		KeyPair hostKey = us.bringardner.parley.ssh.server.CertificateTest.ec("secp256r1");
		write("authorized_keys", SshPublicKeys.toOpenSsh(ok.getPublic())+"\n"+SshPublicKeys.toOpenSsh(bad.getPublic())+"\n");
		write("revoked", SshPublicKeys.toOpenSsh(bad.getPublic())+"\n");
		SshServer server = new SshServer(0);
		server.setHostKeyProvider(HostKeyProviders.of(hostKey));
		server.setPublicKeyAuthenticator(AuthorizedKeysAuthenticator.forFile(f("authorized_keys"))
				.or(new UserCertificateAuthenticator(Collections.singletonList(ca.getPublic()))));
		server.setRevokedKeys(KeyRevocationList.load(f("revoked")));
		server.setLoginFailureDelay(0);
		server.startAndWait(5000);
		try (SshClient client = new SshClient()) {
			client.setHostKeyVerifier(new KnownHosts(Collections.<String>emptyList()).setPolicy(KnownHosts.Policy.ACCEPT));
			ClientSession s = client.connectAndWait("localhost", server.getLocalPort());
			s.authenticateAndWait("alice", new PublicKeyAuth(ok));
			s.close();
			ClientSession s2 = client.connectAndWait("localhost", server.getLocalPort());
			assertThrows(SshException.class, () -> s2.authenticateAndWait("alice", new PublicKeyAuth(bad)), "revoked key");
			s2.close();
			ClientSession s3 = client.connectAndWait("localhost", server.getLocalPort());
			assertThrows(SshException.class, () -> s3.authenticateAndWait("alice", new PublicKeyAuth().addCertificate(bad,
					us.bringardner.parley.ssh.server.CertificateTest.user(bad, ca, null, null, "alice"))), "a certificate of a revoked key");
			s3.close();

			// Client side: the host key is revoked
			write("revoked_hosts", SshPublicKeys.toOpenSsh(hostKey.getPublic())+"\n");
			client.setHostKeyVerifier(new KnownHosts(Collections.<String>emptyList()).setPolicy(KnownHosts.Policy.ACCEPT)
					.setRevokedHostKeys(KeyRevocationList.load(f("revoked_hosts"))));
			assertThrows(java.io.IOException.class, () -> client.connectAndWait("localhost", server.getLocalPort()));
		} finally {
			server.stop(5000, false);
		}
	}
}
