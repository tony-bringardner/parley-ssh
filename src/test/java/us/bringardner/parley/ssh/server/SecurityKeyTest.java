package us.bringardner.parley.ssh.server;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.Ed25519;
import us.bringardner.parley.ssh.algorithms.SkPublicKey;
import us.bringardner.parley.ssh.algorithms.SkSignature;
import us.bringardner.parley.ssh.algorithms.SkSoftwareKey;
import us.bringardner.parley.ssh.algorithms.SshAlgorithms;
import us.bringardner.parley.ssh.algorithms.SshCertificate;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;
import us.bringardner.parley.ssh.client.ClientSession;
import us.bringardner.parley.ssh.client.HostKeyVerifiers;
import us.bringardner.parley.ssh.client.PublicKeyAuth;
import us.bringardner.parley.ssh.client.SshClient;

/**
 * FIDO security keys (sk-ecdsa-sha2-nistp256@openssh.com, sk-ssh-ed25519@openssh.com) on
 * the server. A software key signs as a device would; OpenSSH's sshd accepting those
 * signatures shows the format is OpenSSH's, and ssh-keygen reads and certifies the keys.
 */
public class SecurityKeyTest {

	@TempDir
	File dir;

	private SshServer server;
	private SshClient client;

	private static final long NOW = System.currentTimeMillis()/1000;

	@AfterEach
	public void stop() throws Exception {
		if( client != null ) {
			client.close();
		}
		if( server != null ) {
			server.stop(5000, false);
		}
	}

	/** @return a security key that reports these flags */
	static KeyPair sk(boolean ed25519, int flags) throws Exception {
		KeyPair base = ed25519 ? Ed25519.generate() : CertificateTest.ec("secp256r1");
		return new KeyPair(new SkPublicKey(base.getPublic(), SkPublicKey.DEFAULT_APPLICATION),
				new SkSoftwareKey(base.getPrivate(), SkPublicKey.DEFAULT_APPLICATION, flags));
	}

	private List<Boolean> types() {
		return Ed25519.isSupported() ? Arrays.asList(false, true) : Collections.singletonList(false);
	}

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

	@Test
	public void keysAndSignatures() throws Exception {
		for (boolean ed : types()) {
			KeyPair k = sk(ed, SkSignature.FLAG_USER_PRESENT);
			SkPublicKey pub = (SkPublicKey) k.getPublic();
			byte[] blob = SshPublicKeys.encode(pub);
			assertEquals(ed ? SkPublicKey.SK_ED25519 : SkPublicKey.SK_ECDSA, SshPublicKeys.blobType(blob));
			SkPublicKey back = (SkPublicKey) SshPublicKeys.decode(blob);
			assertEquals(pub, back);
			assertEquals("ssh:", back.getApplication());
			assertEquals(pub, SshPublicKeys.fromOpenSsh(SshPublicKeys.toOpenSsh(pub)));

			SkSignature sig = (SkSignature) SshAlgorithms.findSignature(pub.getType());
			byte[] data = "data".getBytes(StandardCharsets.UTF_8);
			byte[] s = sig.sign(k.getPrivate(), data);
			assertTrue(sig.verify(pub, data, s));
			assertEquals(SkSignature.FLAG_USER_PRESENT, SkSignature.flags(s));
			assertFalse(sig.verify(pub, "other".getBytes(StandardCharsets.UTF_8), s));
			// Another application: another key as far as the device is concerned
			assertFalse(sig.verify(new SkPublicKey(pub.getKey(), "ssh:other"), data, s));
			// The flags are signed: changing them breaks the signature
			byte[] changed = s.clone();
			changed[changed.length-5] = 0x05;
			assertFalse(sig.verify(pub, data, changed));
			assertThrows(java.security.GeneralSecurityException.class, () -> sig.sign(CertificateTest.ec("secp256r1").getPrivate(), data),
					"only a device (or a software key) signs");
		}
	}

	/** ssh-keygen reads our security keys, and certifies them */
	@Test
	public void sshKeygenInterop() throws Exception {
		assumeTrue(run("ssh-keygen", "-q", "-t", "ecdsa", "-N", "", "-f", "ca") == 0, "no ssh-keygen");
		for (boolean ed : types()) {
			KeyPair k = sk(ed, SkSignature.FLAG_USER_PRESENT);
			File pub = new File(dir, "sk"+ed+".pub");
			Files.write(pub.toPath(), (SshPublicKeys.toOpenSsh(k.getPublic())+" test\n").getBytes(StandardCharsets.UTF_8));
			assertEquals(0, run("ssh-keygen", "-l", "-f", pub.getPath()), "ssh-keygen reads it");
			assertEquals(0, run("ssh-keygen", "-q", "-s", "ca", "-I", "sk-id", "-n", "alice", "-O", "no-touch-required", pub.getPath()));
			SshCertificate c = SshCertificate.load(new File(dir, "sk"+ed+"-cert.pub"));
			assertEquals(SshCertificate.certificateType(((SkPublicKey) k.getPublic()).getType()), c.getType());
			assertEquals(ed ? "sk-ssh-ed25519-cert-v01@openssh.com" : "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com", c.getType());
			assertArrayEquals(SshPublicKeys.encode(k.getPublic()), c.getPublicKeyBlob());
			assertTrue(c.hasExtension(SshCertificate.NO_TOUCH_REQUIRED));
			assertTrue(c.isSignatureValid());
		}
	}

	// ------------------------------------------------------------------ logins

	private void startServer(IPublicKeyAuthenticator auth) throws Exception {
		server = new SshServer(0);
		server.setHostKeyProvider(HostKeyProviders.ephemeral());
		server.setPublicKeyAuthenticator(auth);
		server.setCommandFactory((line, env) -> ServerTest.command(line));
		server.setLoginFailureDelay(0);
		server.startAndWait(5000);
	}

	private ClientSession login(PublicKeyAuth auth) throws Exception {
		if( client != null ) {
			client.close();
		}
		client = new SshClient();
		client.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
		ClientSession s = client.connectAndWait("localhost", server.getLocalPort());
		s.authenticateAndWait("alice", auth);
		return s;
	}

	private boolean canLogIn(PublicKeyAuth auth) throws Exception {
		try {
			login(auth).close();
			return true;
		} catch (SshException e) {
			return false;
		}
	}

	private AuthorizedKeysAuthenticator file(String... lines) throws Exception {
		File f = new File(dir, "authorized_keys");
		Files.write(f.toPath(), (String.join("\n", lines)+"\n").getBytes(StandardCharsets.UTF_8));
		return AuthorizedKeysAuthenticator.forFile(f);
	}

	@Test
	public void touchAndVerification() throws Exception {
		for (boolean ed : types()) {
			KeyPair touched = sk(ed, SkSignature.FLAG_USER_PRESENT);
			KeyPair untouched = sk(ed, 0);
			KeyPair waived = sk(ed, 0);
			KeyPair pinNeeded = sk(ed, SkSignature.FLAG_USER_PRESENT);
			KeyPair withPin = sk(ed, SkSignature.FLAG_USER_PRESENT | SkSignature.FLAG_USER_VERIFIED);
			startServer(file(SshPublicKeys.toOpenSsh(touched.getPublic()), SshPublicKeys.toOpenSsh(untouched.getPublic()),
					"no-touch-required "+SshPublicKeys.toOpenSsh(waived.getPublic()),
					"verify-required "+SshPublicKeys.toOpenSsh(pinNeeded.getPublic()),
					"verify-required "+SshPublicKeys.toOpenSsh(withPin.getPublic())));
			String at = ed ? "ed25519-sk: " : "ecdsa-sk: ";
			ClientSession s = login(new PublicKeyAuth(touched));
			assertEquals("alice", s.exec("whoami", null, 10000).getStdoutText(), at);
			s.close();
			assertFalse(canLogIn(new PublicKeyAuth(untouched)), at+"not touched");
			assertTrue(canLogIn(new PublicKeyAuth(waived)), at+"no-touch-required");
			assertFalse(canLogIn(new PublicKeyAuth(pinNeeded)), at+"verify-required without a PIN");
			assertTrue(canLogIn(new PublicKeyAuth(withPin)), at+"verified");

			// Server-wide settings
			server.setSecurityKeyTouchRequired(true);
			assertFalse(canLogIn(new PublicKeyAuth(waived)), at+"touch required by the server");
			server.setSecurityKeyTouchRequired(false);
			server.setSecurityKeyVerifyRequired(true);
			assertFalse(canLogIn(new PublicKeyAuth(touched)), at+"verification required by the server");
			assertTrue(canLogIn(new PublicKeyAuth(withPin)), at);
			server.stop(5000, false);
		}
	}

	@Test
	public void certificates() throws Exception {
		KeyPair ca = CertificateTest.ec("secp256r1");
		startServer(new UserCertificateAuthenticator(Collections.singletonList(ca.getPublic())));
		for (boolean ed : types()) {
			KeyPair touched = sk(ed, SkSignature.FLAG_USER_PRESENT);
			KeyPair untouched = sk(ed, 0);
			Map<String, String> noTouch = Collections.singletonMap(SshCertificate.NO_TOUCH_REQUIRED, "");
			Map<String, String> verify = Collections.singletonMap(SshCertificate.VERIFY_REQUIRED, "");
			assertTrue(canLogIn(new PublicKeyAuth().addCertificate(touched, CertificateTest.user(touched, ca, null, null, "alice"))));
			assertFalse(canLogIn(new PublicKeyAuth().addCertificate(untouched, CertificateTest.user(untouched, ca, null, null, "alice"))),
					"not touched");
			assertTrue(canLogIn(new PublicKeyAuth().addCertificate(untouched, CertificateTest.user(untouched, ca, null, noTouch, "alice"))),
					"no-touch-required extension");
			assertFalse(canLogIn(new PublicKeyAuth().addCertificate(touched, CertificateTest.user(touched, ca, verify, null, "alice"))),
					"verify-required critical option");
			// A plain security key is not enough for a server that only trusts the CA
			assertFalse(canLogIn(new PublicKeyAuth(touched)));
		}
	}

	// ------------------------------------------------------------------ OpenSSH's sshd checks our signatures

	@Test
	public void opensshServerAcceptsOurSignatures() throws Exception {
		File exe = new File("/usr/sbin/sshd");
		assumeTrue(exe.canExecute(), "no sshd");
		assumeTrue(run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "host") == 0, "no ssh-keygen");
		assertEquals(0, run("ssh-keygen", "-q", "-t", "ecdsa", "-N", "", "-f", "ca"));
		List<KeyPair> good = new ArrayList<KeyPair>();
		StringBuilder keys = new StringBuilder();
		for (boolean ed : types()) {
			KeyPair k = sk(ed, SkSignature.FLAG_USER_PRESENT);
			good.add(k);
			keys.append(SshPublicKeys.toOpenSsh(k.getPublic())).append('\n');
		}
		KeyPair untouched = sk(false, 0);
		KeyPair waived = sk(false, 0);
		keys.append(SshPublicKeys.toOpenSsh(untouched.getPublic())).append('\n');
		keys.append("no-touch-required ").append(SshPublicKeys.toOpenSsh(waived.getPublic())).append('\n');
		File authorized = new File(dir, "ak");
		Files.write(authorized.toPath(), keys.toString().getBytes(StandardCharsets.UTF_8));
		// A security key certified by ssh-keygen, for TrustedUserCAKeys
		KeyPair certified = sk(false, SkSignature.FLAG_USER_PRESENT);
		File cpub = new File(dir, "certified.pub");
		Files.write(cpub.toPath(), (SshPublicKeys.toOpenSsh(certified.getPublic())+"\n").getBytes(StandardCharsets.UTF_8));
		assertEquals(0, run("ssh-keygen", "-q", "-s", "ca", "-I", "sk", "-n", System.getProperty("user.name"), cpub.getPath()));

		int port;
		try (ServerSocket ss = new ServerSocket(0)) {
			port = ss.getLocalPort();
		}
		File config = new File(dir, "sshd_config");
		Files.write(config.toPath(), String.join("\n", "Port "+port, "ListenAddress 127.0.0.1", "HostKey "+new File(dir, "host").getPath(),
				"AuthorizedKeysFile "+authorized.getPath(), "TrustedUserCAKeys "+new File(dir, "ca.pub").getPath(),
				"PidFile "+new File(dir, "sshd.pid").getPath(), "UsePAM no", "StrictModes no", "PasswordAuthentication no",
				"KbdInteractiveAuthentication no", "").getBytes(StandardCharsets.UTF_8));
		Process sshd = new ProcessBuilder(exe.getPath(), "-D", "-f", config.getPath(), "-E", new File(dir, "sshd.log").getPath()).start();
		try {
			long end = System.currentTimeMillis()+10000;
			boolean up = false;
			while( !up && System.currentTimeMillis() < end && sshd.isAlive() ) {
				try (java.net.Socket t = new java.net.Socket("127.0.0.1", port)) {
					up = true;
				} catch (java.io.IOException e) {
					Thread.sleep(100);
				}
			}
			assumeTrue(up, "sshd didn't start as this user");
			String user = System.getProperty("user.name");
			for (KeyPair k : good) {
				assertTrue(opensshLogin(port, user, new PublicKeyAuth(k)), "sshd accepts "+((SkPublicKey) k.getPublic()).getType());
			}
			assertFalse(opensshLogin(port, user, new PublicKeyAuth(untouched)), "sshd refuses an untouched key too");
			assertTrue(opensshLogin(port, user, new PublicKeyAuth(waived)), "and honours no-touch-required");
			assertTrue(opensshLogin(port, user, new PublicKeyAuth().addCertificate(certified,
					SshCertificate.load(new File(dir, "certified-cert.pub")))), "a security key certificate");
		} finally {
			sshd.destroy();
			sshd.waitFor(10, TimeUnit.SECONDS);
		}
	}

	private boolean opensshLogin(int port, String user, PublicKeyAuth auth) throws Exception {
		try (SshClient c = new SshClient()) {
			c.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
			ClientSession s = c.connectAndWait("127.0.0.1", port);
			try {
				s.authenticateAndWait(user, auth);
				return s.exec("echo ok", null, 30000).getStdoutText().equals("ok\n");
			} catch (SshException e) {
				return false;
			} finally {
				s.close();
			}
		}
	}

	@Test
	public void certificateTypeNames() {
		assertEquals("sk-ssh-ed25519-cert-v01@openssh.com", SshCertificate.certificateType(SkPublicKey.SK_ED25519));
		assertEquals(SkPublicKey.SK_ECDSA, SshCertificate.plainType("sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"));
		assertEquals("ssh-ed25519-cert-v01@openssh.com", SshCertificate.certificateType("ssh-ed25519"));
		assertEquals("rsa-sha2-512", SshCertificate.plainType("rsa-sha2-512-cert-v01@openssh.com"));
		assertTrue(SshAlgorithms.findSignature("sk-ssh-ed25519-cert-v01@openssh.com") != null);
		assertTrue(NOW > 0);
	}
}
