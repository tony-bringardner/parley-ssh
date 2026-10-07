package us.bringardner.parley.ssh.server;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.Ed25519;
import us.bringardner.parley.ssh.algorithms.SshCertificate;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;
import us.bringardner.parley.ssh.client.ClientSession;
import us.bringardner.parley.ssh.client.KnownHosts;
import us.bringardner.parley.ssh.client.PublicKeyAuth;
import us.bringardner.parley.ssh.client.SessionChannel;
import us.bringardner.parley.ssh.client.SshClient;
import us.bringardner.parley.ssh.keys.SshKeyLoader;

/**
 * OpenSSH certificates: the format (against ssh-keygen when installed), user certificates
 * with their restrictions, and host certificates checked against known_hosts.
 */
public class CertificateTest {

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

	public static KeyPair ec(String curve) throws Exception {
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
		g.initialize(new ECGenParameterSpec(curve));
		return g.generateKeyPair();
	}

	static KeyPair rsa() throws Exception {
		KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
		g.initialize(2048);
		return g.generateKeyPair();
	}

	static List<KeyPair> keyTypes() throws Exception {
		List<KeyPair> ret = new ArrayList<KeyPair>(Arrays.asList(ec("secp256r1"), ec("secp384r1"), rsa()));
		if( Ed25519.isSupported() ) {
			ret.add(0, Ed25519.generate());
		}
		return ret;
	}

	static Map<String, String> userExtensions() {
		Map<String, String> ext = new HashMap<String, String>();
		ext.put(SshCertificate.PERMIT_PTY, "");
		ext.put(SshCertificate.PERMIT_PORT_FORWARDING, "");
		return ext;
	}

	public static SshCertificate user(KeyPair key, KeyPair ca, Map<String, String> critical, Map<String, String> ext, String... principals) throws Exception {
		return SshCertificate.sign(key.getPublic(), SshCertificate.USER, "test-id", Arrays.asList(principals), NOW-60, NOW+3600, critical, ext, ca);
	}

	// ------------------------------------------------------------------ the format

	@Test
	public void signDecodeAndCheck() throws Exception {
		for (KeyPair ca : keyTypes()) {
			for (KeyPair key : keyTypes()) {
				Map<String, String> crit = Collections.singletonMap(SshCertificate.FORCE_COMMAND, "echo hi");
				SshCertificate c = SshCertificate.sign(key.getPublic(), SshCertificate.USER, "kid", Arrays.asList("alice", "bob"),
						NOW-60, SshCertificate.FOREVER, crit, userExtensions(), ca);
				SshCertificate d = SshCertificate.decode(c.getBlob());
				assertEquals(SshCertificate.certificateType(SshPublicKeys.keyType(key.getPublic())), d.getType());
				assertArrayEquals(SshPublicKeys.encode(key.getPublic()), d.getPublicKeyBlob());
				assertArrayEquals(SshPublicKeys.encode(ca.getPublic()), d.getCaKeyBlob());
				assertEquals("kid", d.getKeyId());
				assertEquals(Arrays.asList("alice", "bob"), d.getPrincipals());
				assertEquals("echo hi", d.getCriticalOptions().get(SshCertificate.FORCE_COMMAND));
				assertTrue(d.hasExtension(SshCertificate.PERMIT_PTY));
				assertTrue(d.isSignatureValid(), d.toString());
				assertNull(d.check(SshCertificate.USER, "alice", NOW));
				assertNull(d.check(SshCertificate.USER, "alice", Long.MAX_VALUE), "valid forever");
				assertNotNull(d.check(SshCertificate.USER, "carol", NOW));
				assertNotNull(d.check(SshCertificate.HOST, "alice", NOW));
				assertNotNull(d.check(SshCertificate.USER, "alice", NOW-3600), "not valid yet");

				// Any change breaks the CA's signature
				byte[] blob = c.getBlob();
				blob[blob.length/2] ^= 1;
				SshCertificate bad;
				try {
					bad = SshCertificate.decode(blob);
				} catch (SshException e) {
					continue;
				}
				assertFalse(bad.isSignatureValid());
			}
		}
	}

	@Test
	public void hostPrincipalPatterns() throws Exception {
		KeyPair ca = ec("secp256r1");
		KeyPair key = ec("secp256r1");
		SshCertificate c = SshCertificate.sign(key.getPublic(), SshCertificate.HOST, "h", Arrays.asList("*.example.com", "db?"), NOW-60, NOW+60, null, null, ca);
		assertNull(c.check(SshCertificate.HOST, "www.example.com", NOW));
		assertNull(c.check(SshCertificate.HOST, "DB1", NOW));
		assertNotNull(c.check(SshCertificate.HOST, "example.org", NOW));
		SshCertificate any = SshCertificate.sign(key.getPublic(), SshCertificate.HOST, "h", Collections.emptyList(), NOW-60, NOW+60, null, null, ca);
		assertNull(any.check(SshCertificate.HOST, "anything", NOW), "no principals: any host");
		SshCertificate expired = SshCertificate.sign(key.getPublic(), SshCertificate.HOST, "h", Collections.emptyList(), NOW-120, NOW-60, null, null, ca);
		assertEquals("expired", expired.check(SshCertificate.HOST, "anything", NOW));
	}

	private static boolean run(File dir, String... cmd) throws Exception {
		Process p;
		try {
			p = new ProcessBuilder(cmd).directory(dir).redirectErrorStream(true).start();
		} catch (java.io.IOException e) {
			return false;
		}
		String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		boolean ok = p.waitFor(60, TimeUnit.SECONDS) && p.exitValue() == 0;
		if( !ok ) {
			System.err.println(String.join(" ", cmd)+": "+out);
		}
		return ok;
	}

	/** Certificates ssh-keygen makes are read, and ours are read by ssh-keygen */
	@Test
	public void sshKeygenInterop() throws Exception {
		assumeTrue(run(dir, "ssh-keygen", "-q", "-t", "ecdsa", "-N", "", "-f", "ca"), "no ssh-keygen");
		for (String type : new String[] {"ed25519", "ecdsa", "rsa"}) {
			assertTrue(run(dir, "ssh-keygen", "-q", "-t", type, "-N", "", "-f", "user_"+type));
			assertTrue(run(dir, "ssh-keygen", "-q", "-s", "ca", "-I", "kid-"+type, "-n", "alice,bob", "-V", "-5m:+1h",
					"-O", "force-command=echo forced", "-O", "source-address=127.0.0.1/32", "user_"+type+".pub"));
			SshCertificate c = SshCertificate.load(new File(dir, "user_"+type+"-cert.pub"));
			assertEquals("kid-"+type, c.getKeyId());
			assertEquals(Arrays.asList("alice", "bob"), c.getPrincipals());
			assertEquals("echo forced", c.getCriticalOptions().get(SshCertificate.FORCE_COMMAND));
			assertEquals("127.0.0.1/32", c.getCriticalOptions().get(SshCertificate.SOURCE_ADDRESS));
			assertTrue(c.hasExtension(SshCertificate.PERMIT_PTY), "ssh-keygen's default extensions");
			assertTrue(c.isSignatureValid());
			assertNull(c.check(SshCertificate.USER, "bob", NOW));
			assertArrayEquals(SshPublicKeys.encode(SshKeyLoader.loadPublic(new File(dir, "user_"+type+".pub"))), c.getPublicKeyBlob());
		}
		// Ours, with an RSA CA (rsa-sha2-512 signature), as ssh-keygen -L reads it
		KeyPair ca = rsa();
		KeyPair key = ec("secp384r1");
		SshCertificate ours = SshCertificate.sign(key.getPublic(), SshCertificate.HOST, "our-host", Arrays.asList("host.example"),
				NOW-60, NOW+3600, null, null, ca);
		File f = new File(dir, "ours-cert.pub");
		Files.write(f.toPath(), (ours.toOpenSsh("ours")+"\n").getBytes(StandardCharsets.UTF_8));
		Process p = new ProcessBuilder("ssh-keygen", "-L", "-f", f.getPath()).redirectErrorStream(true).start();
		String listing = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		assertTrue(p.waitFor(30, TimeUnit.SECONDS));
		assertEquals(0, p.exitValue(), listing);
		assertTrue(listing.contains("host certificate"), listing);
		assertTrue(listing.contains("host.example"), listing);
		assertTrue(listing.contains("our-host"), listing);
	}

	// ------------------------------------------------------------------ user certificates

	private SshServer startServer(IHostKeyProvider hostKeys, IPublicKeyAuthenticator auth) throws Exception {
		server = new SshServer(0);
		server.setHostKeyProvider(hostKeys);
		server.setPublicKeyAuthenticator(auth);
		server.setCommandFactory((line, env) -> ServerTest.command(line));
		server.setForwardingFilter(ForwardingFilters.allowAll());
		server.setLoginFailureDelay(0);
		server.startAndWait(5000);
		return server;
	}

	private ClientSession connect() throws Exception {
		client = new SshClient();
		client.setHostKeyVerifier(new KnownHosts(Collections.<String>emptyList()).setPolicy(KnownHosts.Policy.ACCEPT));
		return client.connectAndWait("localhost", server.getLocalPort());
	}

	private ClientSession login(KeyPair key, SshCertificate cert) throws Exception {
		ClientSession s = connect();
		s.authenticateAndWait("alice", new PublicKeyAuth().addCertificate(key, cert));
		return s;
	}

	private void refused(KeyPair key, SshCertificate cert, String why) throws Exception {
		ClientSession s = connect();
		assertThrows(SshException.class, () -> s.authenticateAndWait("alice", new PublicKeyAuth().addCertificate(key, cert)), why);
		s.close();
	}

	@Test
	public void userCertificates() throws Exception {
		KeyPair ca = ec("secp256r1");
		KeyPair other = ec("secp256r1");
		KeyPair alice = Ed25519.isSupported() ? Ed25519.generate() : ec("secp256r1");
		startServer(HostKeyProviders.ephemeral(), new UserCertificateAuthenticator(Collections.singletonList(ca.getPublic())));

		ClientSession s = login(alice, user(alice, ca, null, userExtensions(), "alice"));
		assertEquals("alice", s.exec("whoami", null, 10000).getStdoutText());
		s.close();

		refused(alice, user(alice, other, null, userExtensions(), "alice"), "another CA");
		refused(alice, user(alice, ca, null, userExtensions(), "bob"), "for another user");
		refused(alice, SshCertificate.sign(alice.getPublic(), SshCertificate.USER, "old", Arrays.asList("alice"), NOW-7200, NOW-3600, null, null, ca), "expired");
		refused(alice, SshCertificate.sign(alice.getPublic(), SshCertificate.HOST, "host", Arrays.asList("alice"), NOW-60, NOW+60, null, null, ca), "a host certificate");
		refused(alice, user(alice, ca, Collections.singletonMap("verify-required", ""), userExtensions(), "alice"), "unknown critical option");
		refused(alice, user(alice, ca, Collections.singletonMap(SshCertificate.SOURCE_ADDRESS, "10.0.0.0/8"), userExtensions(), "alice"), "from elsewhere");
		login(alice, user(alice, ca, Collections.singletonMap(SshCertificate.SOURCE_ADDRESS, "127.0.0.1/32,::1/128"), userExtensions(), "alice")).close();

		// Signed by another CA, then made to name the trusted one: the signature doesn't match
		refused(alice, forged(user(alice, other, null, userExtensions(), "alice"), other, ca), "forged");

		// A plain key is not enough, nor a certificate for another key
		ClientSession plain = connect();
		assertThrows(SshException.class, () -> plain.authenticateAndWait("alice", new PublicKeyAuth(alice)));
		plain.close();
		assertThrows(IllegalArgumentException.class, () -> new PublicKeyAuth().addCertificate(other, user(alice, ca, null, null, "alice")));
	}

	/**
	 * @return the certificate with its CA key replaced by another of the same size
	 */
	static SshCertificate forged(SshCertificate cert, KeyPair signer, KeyPair claimed) throws Exception {
		byte[] blob = cert.getBlob();
		byte[] from = SshPublicKeys.encode(signer.getPublic());
		byte[] to = SshPublicKeys.encode(claimed.getPublic());
		assertEquals(from.length, to.length);
		for (int i = 0; i+from.length <= blob.length; i++) {
			if( Arrays.equals(Arrays.copyOfRange(blob, i, i+from.length), from) ) {
				System.arraycopy(to, 0, blob, i, to.length);
				SshCertificate ret = SshCertificate.decode(blob);
				assertFalse(ret.isSignatureValid());
				return ret;
			}
		}
		throw new AssertionError("CA key not found in the certificate");
	}

	@Test
	public void authorizedPrincipalsAndCombinedWithAuthorizedKeys() throws Exception {
		KeyPair ca = ec("secp256r1");
		KeyPair alice = ec("secp256r1");
		KeyPair plainKey = ec("secp256r1");
		File keys = new File(dir, "authorized_keys");
		Files.write(keys.toPath(), (SshPublicKeys.toOpenSsh(plainKey.getPublic())+"\n").getBytes(StandardCharsets.UTF_8));
		UserCertificateAuthenticator cas = new UserCertificateAuthenticator(Collections.singletonList(ca.getPublic()))
				.setPrincipals(user -> "alice".equals(user) ? Arrays.asList("ops", "alice-admin") : null);
		startServer(HostKeyProviders.ephemeral(), AuthorizedKeysAuthenticator.forFile(keys).or(cas));
		login(alice, user(alice, ca, null, null, "ops")).close();
		refused(alice, user(alice, ca, null, null, "alice"), "alice is not one of alice's principals here");
		ClientSession s = connect();
		s.authenticateAndWait("alice", new PublicKeyAuth(plainKey));
		s.close();
	}

	@Test
	public void certificateRestrictions() throws Exception {
		KeyPair ca = ec("secp256r1");
		KeyPair alice = ec("secp256r1");
		startServer(HostKeyProviders.ephemeral(), new UserCertificateAuthenticator(Collections.singletonList(ca.getPublic())));

		// force-command runs instead of what was asked; the request is in SSH_ORIGINAL_COMMAND
		ClientSession s = login(alice, user(alice, ca, Collections.singletonMap(SshCertificate.FORCE_COMMAND, "env SSH_ORIGINAL_COMMAND"), userExtensions(), "alice"));
		assertEquals("whoami", s.exec("whoami", null, 10000).getStdoutText());
		s.close();

		// No permit-pty, no permit-port-forwarding
		ClientSession limited = login(alice, user(alice, ca, null, Collections.<String, String>emptyMap(), "alice"));
		SessionChannel ch = limited.openSession();
		assertThrows(SshException.class, () -> ch.requestPty("xterm", 80, 24));
		ch.close();
		assertThrows(java.io.IOException.class, () -> limited.openDirectTcpip("localhost", server.getLocalPort()));
		assertEquals("alice", limited.exec("whoami", null, 10000).getStdoutText(), "other requests still work");
		limited.close();

		// With the extensions
		s = login(alice, user(alice, ca, null, userExtensions(), "alice"));
		SessionChannel ch2 = s.openSession();
		ch2.requestPty("xterm", 80, 24);
		ch2.close();
		s.openDirectTcpip("localhost", server.getLocalPort()).close();
		s.close();
	}

	// ------------------------------------------------------------------ host certificates

	private SshServer hostCertServer(KeyPair hostKey, SshCertificate cert) throws Exception {
		return startServer(HostKeyProviders.withCertificates(HostKeyProviders.of(hostKey), cert),
				new UserCertificateAuthenticator(Collections.singletonList(ec("secp256r1").getPublic())));
	}

	private ClientSession connect(KnownHosts known) throws Exception {
		client = new SshClient();
		client.setHostKeyVerifier(known);
		return client.connectAndWait("localhost", server.getLocalPort());
	}

	@Test
	public void hostCertificates() throws Exception {
		KeyPair ca = ec("secp384r1");
		KeyPair hostKey = Ed25519.isSupported() ? Ed25519.generate() : ec("secp256r1");
		SshCertificate cert = SshCertificate.sign(hostKey.getPublic(), SshCertificate.HOST, "test-host", Arrays.asList("localhost"),
				NOW-60, NOW+3600, null, null, ca);
		hostCertServer(hostKey, cert);
		assertEquals(1, server.getHostCertificates().size());
		String caLine = "@cert-authority * "+SshPublicKeys.toOpenSsh(ca.getPublic());

		// Trusted through the CA alone: no key for the host in known_hosts
		ClientSession s = connect(new KnownHosts(Arrays.asList(caLine)));
		assertNotNull(s.getHostCertificate(), "the server identified itself with its certificate");
		assertEquals(cert.getType(), s.getNegotiated().getHostKey());
		assertArrayEquals(cert.getBlob(), s.getHostCertificate().getBlob());
		s.close();
		client.close();

		// Another CA, a CA for other hosts, or a revoked key: refused
		String otherCa = "@cert-authority * "+SshPublicKeys.toOpenSsh(ec("secp256r1").getPublic());
		assertThrows(java.io.IOException.class, () -> connect(new KnownHosts(Arrays.asList(otherCa))));
		client.close();
		assertThrows(java.io.IOException.class, () -> connect(new KnownHosts(Arrays.asList("@cert-authority *.example.com "+SshPublicKeys.toOpenSsh(ca.getPublic())))));
		client.close();
		assertThrows(java.io.IOException.class, () -> connect(new KnownHosts(Arrays.asList(caLine, "@revoked * "+SshPublicKeys.toOpenSsh(hostKey.getPublic())))));
		client.close();

		// A forged host certificate naming the trusted CA
		KeyPair rogue = ec("secp384r1");
		SshCertificate forged = forged(SshCertificate.sign(hostKey.getPublic(), SshCertificate.HOST, "rogue", Arrays.asList("localhost"),
				NOW-60, NOW+3600, null, null, rogue), rogue, ca);
		server.stop(5000, false);
		hostCertServer(hostKey, forged);
		assertThrows(java.io.IOException.class, () -> connect(new KnownHosts(Arrays.asList(caLine))));
		client.close();

		// A client without a CA uses the plain key
		s = connect(new KnownHosts(Collections.<String>emptyList()).setPolicy(KnownHosts.Policy.ACCEPT));
		assertNull(s.getHostCertificate());
		assertFalse(SshCertificate.isCertificateType(s.getNegotiated().getHostKey()));
		s.close();
	}

	@Test
	public void hostCertificateForAnotherHostIsRefused() throws Exception {
		KeyPair ca = ec("secp256r1");
		KeyPair hostKey = ec("secp256r1");
		hostCertServer(hostKey, SshCertificate.sign(hostKey.getPublic(), SshCertificate.HOST, "h", Arrays.asList("other.example"),
				NOW-60, NOW+3600, null, null, ca));
		assertThrows(java.io.IOException.class, () -> connect(new KnownHosts(Arrays.asList("@cert-authority * "+SshPublicKeys.toOpenSsh(ca.getPublic())))));
	}

	@Test
	public void certificatesForOtherKeysAreNotUsed() throws Exception {
		KeyPair ca = ec("secp256r1");
		KeyPair hostKey = ec("secp256r1");
		hostCertServer(hostKey, SshCertificate.sign(ec("secp256r1").getPublic(), SshCertificate.HOST, "h", Collections.emptyList(),
				NOW-60, NOW+3600, null, null, ca));
		assertTrue(server.getHostCertificates().isEmpty());
	}
}
