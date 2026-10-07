package us.bringardner.parley.ssh.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.SshCertificate;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;
import us.bringardner.parley.ssh.client.ClientSession;
import us.bringardner.parley.ssh.client.HostKeyVerifiers;
import us.bringardner.parley.ssh.client.PublicKeyAuth;
import us.bringardner.parley.ssh.client.SessionChannel;
import us.bringardner.parley.ssh.client.SshClient;

/**
 * authorized_keys options (sshd(8) AUTHORIZED_KEYS FILE FORMAT): parsing, and what they
 * do to a session; cert-authority lines.
 */
public class AuthorizedKeysOptionsTest {

	@TempDir
	File dir;

	private SshServer server;
	private SshClient client;
	private File keys;

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

	// ------------------------------------------------------------------ parsing

	private static AuthorizedKeysAuthenticator.Entry line(String options, KeyPair key) throws Exception {
		return AuthorizedKeysAuthenticator.parseLine(options+" "+SshPublicKeys.toOpenSsh(key.getPublic())+" comment");
	}

	@Test
	public void parsing() throws Exception {
		KeyPair k = CertificateTest.ec("secp256r1");
		AuthorizedKeysAuthenticator.Entry e = line("command=\"echo \\\"a, b\\\"\",no-pty,from=\"127.0.0.1,::1\"", k);
		assertEquals("echo \"a, b\"", e.restrictions.getForceCommand(), "quotes, escaped quotes and commas in a value");
		assertFalse(e.restrictions.isPtyAllowed());
		assertTrue(e.restrictions.isPortForwardingAllowed());
		assertEquals("127.0.0.1,::1", e.from);

		e = line("restrict,pty", k);
		assertTrue(e.restrictions.isPtyAllowed(), "pty allows it again after restrict");
		assertFalse(e.restrictions.isPortForwardingAllowed());
		assertFalse(e.restrictions.isAgentForwardingAllowed());

		e = line("permitopen=\"db:5432\",permitopen=\"*:80\"", k);
		assertTrue(e.restrictions.canConnect("db", 5432));
		assertTrue(e.restrictions.canConnect("web", 80));
		assertFalse(e.restrictions.canConnect("db", 22));

		e = line("cert-authority,principals=\"ops, admins\"", k);
		assertTrue(e.certAuthority);
		assertEquals(Arrays.asList("ops", "admins"), e.principals);

		assertThrows(IllegalArgumentException.class, () -> line("no-such-option", k));
		assertThrows(IllegalArgumentException.class, () -> line("principals=\"x\"", k), "principals= needs cert-authority");
		assertThrows(IllegalArgumentException.class, () -> line("command=\"unterminated", k));
		assertThrows(IllegalArgumentException.class, () -> line("command", k), "command needs a value");
		// environment= is ignored, as OpenSSH does without PermitUserEnvironment
		assertNull(line("environment=\"A=b\"", k).restrictions.getForceCommand());

		assertEquals(java.time.LocalDate.of(2030, 1, 2).atStartOfDay(java.time.ZoneOffset.UTC).toEpochSecond(),
				AuthorizedKeysAuthenticator.expiry("20300102Z"));
		assertEquals(java.time.LocalDateTime.of(2030, 1, 2, 3, 4, 5).atZone(java.time.ZoneOffset.UTC).toEpochSecond(),
				AuthorizedKeysAuthenticator.expiry("20300102030405Z"));
		assertThrows(IllegalArgumentException.class, () -> AuthorizedKeysAuthenticator.expiry("2030-01-02"));
	}

	@Test
	public void fromPatterns() throws Exception {
		InetSocketAddress local = new InetSocketAddress("127.0.0.1", 1);
		assertTrue(AuthorizedKeysAuthenticator.fromMatches("127.0.0.1", local));
		assertTrue(AuthorizedKeysAuthenticator.fromMatches("10.*,127.0.0.?", local));
		assertTrue(AuthorizedKeysAuthenticator.fromMatches("127.0.0.0/8", local));
		assertFalse(AuthorizedKeysAuthenticator.fromMatches("10.0.0.0/8", local));
		assertFalse(AuthorizedKeysAuthenticator.fromMatches("!127.0.0.1,*", local), "negation wins");
		assertFalse(AuthorizedKeysAuthenticator.fromMatches("localhost", local), "no DNS lookups");
	}

	// ------------------------------------------------------------------ sessions

	private void startServer(String... lines) throws Exception {
		keys = new File(dir, "authorized_keys");
		Files.write(keys.toPath(), (String.join("\n", lines)+"\n").getBytes(StandardCharsets.UTF_8));
		server = new SshServer(0);
		server.setHostKeyProvider(HostKeyProviders.ephemeral());
		server.setPublicKeyAuthenticator(AuthorizedKeysAuthenticator.forFile(keys));
		server.setCommandFactory((line, env) -> ServerTest.command(line));
		server.setForwardingFilter(ForwardingFilters.allowAll());
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

	private void refused(PublicKeyAuth auth, String why) throws Exception {
		assertThrows(SshException.class, () -> login(auth), why);
	}

	private static String key(String options, KeyPair k) {
		return (options.isEmpty() ? "" : options+" ")+SshPublicKeys.toOpenSsh(k.getPublic());
	}

	@Test
	public void commandAndPty() throws Exception {
		KeyPair forced = CertificateTest.ec("secp256r1");
		KeyPair noPty = CertificateTest.ec("secp256r1");
		startServer(key("command=\"env SSH_ORIGINAL_COMMAND\"", forced), key("no-pty", noPty));
		ClientSession s = login(new PublicKeyAuth(forced));
		assertEquals("whoami", s.exec("whoami", null, 10000).getStdoutText(), "the forced command ran");
		s.close();
		s = login(new PublicKeyAuth(noPty));
		SessionChannel ch = s.openSession();
		assertThrows(SshException.class, () -> ch.requestPty("xterm", 80, 24));
		assertEquals("alice", s.exec("whoami", null, 10000).getStdoutText());
		s.close();
	}

	@Test
	public void forwardingOptions() throws Exception {
		KeyPair restricted = CertificateTest.ec("secp256r1");
		KeyPair one = CertificateTest.ec("secp256r1");
		try (ServerSocket target = new ServerSocket(0); ServerSocket other = new ServerSocket(0)) {
			startServer(key("restrict", restricted), key("permitopen=\"localhost:"+target.getLocalPort()+"\"", one));
			ClientSession s = login(new PublicKeyAuth(restricted));
			assertThrows(java.io.IOException.class, () -> s.openDirectTcpip("localhost", target.getLocalPort()), "restrict");
			s.close();
			ClientSession t = login(new PublicKeyAuth(one));
			t.openDirectTcpip("localhost", target.getLocalPort()).close();
			assertThrows(java.io.IOException.class, () -> t.openDirectTcpip("localhost", other.getLocalPort()), "not permitted");
			t.close();
		}
	}

	@Test
	public void fromAndExpiry() throws Exception {
		KeyPair far = CertificateTest.ec("secp256r1");
		KeyPair near = CertificateTest.ec("secp256r1");
		KeyPair expired = CertificateTest.ec("secp256r1");
		KeyPair current = CertificateTest.ec("secp256r1");
		startServer(key("from=\"10.0.0.0/8\"", far), key("from=\"127.0.0.1,::1\"", near),
				key("expiry-time=\"20000101Z\"", expired), key("expiry-time=\"29991231Z\"", current));
		refused(new PublicKeyAuth(far), "from elsewhere");
		login(new PublicKeyAuth(near)).close();
		refused(new PublicKeyAuth(expired), "expired");
		login(new PublicKeyAuth(current)).close();
	}

	@Test
	public void certAuthorityLines() throws Exception {
		KeyPair ca = CertificateTest.ec("secp256r1");
		KeyPair opsCa = CertificateTest.ec("secp256r1");
		KeyPair forcedCa = CertificateTest.ec("secp256r1");
		KeyPair alice = CertificateTest.ec("secp256r1");
		startServer(key("cert-authority", ca), key("cert-authority,principals=\"ops\"", opsCa),
				key("cert-authority,command=\"echo line\"", forcedCa));

		login(new PublicKeyAuth().addCertificate(alice, CertificateTest.user(alice, ca, null, null, "alice"))).close();
		refused(new PublicKeyAuth().addCertificate(alice, CertificateTest.user(alice, ca, null, null, "bob")), "another user");
		login(new PublicKeyAuth().addCertificate(alice, CertificateTest.user(alice, opsCa, null, null, "ops"))).close();
		refused(new PublicKeyAuth().addCertificate(alice, CertificateTest.user(alice, opsCa, null, null, "alice")), "not one of the line's principals");
		// The CA's key is not a user key
		refused(new PublicKeyAuth(ca), "a CA key as a plain key");

		// The line's options apply to the certificate's session, with the certificate's own
		ClientSession s = login(new PublicKeyAuth().addCertificate(alice, CertificateTest.user(alice, forcedCa, null, null, "alice")));
		assertEquals("line\n", s.exec("whoami", null, 10000).getStdoutText());
		s.close();
		s = login(new PublicKeyAuth().addCertificate(alice, CertificateTest.user(alice, forcedCa,
				Collections.singletonMap(SshCertificate.FORCE_COMMAND, "echo line"), null, "alice")));
		s.close();
		refused(new PublicKeyAuth().addCertificate(alice, CertificateTest.user(alice, forcedCa,
				Collections.singletonMap(SshCertificate.FORCE_COMMAND, "echo cert"), null, "alice")), "two different forced commands");
	}

	@Test
	public void unknownOptionsSkipTheLine() throws Exception {
		KeyPair k = CertificateTest.ec("secp256r1");
		startServer(key("no-such-option", k));
		refused(new PublicKeyAuth(k), "skipped");
		List<AuthorizedKeysAuthenticator.Entry> e = new AuthorizedKeysAuthenticator(u -> null).parse(Files.readAllLines(keys.toPath()), "test");
		assertTrue(e.isEmpty());
	}
}
