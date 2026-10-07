package us.bringardner.parley.ssh.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.keyboard.UserAuthKeyboardInteractiveFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.ssh.SshConstants;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;

/**
 * Client authentication against an embedded MINA SSHD server: password, publickey (RSA and
 * each ECDSA curve), keyboard-interactive, two methods in a row, banners.
 */
public class MinaAuthTest {

	private static KeyPair hostKey;
	private static KeyPair rsa;
	private static KeyPair ec256;
	private static KeyPair ec384;
	private static KeyPair ec521;
	private static KeyPair stranger;

	private SshServer sshd;
	private SshClient client;
	/** Public keys the server accepts for alice */
	private final List<PublicKey> authorized = new CopyOnWriteArrayList<PublicKey>();
	/** Signature algorithms MINA saw for public keys */
	private final List<String> seenKeyTypes = new CopyOnWriteArrayList<String>();

	private static KeyPair ec(String curve) throws Exception {
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
		g.initialize(new ECGenParameterSpec(curve));
		return g.generateKeyPair();
	}

	@BeforeAll
	public static void keys() throws Exception {
		hostKey = ec("secp256r1");
		KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
		g.initialize(2048);
		rsa = g.generateKeyPair();
		ec256 = ec("secp256r1");
		ec384 = ec("secp384r1");
		ec521 = ec("secp521r1");
		stranger = ec("secp256r1");
	}

	private void start(SshServer s) throws Exception {
		s.setHost("localhost");
		s.setPort(0);
		s.setKeyPairProvider(KeyPairProvider.wrap(hostKey));
		s.setPasswordAuthenticator((user, password, session) -> "alice".equals(user) && "secret".equals(password));
		s.setPublickeyAuthenticator((user, key, session) -> {
			seenKeyTypes.add(SshPublicKeys.keyType(key));
			if( !"alice".equals(user) ) {
				return false;
			}
			for (PublicKey k : authorized) {
				if( Arrays.equals(SshPublicKeys.encode(k), SshPublicKeys.encode(key)) ) {
					return true;
				}
			}
			return false;
		});
		s.start();
		sshd = s;
		client = new SshClient();
		client.setHostKeyVerifier(HostKeyVerifiers.only(hostKey.getPublic()));
	}

	private ClientSession session() throws Exception {
		return client.connectAndWait("localhost", sshd.getPort());
	}

	@AfterEach
	public void stop() throws Exception {
		if( client != null ) {
			client.close();
		}
		if( sshd != null ) {
			sshd.stop(true);
		}
	}

	@Test
	public void password() throws Exception {
		start(SshServer.setUpDefaultServer());
		ClientSession s = session();
		SshException e = assertThrows(SshException.class, () -> s.authenticateAndWait("alice", new PasswordAuth("wrong")));
		assertEquals(SshConstants.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, e.getReason());
		assertFalse(s.isAuthenticated());
		assertTrue(s.isOpen(), "a failed login leaves the session open for another try");

		s.authenticateAndWait("alice", new PasswordAuth("secret"));
		assertTrue(s.isAuthenticated());
		assertEquals("alice", s.getAuthenticatedUser());
		// Re-keying works after a login (and starts by itself from now on)
		s.rekey().get(10, TimeUnit.SECONDS);
		assertThrows(Exception.class, () -> s.authenticate("alice", new PasswordAuth("secret")).get(), "only once");
		s.close();
	}

	@Test
	public void publicKeys() throws Exception {
		start(SshServer.setUpDefaultServer());
		for (KeyPair kp : new KeyPair[] {rsa, ec256, ec384, ec521}) {
			authorized.clear();
			authorized.add(kp.getPublic());
			ClientSession s = session();
			// A key the server doesn't know comes first: it is only offered (never signed with), then the next is tried
			s.authenticateAndWait("alice", new PublicKeyAuth(stranger, kp));
			assertTrue(s.isAuthenticated(), SshPublicKeys.keyType(kp.getPublic()));
			if( kp == rsa ) {
				assertTrue(s.getServerSignatureAlgorithms().contains("rsa-sha2-512"), "MINA sends server-sig-algs");
			}
			s.close();
		}
		ClientSession s = session();
		authorized.clear();
		SshException e = assertThrows(SshException.class, () -> s.authenticateAndWait("alice", new PublicKeyAuth(rsa, ec256)));
		assertEquals(SshConstants.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, e.getReason());
		s.close();
	}

	/** The usual fallback: keys first, then the password */
	@Test
	public void keyThenPassword() throws Exception {
		start(SshServer.setUpDefaultServer());
		ClientSession s = session();
		s.authenticateAndWait("alice", new PublicKeyAuth(stranger), new PasswordAuth("secret"));
		assertTrue(s.isAuthenticated());
		s.close();
	}

	@Test
	public void keyboardInteractive() throws Exception {
		SshServer server = SshServer.setUpDefaultServer();
		// Keyboard-interactive only (MINA asks for the password through it)
		server.setUserAuthFactories(Collections.singletonList(UserAuthKeyboardInteractiveFactory.INSTANCE));
		start(server);

		ClientSession s = session();
		// "password" isn't allowed, so it is skipped and keyboard-interactive answers the prompt
		s.authPassword("alice", "secret".toCharArray());
		assertTrue(s.isAuthenticated());
		s.close();

		ClientSession s2 = session();
		List<String> prompts = new CopyOnWriteArrayList<String>();
		assertThrows(SshException.class, () -> s2.authenticateAndWait("alice", new KeyboardInteractiveAuth((name, instruction, p, echo) -> {
			prompts.addAll(Arrays.asList(p));
			return new String[] {"wrong"};
		})));
		assertFalse(prompts.isEmpty(), "the server prompted");
		s2.close();
	}

	/** The server wants a key and a password: the first succeeds partially */
	@Test
	public void twoMethods() throws Exception {
		SshServer server = SshServer.setUpDefaultServer();
		CoreModuleProperties.AUTH_METHODS.set(server, "publickey,password");
		start(server);
		authorized.add(ec384.getPublic());

		ClientSession s = session();
		assertThrows(SshException.class, () -> s.authenticateAndWait("alice", new PasswordAuth("secret")), "a password alone is not enough");
		s.close();

		ClientSession s2 = session();
		s2.authenticateAndWait("alice", new PublicKeyAuth(ec384), new PasswordAuth("secret"));
		assertTrue(s2.isAuthenticated());
		s2.close();
	}

	@Test
	public void banner() throws Exception {
		SshServer server = SshServer.setUpDefaultServer();
		CoreModuleProperties.WELCOME_BANNER.set(server, "Authorized users only");
		start(server);
		ClientSession s = session();
		List<String> banners = new CopyOnWriteArrayList<String>();
		s.setBannerListener(banners::add);
		s.authenticateAndWait("alice", new PasswordAuth("secret"));
		assertEquals(1, banners.size());
		assertTrue(banners.get(0).contains("Authorized users only"), banners.toString());
		s.close();
	}
}
