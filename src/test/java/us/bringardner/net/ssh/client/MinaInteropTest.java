package us.bringardner.net.ssh.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.server.SshServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.net.ssh.SshBuffer;
import us.bringardner.net.ssh.SshConstants;
import us.bringardner.net.ssh.SshException;
import us.bringardner.net.ssh.algorithms.SshAlgorithms;
import us.bringardner.net.ssh.algorithms.SshPublicKeys;

/**
 * The client against an embedded Apache MINA SSHD server: every key exchange, host key,
 * cipher and MAC, strict key exchange, re-keying and host key checks.
 */
public class MinaInteropTest {

	private static SshServer sshd;
	private static int port;
	private static KeyPair rsa;
	private static KeyPair ec256;
	private static KeyPair ec384;
	private static KeyPair ec521;

	@TempDir
	File dir;

	private static KeyPair ec(String curve) throws Exception {
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
		g.initialize(new ECGenParameterSpec(curve));
		return g.generateKeyPair();
	}

	@BeforeAll
	public static void startServer() throws Exception {
		KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
		g.initialize(3072);
		rsa = g.generateKeyPair();
		ec256 = ec("secp256r1");
		ec384 = ec("secp384r1");
		ec521 = ec("secp521r1");
		sshd = SshServer.setUpDefaultServer();
		sshd.setHost("localhost");
		sshd.setPort(0);
		sshd.setKeyPairProvider(KeyPairProvider.wrap(rsa, ec256, ec384, ec521));
		sshd.setPasswordAuthenticator((user, password, session) -> "test".equals(user) && "test".equals(password));
		sshd.start();
		port = sshd.getPort();
	}

	@AfterAll
	public static void stopServer() throws Exception {
		if( sshd != null ) {
			sshd.stop(true);
		}
	}

	private static SshClient client(SshAlgorithms algorithms) {
		SshClient ret = new SshClient();
		ret.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
		ret.setConnectTimeout(20000);
		if( algorithms != null ) {
			ret.setAlgorithms(algorithms);
		}
		return ret;
	}

	/** Connect with these algorithms, check what was negotiated, ask for ssh-userauth */
	private static ClientSession connect(SshClient client) throws Exception {
		ClientSession s = client.connectAndWait("localhost", port);
		assertTrue(s.isReady());
		assertTrue(s.isStrictKex(), "MINA supports strict key exchange");
		assertNotNull(s.getPeerVersion());
		s.requestService(SshConstants.SERVICE_USERAUTH).get(10, TimeUnit.SECONDS);
		return s;
	}

	@Test
	public void everyKeyExchange() throws Exception {
		for (String kex : SshAlgorithms.defaults().getKeyExchangeNames()) {
			try (SshClient c = client(SshAlgorithms.defaults().setKeyExchanges(kex))) {
				ClientSession s = connect(c);
				assertEquals(kex, s.getNegotiated().getKeyExchange());
				s.close();
			}
		}
	}

	@Test
	public void everyHostKeyAlgorithm() throws Exception {
		for (String alg : SshAlgorithms.defaults().getHostKeyAlgorithmNames()) {
			try (SshClient c = client(SshAlgorithms.defaults().setHostKeyAlgorithms(alg))) {
				ClientSession s = connect(c);
				assertEquals(alg, s.getNegotiated().getHostKey());
				String type = SshPublicKeys.keyType(s.getServerHostKey());
				assertEquals(SshAlgorithms.findSignature(alg).getKeyType(), type);
				s.close();
			}
		}
	}

	@Test
	public void everyCipherAndMac() throws Exception {
		for (String cipher : SshAlgorithms.defaults().getCipherNames()) {
			for (String mac : SshAlgorithms.defaults().getMacNames()) {
				try (SshClient c = client(SshAlgorithms.defaults().setCiphers(cipher).setMacs(mac))) {
					ClientSession s = connect(c);
					assertEquals(cipher, s.getNegotiated().getCipherClientToServer());
					assertEquals(cipher, s.getNegotiated().getCipherServerToClient());
					if( cipher.contains("gcm") ) {
						assertNull(s.getNegotiated().getMacClientToServer(), "AEAD: no MAC");
					} else {
						assertEquals(mac, s.getNegotiated().getMacClientToServer());
					}
					// Data in both directions under these keys: a re-key goes out and comes back
					s.rekey().get(10, TimeUnit.SECONDS);
					assertEquals(2, s.getKexCount());
					s.close();
				}
			}
		}
	}

	/** Many packets of all sizes, explicit and automatic re-keying, the stream stays intact */
	@Test
	public void rekeyUnderLoad() throws Exception {
		try (SshClient c = client(null)) {
			ClientSession s = c.connectAndWait("localhost", port);
			byte[] session = s.getSessionId();
			Random r = new Random(5);
			for (int i = 0; i < 3; i++) {
				s.rekey().get(10, TimeUnit.SECONDS);
			}
			assertEquals(4, s.getKexCount());
			assertArrayEquals(session, s.getSessionId(), "the session id is the first exchange hash");

			// Re-key every 256 KB: not before the login (OpenSSH refuses that)...
			s.setRekeyBytes(256*1024);
			for (int i = 0; i < 100; i++) {
				s.send(SshBuffer.message(SshConstants.SSH_MSG_IGNORE).putString(new byte[10000]));
			}
			s.authenticateAndWait("test", new PasswordAuth("test"));
			assertEquals(4, s.getKexCount(), "no automatic re-key before the login");

			// ...after it, while about 2.5 MB of IGNORE packets flow (packets sent during a key
			// exchange wait and go out together after it, so not one re-key per 256 KB)
			for (int i = 0; i < 1000; i++) {
				byte[] junk = new byte[r.nextInt(i % 50 == 0 ? 30000 : 4000)];
				r.nextBytes(junk);
				s.send(SshBuffer.message(SshConstants.SSH_MSG_IGNORE).putString(junk));
			}
			s.rekey().get(20, TimeUnit.SECONDS);
			assertTrue(s.getKexCount() >= 8, "at least 3 automatic re-keys: "+s.getKexCount());
			assertTrue(s.isOpen());
			s.close();
		}
	}

	@Test
	public void untrustedHostKeyIsRefused() throws Exception {
		try (SshClient c = client(null)) {
			c.setHostKeyVerifier(HostKeyVerifiers.only(ec("secp256r1").getPublic()));
			SshException e = assertThrows(SshException.class, () -> c.connectAndWait("localhost", port));
			assertEquals(SshConstants.SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, e.getReason());
		}
	}

	/** The client asks for the key type it already knows (ECDSA first by default, RSA here) */
	@Test
	public void knownKeyTypeIsPreferred() throws Exception {
		try (SshClient c = client(null)) {
			c.setHostKeyVerifier(HostKeyVerifiers.only(rsa.getPublic()));
			ClientSession s = c.connectAndWait("localhost", port);
			assertEquals("rsa-sha2-512", s.getNegotiated().getHostKey());
			s.close();
		}
	}

	@Test
	public void knownHostsFile() throws Exception {
		File f = new File(dir, "known_hosts");
		try (SshClient c = client(null)) {
			c.setHostKeyVerifier(new KnownHosts(f));
			assertThrows(SshException.class, () -> c.connectAndWait("localhost", port), "unknown host, REJECT");

			c.setHostKeyVerifier(new KnownHosts(f).setPolicy(KnownHosts.Policy.ACCEPT_NEW));
			c.connectAndWait("localhost", port).close();

			// Now known: trusted with the default policy
			c.setHostKeyVerifier(new KnownHosts(f));
			ClientSession s = connect(c);
			assertEquals(KnownHosts.Result.TRUSTED, new KnownHosts(f).check("localhost", port, s.getServerHostKey()));
			s.close();
		}
	}
}
