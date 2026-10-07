package us.bringardner.parley.ssh.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.ssh.SshConstants;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.SshAlgorithms;

/**
 * The client against a real OpenSSH server: the local sshd (port 22, or the system property
 * parley.ssh.it.host / parley.ssh.it.port). Skipped when nothing listens there. Only the transport
 * is used (key exchange, re-key, service request), never a login.
 * <p>
 * Runs in 'mvn verify' (failsafe), not 'mvn test'.
 */
public class OpenSshIT {

	private static final String HOST = System.getProperty("parley.ssh.it.host", "localhost");
	private static final int PORT = Integer.getInteger("parley.ssh.it.port", 22);

	@BeforeAll
	public static void needServer() {
		boolean up;
		try (Socket s = new Socket()) {
			s.connect(new InetSocketAddress(HOST, PORT), 1000);
			up = true;
		} catch (Exception e) {
			up = false;
		}
		Assumptions.assumeTrue(up, "No SSH server on "+HOST+":"+PORT);
	}

	private static ClientSession connect(SshAlgorithms algorithms) throws Exception {
		try (SshClient c = new SshClient()) {
			c.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
			if( algorithms != null ) {
				c.setAlgorithms(algorithms);
			}
			ClientSession s = c.connectAndWait(HOST, PORT);
			s.requestService(SshConstants.SERVICE_USERAUTH).get(10, TimeUnit.SECONDS);
			// OpenSSH 10 refuses to re-key before a login (SSH_MSG_UNIMPLEMENTED); older versions do it
			try {
				s.rekey().get(10, TimeUnit.SECONDS);
			} catch (java.util.concurrent.ExecutionException e) {
				assertTrue(e.getCause() instanceof SshException && e.getCause().getMessage().contains("refused"), "rekey: "+e.getCause());
				assertTrue(s.isOpen(), "the session goes on with its keys");
				s.send(us.bringardner.parley.ssh.SshBuffer.message(SshConstants.SSH_MSG_IGNORE).putString("still here"));
			}
			s.close();
			return s;
		}
	}

	@Test
	public void defaults() throws Exception {
		ClientSession s = connect(null);
		assertTrue(s.getPeerVersion().contains("OpenSSH"), s.getPeerVersion());
		assertTrue(s.isStrictKex(), "OpenSSH 9.6+ does strict key exchange");
		assertTrue(s.getKexCount() >= 1);
	}

	/** Each of our algorithms that the server also has; the server decides which those are */
	@Test
	public void eachAlgorithm() throws Exception {
		SshAlgorithms d = SshAlgorithms.defaults();
		List<String> worked = new ArrayList<String>();
		List<String> notOffered = new ArrayList<String>();
		for (String kex : d.getKeyExchangeNames()) {
			run(SshAlgorithms.defaults().setKeyExchanges(kex), "kex "+kex, worked, notOffered);
		}
		for (String hk : d.getHostKeyAlgorithmNames()) {
			run(SshAlgorithms.defaults().setHostKeyAlgorithms(hk), "hostkey "+hk, worked, notOffered);
		}
		for (String cipher : d.getCipherNames()) {
			run(SshAlgorithms.defaults().setCiphers(cipher), "cipher "+cipher, worked, notOffered);
		}
		for (String mac : d.getMacNames()) {
			// a CTR cipher, so the MAC is used
			run(SshAlgorithms.defaults().setCiphers("aes128-ctr").setMacs(mac), "mac "+mac, worked, notOffered);
		}
		System.out.println("OpenSSH interop: worked "+worked+"; not offered by the server "+notOffered);
		assertTrue(worked.size() >= 10, "worked: "+worked);
	}

	/**
	 * Wrong credentials for a user that doesn't exist: OpenSSH answers each request (a 
	 * malformed one would get a disconnect) and the login fails cleanly.
	 */
	@Test
	public void failedLogin() throws Exception {
		try (SshClient c = new SshClient()) {
			c.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
			ClientSession s = c.connectAndWait(HOST, PORT);
			java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("EC");
			g.initialize(256);
			SshException e = org.junit.jupiter.api.Assertions.assertThrows(SshException.class, () -> s.authenticateAndWait("parley-no-such-user",
					new PublicKeyAuth(g.generateKeyPair()), KeyboardInteractiveAuth.password("not-a-password".toCharArray())));
			assertTrue(e.getReason() == SshConstants.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE
					|| e.getMessage().contains("Too many"), e.toString());
			System.out.println("OpenSSH login failure: "+e.getMessage());
			s.close();
		}
	}

	/**
	 * A real login, only when asked for: -Dparley.ssh.it.user=name -Dparley.ssh.it.key=~/.ssh/id_ecdsa 
	 * (an unencrypted or PEM / PKCS8 key whose public key is in the user's authorized_keys).
	 */
	@Test
	public void realLogin() throws Exception {
		String user = System.getProperty("parley.ssh.it.user");
		String key = System.getProperty("parley.ssh.it.key");
		Assumptions.assumeTrue(user != null && key != null, "set parley.ssh.it.user and parley.ssh.it.key for a real login");
		String pass = System.getProperty("parley.ssh.it.passphrase");
		java.security.KeyPair kp = us.bringardner.parley.ssh.keys.SshKeyLoader.load(new java.io.File(key), pass == null ? null : pass.toCharArray());
		try (SshClient c = new SshClient()) {
			ClientSession s = c.connectAndWait(HOST, PORT);
			s.authPublicKey(user, kp);
			assertTrue(s.isAuthenticated());
			s.rekey().get(10, TimeUnit.SECONDS);
			ExecResult r = s.exec("echo hello; echo oops >&2; exit 7", null, 20000);
			assertEquals("hello\n", r.getStdoutText());
			assertEquals("oops\n", r.getStderrText());
			assertEquals(7, r.getExitStatus());
			byte[] data = new byte[3*1024*1024];
			new java.util.Random(3).nextBytes(data);
			org.junit.jupiter.api.Assertions.assertArrayEquals(data, s.exec("cat", data, 60000).getStdout());
			s.close();
		}
	}

	private static void run(SshAlgorithms a, String what, List<String> worked, List<String> notOffered) throws Exception {
		try {
			connect(a);
			worked.add(what);
		} catch (SshException e) {
			if( e.getReason() == SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED && e.getMessage().startsWith("No common") ) {
				notOffered.add(what);
			} else {
				throw new AssertionError(what+" failed: "+e, e);
			}
		}
	}
}
