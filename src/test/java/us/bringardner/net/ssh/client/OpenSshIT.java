package us.bringardner.net.ssh.client;

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

import us.bringardner.net.ssh.SshConstants;
import us.bringardner.net.ssh.SshException;
import us.bringardner.net.ssh.algorithms.SshAlgorithms;

/**
 * The client against a real OpenSSH server: the local sshd (port 22, or the system property
 * bjl.ssh.it.host / bjl.ssh.it.port). Skipped when nothing listens there. Only the transport
 * is used (key exchange, re-key, service request), never a login.
 * <p>
 * Runs in 'mvn verify' (failsafe), not 'mvn test'.
 */
public class OpenSshIT {

	private static final String HOST = System.getProperty("bjl.ssh.it.host", "localhost");
	private static final int PORT = Integer.getInteger("bjl.ssh.it.port", 22);

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
				s.send(us.bringardner.net.ssh.SshBuffer.message(SshConstants.SSH_MSG_IGNORE).putString("still here"));
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
