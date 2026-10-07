package us.bringardner.parley.ssh.server;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

import us.bringardner.parley.ssh.algorithms.SshAlgorithms;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;
import us.bringardner.parley.ssh.keys.SshKeyWriter;

/**
 * The server with other clients: JSch for every key exchange, host key, cipher and MAC,
 * and its logins; Apache MINA SSHD for logins and exec.
 */
public class ThirdPartyClientsTest {

	@TempDir
	static File dir;

	private static SshServer server;
	private static KeyPair alicesKey;
	private static File alicesKeyFile;

	@BeforeAll
	public static void start() throws Exception {
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
		g.initialize(new ECGenParameterSpec("secp256r1"));
		alicesKey = g.generateKeyPair();
		alicesKeyFile = new File(dir, "alice_key");
		SshKeyWriter.write(alicesKey, alicesKeyFile, "alice", true);
		File keys = new File(dir, "authorized_keys");
		Files.write(keys.toPath(), (SshPublicKeys.toOpenSsh(alicesKey.getPublic())+"\n").getBytes(StandardCharsets.UTF_8));

		server = new SshServer(0);
		server.setHostKeyProvider(HostKeyProviders.ephemeral());
		server.setPasswordAuthenticator((user, pw, ctx) -> "alice".equals(user) && "secret".equals(new String(pw)) ? new SshPrincipal(user) : null);
		server.setPublicKeyAuthenticator(AuthorizedKeysAuthenticator.forFile(keys));
		server.setCommandFactory((line, env) -> ServerTest.command(line));
		server.setLoginFailureDelay(10);
		server.startAndWait(5000);
	}

	@AfterAll
	public static void stop() throws Exception {
		server.stop(5000, false);
	}

	// ------------------------------------------------------------------ JSch

	private static Session jsch(String... config) throws Exception {
		JSch j = new JSch();
		Session s = j.getSession("alice", "localhost", server.getLocalPort());
		s.setPassword("secret");
		s.setConfig("StrictHostKeyChecking", "no");
		s.setConfig("PreferredAuthentications", "password");
		for (int i = 0; i < config.length; i += 2) {
			s.setConfig(config[i], config[i+1]);
		}
		s.connect(15000);
		return s;
	}

	private static String jschExec(Session s, String command, byte[] stdin) throws Exception {
		ChannelExec ch = (ChannelExec) s.openChannel("exec");
		ch.setCommand(command);
		InputStream in = ch.getInputStream();
		OutputStream out = ch.getOutputStream();
		ch.connect(10000);
		Thread writer = null;
		if( stdin != null ) {
			writer = new Thread(() -> {
				try {
					out.write(stdin);
					out.close();
				} catch (Exception e) {
					// read side fails
				}
			});
			writer.start();
		} else {
			out.close();
		}
		ByteArrayOutputStream got = new ByteArrayOutputStream();
		in.transferTo(got);
		if( writer != null ) {
			writer.join(10000);
		}
		while( !ch.isClosed() ) {
			Thread.sleep(10);
		}
		int status = ch.getExitStatus();
		ch.disconnect();
		return got.toString("ISO-8859-1")+"|"+status;
	}

	@Test
	public void jschEveryAlgorithm() throws Exception {
		SshAlgorithms d = SshAlgorithms.defaults();
		List<String[]> runs = new ArrayList<String[]>();
		for (String k : d.getKeyExchangeNames()) {
			runs.add(new String[] {"kex", k});
		}
		for (String h : new String[] {"ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"}) {
			runs.add(new String[] {"server_host_key", h});
		}
		for (String c : d.getCipherNames()) {
			if( c.startsWith("chacha20") ) {
				// JSch needs Bouncy Castle for it; OpenSSH and MINA cover it
				continue;
			}
			runs.add(new String[] {"cipher.c2s", c, "cipher.s2c", c});
		}
		for (String m : d.getMacNames()) {
			runs.add(new String[] {"cipher.c2s", "aes128-ctr", "cipher.s2c", "aes128-ctr", "mac.c2s", m, "mac.s2c", m});
		}
		List<String> worked = new ArrayList<String>();
		for (String[] run : runs) {
			Session s = jsch(run);
			assertEquals("hi\n|0", jschExec(s, "echo hi", null), String.join(" ", run));
			s.rekey();
			assertEquals("again\n|0", jschExec(s, "echo again", null), "after a re-key: "+String.join(" ", run));
			s.disconnect();
			worked.add(String.join(" ", run));
		}
		assertEquals(runs.size(), worked.size());
	}

	@Test
	public void jschStreamsAndLogins() throws Exception {
		Session s = jsch();
		byte[] data = new byte[4*1024*1024];
		new Random(9).nextBytes(data);
		String r = jschExec(s, "cat", data);
		assertArrayEquals(data, r.substring(0, r.lastIndexOf('|')).getBytes("ISO-8859-1"));
		assertTrue(jschExec(s, "fail 5", null).endsWith("|5"));
		s.disconnect();

		// Public key login with a key file in OpenSSH's format, written by SshKeyWriter
		JSch j = new JSch();
		j.addIdentity(alicesKeyFile.getPath());
		Session k = j.getSession("alice", "localhost", server.getLocalPort());
		k.setConfig("StrictHostKeyChecking", "no");
		k.setConfig("PreferredAuthentications", "publickey");
		k.connect(15000);
		assertEquals("alice|0", jschExec(k, "whoami", null));
		k.disconnect();

		// Keyboard-interactive answered from the password
		Session ki = new JSch().getSession("alice", "localhost", server.getLocalPort());
		ki.setConfig("StrictHostKeyChecking", "no");
		ki.setConfig("PreferredAuthentications", "keyboard-interactive");
		ki.setUserInfo(new KiUser());
		ki.connect(15000);
		assertEquals("alice|0", jschExec(ki, "whoami", null));
		ki.disconnect();

		Session bad = new JSch().getSession("alice", "localhost", server.getLocalPort());
		bad.setPassword("wrong");
		bad.setConfig("StrictHostKeyChecking", "no");
		bad.setConfig("PreferredAuthentications", "password");
		assertThrows(com.jcraft.jsch.JSchException.class, () -> bad.connect(15000));
	}

	/** JSch's keyboard-interactive callbacks */
	private static final class KiUser implements com.jcraft.jsch.UserInfo, com.jcraft.jsch.UIKeyboardInteractive {
		@Override
		public String[] promptKeyboardInteractive(String destination, String name, String instruction, String[] prompt, boolean[] echo) {
			return new String[] {"secret"};
		}

		@Override
		public String getPassphrase() {
			return null;
		}

		@Override
		public String getPassword() {
			return null;
		}

		@Override
		public boolean promptPassword(String message) {
			return false;
		}

		@Override
		public boolean promptPassphrase(String message) {
			return false;
		}

		@Override
		public boolean promptYesNo(String message) {
			return true;
		}

		@Override
		public void showMessage(String message) {
		}
	}

	// ------------------------------------------------------------------ MINA

	@Test
	public void minaLoginsAndExec() throws Exception {
		org.apache.sshd.client.SshClient c = org.apache.sshd.client.SshClient.setUpDefaultClient();
		c.setServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE);
		c.start();
		try {
			try (ClientSession s = c.connect("alice", "localhost", server.getLocalPort()).verify(Duration.ofSeconds(15)).getSession()) {
				s.addPasswordIdentity("secret");
				s.auth().verify(Duration.ofSeconds(15));
				assertEquals("hi\n", s.executeRemoteCommand("echo hi"));
				byte[] data = new byte[3*1024*1024];
				new Random(4).nextBytes(data);
				try (org.apache.sshd.client.channel.ChannelExec ch = s.createExecChannel("cat")) {
					ByteArrayOutputStream out = new ByteArrayOutputStream();
					ch.setOut(out);
					ch.setIn(new java.io.ByteArrayInputStream(data));
					ch.open().verify(Duration.ofSeconds(10));
					ch.waitFor(Collections.singleton(ClientChannelEvent.CLOSED), Duration.ofSeconds(30));
					assertArrayEquals(data, out.toByteArray());
					assertEquals(0, ch.getExitStatus());
				}
			}
			try (ClientSession s = c.connect("alice", "localhost", server.getLocalPort()).verify(Duration.ofSeconds(15)).getSession()) {
				s.addPublicKeyIdentity(alicesKey);
				s.auth().verify(Duration.ofSeconds(15));
				assertEquals("alice", s.executeRemoteCommand("whoami"));
			}
		} finally {
			c.stop();
		}
	}
}
