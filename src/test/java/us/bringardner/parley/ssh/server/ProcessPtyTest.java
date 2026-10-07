package us.bringardner.parley.ssh.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.ssh.client.ClientSession;
import us.bringardner.parley.ssh.client.ExecResult;
import us.bringardner.parley.ssh.client.HostKeyVerifiers;
import us.bringardner.parley.ssh.client.PasswordAuth;
import us.bringardner.parley.ssh.client.SessionChannel;
import us.bringardner.parley.ssh.client.SshClient;

/**
 * Operating system commands and the login shell on real pseudo terminals (pty4j): what
 * runs sees a terminal of the client's size, which follows the client's window. Unix only.
 */
public class ProcessPtyTest {

	@TempDir
	static File dir;

	private static SshServer server;
	private static SshClient client;

	@BeforeAll
	public static void start() throws Exception {
		assumeTrue(!System.getProperty("os.name").toLowerCase().contains("win"), "Unix commands");
		assumeTrue(ProcessCommandFactory.isPtySupported(), "pty4j");
		server = new SshServer(0);
		server.setHostKeyProvider(HostKeyProviders.ephemeral());
		server.setPasswordAuthenticator((user, pw, ctx) -> "secret".equals(new String(pw)) ? new SshPrincipal(user) : null);
		server.setCommandFactory(new ProcessCommandFactory(dir));
		server.setShellFactory(new ProcessShellFactory(dir));
		server.setLoginFailureDelay(0);
		server.startAndWait(5000);
		client = new SshClient();
		client.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
	}

	@AfterAll
	public static void stop() throws Exception {
		if( client != null ) {
			client.close();
		}
		if( server != null ) {
			server.stop(5000, false);
		}
	}

	private static ClientSession login() throws Exception {
		ClientSession s = client.connectAndWait("localhost", server.getLocalPort());
		s.authenticateAndWait("alice", new PasswordAuth("secret"));
		return s;
	}

	/** Read until the text shows up */
	static String readUntil(InputStream in, String want, long timeoutMs) throws Exception {
		ByteArrayOutputStream got = new ByteArrayOutputStream();
		long end = System.currentTimeMillis()+timeoutMs;
		while( System.currentTimeMillis() < end ) {
			if( in.available() > 0 ) {
				got.write(in.read());
				if( got.toString(StandardCharsets.UTF_8).contains(want) ) {
					return got.toString(StandardCharsets.UTF_8);
				}
			} else {
				Thread.sleep(10);
			}
		}
		throw new AssertionError("'"+want+"' not seen in: "+got.toString(StandardCharsets.UTF_8));
	}

	@Test
	public void execOnAPty() throws Exception {
		ClientSession s = login();
		SessionChannel ch = s.openSession();
		ch.requestPty("xterm-256color", 100, 30);
		ch.exec("stty size; tty; echo TERM=$TERM; exit 7");
		String out = readUntil(ch.getInputStream(), "TERM=xterm-256color", 15000);
		assertTrue(out.contains("30 100"), "the client's size: "+out);
		assertTrue(out.contains("/dev/tty") || out.contains("/dev/pts"), "a terminal: "+out);
		assertTrue(out.contains("\r\n"), "the terminal turns \\n into \\r\\n: "+out);
		assertEquals(7, ch.waitForExit(15, TimeUnit.SECONDS), "the exit status");
		s.close();
	}

	@Test
	public void execWithoutAPty() throws Exception {
		ClientSession s = login();
		ExecResult r = s.exec("tty; echo err >&2", null, 15000);
		assertEquals("not a tty\n", r.getStdoutText());
		assertEquals("err\n", new String(r.getStderr(), StandardCharsets.UTF_8), "stderr separate without a pty");
		s.close();
	}

	@Test
	public void interactiveShellFollowsTheWindow() throws Exception {
		ClientSession s = login();
		SessionChannel ch = s.openSession();
		ch.requestPty("xterm", 80, 24);
		ch.shell();
		OutputStream keys = ch.getOutputStream();
		InputStream screen = ch.getInputStream();
		keys.write("stty size; echo do''ne1\r".getBytes(StandardCharsets.UTF_8));
		keys.flush();
		assertTrue(readUntil(screen, "done1", 15000).contains("24 80"));
		ch.windowChange(132, 50, 0, 0);
		Thread.sleep(200);
		keys.write("stty size; echo do''ne2\r".getBytes(StandardCharsets.UTF_8));
		keys.flush();
		assertTrue(readUntil(screen, "done2", 15000).contains("50 132"), "resized");
		keys.write("exit 3\r".getBytes(StandardCharsets.UTF_8));
		keys.flush();
		assertEquals(3, ch.waitForExit(15, TimeUnit.SECONDS));
		s.close();
	}

	/** OpenSSH's ssh -tt gets the terminal too */
	@Test
	public void opensshClientGetsATerminal() throws Exception {
		File key = new File(dir, "id_ecdsa");
		try {
			assumeTrue(new ProcessBuilder("ssh-keygen", "-q", "-t", "ecdsa", "-N", "", "-f", key.getPath()).start().waitFor() == 0);
		} catch (java.io.IOException e) {
			assumeTrue(false, "no ssh");
		}
		File authorized = new File(dir, "authorized_keys");
		Files.copy(new File(key.getPath()+".pub").toPath(), authorized.toPath());
		IPublicKeyAuthenticator old = server.getPublicKeyAuthenticator();
		server.setPublicKeyAuthenticator(AuthorizedKeysAuthenticator.forFile(authorized));
		try {
			Process p = new ProcessBuilder("ssh", "-F", "/dev/null", "-tt", "-p", ""+server.getLocalPort(), "-i", key.getPath(),
					"-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
					"-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "alice@127.0.0.1", "tty; echo TERM=$TERM")
					.redirectErrorStream(true).start();
			p.getOutputStream().close();
			String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
			assertTrue(p.waitFor(60, TimeUnit.SECONDS));
			assertEquals(0, p.exitValue(), out);
			assertTrue(out.contains("/dev/tty") || out.contains("/dev/pts"), out);
			assertTrue(out.contains("TERM="), out);
			assertTrue(!out.contains("not a tty"), out);
		} finally {
			server.setPublicKeyAuthenticator(old);
		}
	}
}
