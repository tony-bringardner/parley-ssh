package us.bringardner.parley.ssh.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.ssh.client.ClientSession;
import us.bringardner.parley.ssh.client.HostKeyVerifiers;
import us.bringardner.parley.ssh.client.PublicKeyAuth;
import us.bringardner.parley.ssh.client.SessionChannel;
import us.bringardner.parley.ssh.client.SshAgent;
import us.bringardner.parley.ssh.client.SshClient;
import us.bringardner.parley.ssh.keys.SshKeyLoader;

/**
 * Agent forwarding (ssh -A) with OpenSSH's ssh-agent: our client to our server, OpenSSH's
 * ssh to our server, and our client to a private OpenSSH sshd. On the server, ssh-add -l
 * lists the client's keys. Unix, Java 16+, OpenSSH installed.
 */
public class AgentForwardingTest {

	private static File dir;
	private static Process agent;
	private static String socket;
	private static File key;

	private SshServer server;
	private SshClient client;

	private static String run(Map<String, String> env, String... cmd) throws Exception {
		ProcessBuilder pb = new ProcessBuilder(cmd).directory(dir).redirectErrorStream(true);
		if( env != null ) {
			pb.environment().putAll(env);
		}
		Process p = pb.start();
		String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		assertTrue(p.waitFor(60, TimeUnit.SECONDS));
		assertEquals(0, p.exitValue(), String.join(" ", cmd)+": "+out);
		return out;
	}

	@BeforeAll
	public static void startAgent() throws Exception {
		assumeTrue(SshAgent.isSupported() && !System.getProperty("os.name").toLowerCase().contains("win"), "Unix, Java 16+");
		dir = Files.createTempDirectory("agf").toFile();
		socket = new File(dir, "a.sock").getPath();
		try {
			agent = new ProcessBuilder("ssh-agent", "-D", "-a", socket).redirectErrorStream(true).start();
		} catch (java.io.IOException e) {
			assumeTrue(false, "no ssh-agent");
		}
		long end = System.currentTimeMillis()+10000;
		while( !new File(socket).exists() && System.currentTimeMillis() < end ) {
			Thread.sleep(50);
		}
		assumeTrue(new File(socket).exists(), "ssh-agent didn't start");
		key = new File(dir, "id_ed25519");
		run(null, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "forwarded-key", "-f", key.getPath());
		run(Collections.singletonMap("SSH_AUTH_SOCK", socket), "ssh-add", "-q", key.getPath());
	}

	@AfterAll
	public static void stopAgent() throws Exception {
		if( agent != null ) {
			agent.destroy();
			agent.waitFor(10, TimeUnit.SECONDS);
		}
		if( dir != null ) {
			for (File f : dir.listFiles()) {
				f.delete();
			}
			dir.delete();
		}
	}

	@AfterEach
	public void stop() throws Exception {
		if( client != null ) {
			client.close();
		}
		if( server != null ) {
			server.stop(5000, false);
		}
	}

	private void startServer(String authorizedOptions) throws Exception {
		File keys = new File(dir, "authorized_keys");
		Files.write(keys.toPath(), ((authorizedOptions.isEmpty() ? "" : authorizedOptions+" ")
				+new String(Files.readAllBytes(new File(key.getPath()+".pub").toPath()), StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8));
		server = new SshServer(0);
		server.setHostKeyProvider(HostKeyProviders.ephemeral());
		server.setPublicKeyAuthenticator(AuthorizedKeysAuthenticator.forFile(keys));
		ProcessCommandFactory os = new ProcessCommandFactory(dir);
		// "agent-keys" lists the forwarded agent's keys from Java; anything else runs in the OS
		server.setCommandFactory((line, env) -> line.equals("agent-keys") ? new AbstractCommand() {
			@Override
			protected int run(CommandEnvironment e, java.io.InputStream in, java.io.OutputStream out, java.io.OutputStream err) throws Exception {
				try (SshAgent a = e.getSession().openForwardedAgent()) {
					for (SshAgent.Identity id : a.getIdentities()) {
						out.write((id.getComment()+"\n").getBytes(StandardCharsets.UTF_8));
					}
				}
				return 0;
			}
		} : os.create(line, env));
		server.setLoginFailureDelay(0);
		server.startAndWait(5000);
	}

	private ClientSession login(boolean forward) throws Exception {
		client = new SshClient();
		client.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
		ClientSession s = client.connectAndWait("localhost", server.getLocalPort());
		s.authenticateAndWait("alice", new PublicKeyAuth(SshKeyLoader.load(key, null)));
		if( forward ) {
			s.setAgentForwarding(socket);
		}
		return s;
	}

	/** @return exit status and output */
	private static String[] exec(ClientSession s, boolean ask, String command) throws Exception {
		SessionChannel ch = s.openSession();
		boolean agreed = ask && ch.requestAgentForwarding();
		ch.exec(command);
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ch.getInputStream().transferTo(out);
		ch.getErrorStream().transferTo(out);
		Integer status = ch.waitForExit(30, TimeUnit.SECONDS);
		return new String[] {""+status, out.toString(StandardCharsets.UTF_8), ""+agreed};
	}

	@Test
	public void ourClientToOurServer() throws Exception {
		startServer("");
		ClientSession s = login(true);
		String[] r = exec(s, true, "ssh-add -l");
		assertEquals("true", r[2], "the server agreed");
		assertEquals("0", r[0], r[1]);
		assertTrue(r[1].contains("forwarded-key"), "the client's key, seen on the server: "+r[1]);
		r = exec(s, true, "agent-keys");
		assertEquals("forwarded-key\n", r[1], "from Java code on the server");
		// Each session channel asks for itself: without asking, no SSH_AUTH_SOCK
		r = exec(s, false, "echo [$SSH_AUTH_SOCK]");
		assertEquals("[]\n", r[1]);
		s.close();
	}

	@Test
	public void refusals() throws Exception {
		startServer("");
		// The client didn't allow it: the server's agent channel is refused
		ClientSession s = login(false);
		String[] r = exec(s, true, "ssh-add -l");
		assertNotEquals("0", r[0], "no agent: "+r[1]);
		s.close();
		client.close();
		// The server doesn't allow it
		server.setAgentForwardingAllowed(false);
		s = login(true);
		r = exec(s, true, "echo [$SSH_AUTH_SOCK]");
		assertEquals("false", r[2]);
		assertEquals("[]\n", r[1]);
		s.close();
	}

	@Test
	public void noAgentForwardingOption() throws Exception {
		startServer("no-agent-forwarding");
		ClientSession s = login(true);
		assertFalse(Boolean.parseBoolean(exec(s, true, "true")[2]), "the key may not forward the agent");
		s.close();
	}

	@Test
	public void opensshClientToOurServer() throws Exception {
		startServer("");
		ProcessBuilder pb = new ProcessBuilder("ssh", "-F", "/dev/null", "-A", "-p", ""+server.getLocalPort(), "-i", key.getPath(),
				"-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
				"-o", "LogLevel=ERROR", "alice@127.0.0.1", "ssh-add -l").redirectErrorStream(true);
		pb.environment().put("SSH_AUTH_SOCK", socket);
		Process p = pb.start();
		p.getOutputStream().close();
		String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		assertTrue(p.waitFor(60, TimeUnit.SECONDS));
		assertEquals(0, p.exitValue(), out);
		assertTrue(out.contains("forwarded-key"), out);
	}

	@Test
	public void ourClientToOpenSshServer() throws Exception {
		File exe = new File("/usr/sbin/sshd");
		assumeTrue(exe.canExecute(), "no sshd");
		File host = new File(dir, "host_key");
		if( !host.exists() ) {
			run(null, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", host.getPath());
		}
		int port;
		try (ServerSocket ss = new ServerSocket(0)) {
			port = ss.getLocalPort();
		}
		File config = new File(dir, "sshd_config");
		Files.write(config.toPath(), String.join("\n", "Port "+port, "ListenAddress 127.0.0.1", "HostKey "+host.getPath(),
				"AuthorizedKeysFile "+key.getPath()+".pub", "PidFile "+new File(dir, "sshd.pid").getPath(), "UsePAM no", "StrictModes no",
				"PasswordAuthentication no", "KbdInteractiveAuthentication no", "AllowAgentForwarding yes", "").getBytes(StandardCharsets.UTF_8));
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
			client = new SshClient();
			client.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
			ClientSession s = client.connectAndWait("127.0.0.1", port);
			s.authenticateAndWait(System.getProperty("user.name"), new PublicKeyAuth(SshKeyLoader.load(key, null)));
			s.setAgentForwarding(socket);
			String[] r = exec(s, true, "ssh-add -l");
			assertEquals("true", r[2]);
			assertEquals("0", r[0], r[1]);
			assertTrue(r[1].contains("forwarded-key"), r[1]);
			s.close();
		} finally {
			sshd.destroy();
			sshd.waitFor(10, TimeUnit.SECONDS);
		}
	}
}
