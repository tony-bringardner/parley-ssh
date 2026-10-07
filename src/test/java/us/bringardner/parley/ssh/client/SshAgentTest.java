package us.bringardner.parley.ssh.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;
import us.bringardner.parley.ssh.server.AuthorizedKeysAuthenticator;
import us.bringardner.parley.ssh.server.HostKeyProviders;
import us.bringardner.parley.ssh.server.IPublicKeyAuthenticator;
import us.bringardner.parley.ssh.server.SshServer;
import us.bringardner.parley.ssh.server.UserCertificateAuthenticator;

/**
 * Logging in with keys held by OpenSSH's ssh-agent (started for the test on its own
 * socket, loaded with ssh-add). Skipped without OpenSSH or before Java 16.
 */
public class SshAgentTest {

	private static File dir;
	private static Process agent;
	private static String socket;

	private SshServer server;
	private SshClient client;

	private static void run(Map<String, String> env, String... cmd) throws Exception {
		ProcessBuilder pb = new ProcessBuilder(cmd).directory(dir).redirectErrorStream(true);
		if( env != null ) {
			pb.environment().putAll(env);
		}
		Process p = pb.start();
		String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		assertTrue(p.waitFor(60, TimeUnit.SECONDS));
		assertEquals(0, p.exitValue(), String.join(" ", cmd)+": "+out);
	}

	@BeforeAll
	public static void startAgent() throws Exception {
		assumeTrue(SshAgent.isSupported(), "Unix domain sockets need Java 16");
		// Short: socket paths are limited to about 100 characters
		dir = Files.createTempDirectory("agt").toFile();
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
		run(null, "ssh-keygen", "-q", "-t", "ecdsa", "-N", "", "-f", "ca");
		run(null, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "id_ed25519");
		run(null, "ssh-keygen", "-q", "-t", "rsa", "-N", "", "-f", "id_rsa");
		run(null, "ssh-keygen", "-q", "-t", "ecdsa", "-N", "", "-f", "id_cert");
		run(null, "ssh-keygen", "-q", "-s", "ca", "-I", "agent-cert", "-n", "alice", "id_cert.pub");
		Map<String, String> env = Collections.singletonMap("SSH_AUTH_SOCK", socket);
		// ssh-add adds id_cert-cert.pub too
		run(env, "ssh-add", "-q", "id_ed25519", "id_rsa", "id_cert");
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

	private ClientSession connect(IPublicKeyAuthenticator auth) throws Exception {
		server = new SshServer(0);
		server.setHostKeyProvider(HostKeyProviders.ephemeral());
		server.setPublicKeyAuthenticator(auth);
		server.setCommandFactory((line, env) -> us.bringardner.parley.ssh.server.ServerTestAccess.command(line));
		server.setLoginFailureDelay(0);
		server.startAndWait(5000);
		client = new SshClient();
		client.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
		return client.connectAndWait("localhost", server.getLocalPort());
	}

	@Test
	public void listsTheAgentsKeys() throws Exception {
		try (SshAgent a = SshAgent.connect(socket)) {
			List<String> types = new ArrayList<String>();
			for (SshAgent.Identity id : a.getIdentities()) {
				types.add(id.getType());
			}
			assertTrue(types.contains("ssh-ed25519"), types.toString());
			assertTrue(types.contains("ssh-rsa"), types.toString());
			assertTrue(types.contains("ecdsa-sha2-nistp256"), types.toString());
			assertTrue(types.contains("ecdsa-sha2-nistp256-cert-v01@openssh.com"), types.toString());
			// A key the agent doesn't have
			byte[] blob = SshPublicKeys.encode(CertificateTestAccess.ec().getPublic());
			assertThrows(SshException.class, () -> a.sign(blob, new byte[] {1, 2, 3}, 0));
		}
	}

	/** Only the RSA key is authorized: the agent signs with rsa-sha2-512 */
	@Test
	public void logsInWithAnAgentKey() throws Exception {
		File keys = new File(dir, "authorized_keys");
		Files.copy(new File(dir, "id_rsa.pub").toPath(), keys.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
		ClientSession s = connect(AuthorizedKeysAuthenticator.forFile(keys));
		try (SshAgent a = SshAgent.connect(socket)) {
			s.authenticateAndWait("alice", PublicKeyAuth.fromAgent(a));
			assertEquals("alice", s.exec("whoami", null, 10000).getStdoutText());
		}
	}

	@Test
	public void logsInWithACertificateInTheAgent() throws Exception {
		ClientSession s = connect(UserCertificateAuthenticator.fromFile(new File(dir, "ca.pub")));
		try (SshAgent a = SshAgent.connect(socket)) {
			s.authenticateAndWait("alice", PublicKeyAuth.fromAgent(a));
			assertEquals("alice", s.exec("whoami", null, 10000).getStdoutText());
		}
	}

	@Test
	public void noAgentKeyFits() throws Exception {
		File keys = new File(dir, "authorized_keys_none");
		Files.write(keys.toPath(), (SshPublicKeys.toOpenSsh(CertificateTestAccess.ec().getPublic())+"\n").getBytes(StandardCharsets.UTF_8));
		ClientSession s = connect(AuthorizedKeysAuthenticator.forFile(keys));
		try (SshAgent a = SshAgent.connect(socket)) {
			assertThrows(SshException.class, () -> s.authenticateAndWait("alice", PublicKeyAuth.fromAgent(a)));
		}
	}
}
