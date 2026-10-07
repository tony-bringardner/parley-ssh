package us.bringardner.parley.ssh.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.ssh.algorithms.SshCertificate;
import us.bringardner.parley.ssh.client.ClientSession;
import us.bringardner.parley.ssh.client.KnownHosts;
import us.bringardner.parley.ssh.client.PublicKeyAuth;
import us.bringardner.parley.ssh.client.SshClient;
import us.bringardner.parley.ssh.keys.SshKeyLoader;

/**
 * OpenSSH certificates made by ssh-keygen, both ways: OpenSSH's ssh logs in to our server
 * with a user certificate and trusts its host certificate through @cert-authority; our client
 * does the same with a private OpenSSH sshd (run as this user on a free port). Skipped
 * without OpenSSH.
 */
public class OpenSshCertificateIT {

	@TempDir
	static File dir;

	private static SshServer server;
	private static Process sshd;
	private static int sshdPort;

	private static String run(String... cmd) throws Exception {
		Process p = new ProcessBuilder(cmd).directory(dir).redirectErrorStream(true).start();
		String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		assertTrue(p.waitFor(60, TimeUnit.SECONDS));
		assertEquals(0, p.exitValue(), String.join(" ", cmd)+": "+out);
		return out;
	}

	private static File f(String name) {
		return new File(dir, name);
	}

	@BeforeAll
	public static void start() throws Exception {
		try {
			assumeTrue(new ProcessBuilder("ssh-keygen", "-q", "-t", "ecdsa", "-N", "", "-f", f("ca").getPath()).start().waitFor() == 0);
		} catch (java.io.IOException e) {
			assumeTrue(false, "no ssh-keygen");
		}
		run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "host");
		run("ssh-keygen", "-q", "-s", "ca", "-h", "-I", "test-host", "-n", "127.0.0.1,localhost", "host.pub");
		for (String type : new String[] {"ed25519", "rsa"}) {
			run("ssh-keygen", "-q", "-t", type, "-N", "", "-f", "user_"+type);
			run("ssh-keygen", "-q", "-s", "ca", "-I", "alice-"+type, "-n", "alice,"+System.getProperty("user.name"), "-V", "-5m:+1h", "user_"+type+".pub");
		}
		run("ssh-keygen", "-q", "-t", "ecdsa", "-N", "", "-f", "user_forced");
		run("ssh-keygen", "-q", "-s", "ca", "-I", "forced", "-n", "alice", "-O", "force-command=echo forced", "user_forced.pub");

		// Our server: the host key and its certificate from files, users through the CA
		server = new SshServer(0);
		server.setHostKeyProvider(HostKeyProviders.fromFiles(f("host")));
		server.setPublicKeyAuthenticator(UserCertificateAuthenticator.fromFile(f("ca.pub")));
		server.setCommandFactory((line, env) -> ServerTest.command(line));
		server.setLoginFailureDelay(0);
		server.startAndWait(5000);
		assertEquals(1, server.getHostCertificates().size(), "host-cert.pub was found next to the key");
	}

	@AfterAll
	public static void stop() throws Exception {
		if( server != null ) {
			server.stop(5000, false);
		}
		if( sshd != null ) {
			sshd.destroy();
			sshd.waitFor(10, TimeUnit.SECONDS);
		}
	}

	private static String known(int port) throws Exception {
		File known = f("known_hosts_"+port);
		Files.write(known.toPath(), ("@cert-authority [127.0.0.1]:"+port+" "+new String(Files.readAllBytes(f("ca.pub").toPath()), StandardCharsets.UTF_8))
				.getBytes(StandardCharsets.UTF_8));
		return known.getPath();
	}

	/** @return exit status and output of OpenSSH's ssh to our server */
	private static String[] ssh(String key, String command) throws Exception {
		List<String> cmd = new ArrayList<String>(Arrays.asList("ssh", "-F", "/dev/null", "-p", ""+server.getLocalPort(),
				"-i", f(key).getPath(), "-o", "CertificateFile="+f(key+"-cert.pub").getPath(), "-o", "IdentitiesOnly=yes",
				"-o", "IdentityAgent=none", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
				"-o", "UserKnownHostsFile="+known(server.getLocalPort()), "-o", "LogLevel=ERROR", "alice@127.0.0.1", command));
		Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
		p.getOutputStream().close();
		String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		assertTrue(p.waitFor(60, TimeUnit.SECONDS));
		return new String[] {""+p.exitValue(), out};
	}

	@Test
	public void opensshClientWithCertificates() throws Exception {
		for (String key : new String[] {"user_ed25519", "user_rsa"}) {
			String[] r = ssh(key, "whoami");
			assertEquals("0", r[0], key+": "+r[1]);
			assertEquals("alice", r[1], key);
		}
		String[] r = ssh("user_forced", "whoami");
		assertEquals("0", r[0], r[1]);
		assertEquals("forced\n", r[1], "the certificate's force-command ran");

		// A key without its certificate isn't accepted: the server knows no plain keys
		Process p = new ProcessBuilder("ssh", "-F", "/dev/null", "-p", ""+server.getLocalPort(), "-i", f("user_ed25519").getPath(),
				"-o", "CertificateFile=/dev/null", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes",
				"-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile="+known(server.getLocalPort()), "-o", "LogLevel=ERROR",
				"alice@127.0.0.1", "whoami").redirectErrorStream(true).start();
		p.getOutputStream().close();
		p.getInputStream().readAllBytes();
		assertTrue(p.waitFor(60, TimeUnit.SECONDS));
		assertNotEquals(0, p.exitValue());
	}

	/** A cert-authority line in authorized_keys, with OpenSSH's ssh */
	@Test
	public void certAuthorityLineWithOpensshClient() throws Exception {
		File keys = f("authorized_keys_ca");
		Files.write(keys.toPath(), ("cert-authority,principals=\"alice\",command=\"echo via-line\" "
				+new String(Files.readAllBytes(f("ca.pub").toPath()), StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8));
		IPublicKeyAuthenticator old = server.getPublicKeyAuthenticator();
		server.setPublicKeyAuthenticator(AuthorizedKeysAuthenticator.forFile(keys));
		try {
			String[] r = ssh("user_ed25519", "whoami");
			assertEquals("0", r[0], r[1]);
			assertEquals("via-line\n", r[1], "the line's command ran");
		} finally {
			server.setPublicKeyAuthenticator(old);
		}
	}

	/** A private sshd with the host certificate, trusting the CA for users */
	private static void startSshd() throws Exception {
		if( sshd != null ) {
			return;
		}
		File exe = new File("/usr/sbin/sshd");
		assumeTrue(exe.canExecute(), "no sshd");
		try (ServerSocket ss = new ServerSocket(0)) {
			sshdPort = ss.getLocalPort();
		}
		File config = f("sshd_config");
		Files.write(config.toPath(), String.join("\n",
				"Port "+sshdPort, "ListenAddress 127.0.0.1",
				"HostKey "+f("host").getPath(), "HostCertificate "+f("host-cert.pub").getPath(),
				"TrustedUserCAKeys "+f("ca.pub").getPath(), "AuthorizedKeysFile none",
				"PidFile "+f("sshd.pid").getPath(), "UsePAM no", "StrictModes no",
				"PasswordAuthentication no", "KbdInteractiveAuthentication no", "").getBytes(StandardCharsets.UTF_8));
		sshd = new ProcessBuilder(exe.getPath(), "-D", "-f", config.getPath(), "-E", f("sshd.log").getPath()).redirectErrorStream(true).start();
		long end = System.currentTimeMillis()+10000;
		while( System.currentTimeMillis() < end ) {
			try (java.net.Socket s = new java.net.Socket("127.0.0.1", sshdPort)) {
				return;
			} catch (java.io.IOException e) {
				if( !sshd.isAlive() ) {
					break;
				}
				Thread.sleep(100);
			}
		}
		assumeTrue(false, "sshd didn't start as this user");
	}

	@Test
	public void ourClientWithOpenSshServer() throws Exception {
		startSshd();
		for (String key : new String[] {"user_ed25519", "user_rsa"}) {
			try (SshClient client = new SshClient()) {
				client.setHostKeyVerifier(new KnownHosts(Collections.singletonList(
						"@cert-authority [127.0.0.1]:"+sshdPort+" "+new String(Files.readAllBytes(f("ca.pub").toPath()), StandardCharsets.UTF_8).trim())));
				ClientSession s = client.connectAndWait("127.0.0.1", sshdPort);
				assertNotNull(s.getHostCertificate(), "sshd's host certificate was used");
				assertEquals("test-host", s.getHostCertificate().getKeyId());
				s.authenticateAndWait(System.getProperty("user.name"),
						new PublicKeyAuth().addCertificate(SshKeyLoader.load(f(key), null), SshCertificate.load(f(key+"-cert.pub"))));
				assertEquals("it-works\n", s.exec("echo it-works", null, 30000).getStdoutText(), key);
				s.close();
			}
		}
	}
}
