package us.bringardner.parley.ssh.server;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.net.server.PropertyAuthenticator;
import us.bringardner.parley.ssh.SshConstants;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.SshAlgorithms;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;
import us.bringardner.parley.ssh.client.ClientSession;
import us.bringardner.parley.ssh.client.ExecResult;
import us.bringardner.parley.ssh.client.HostKeyVerifiers;
import us.bringardner.parley.ssh.client.KeyboardInteractiveAuth;
import us.bringardner.parley.ssh.client.PasswordAuth;
import us.bringardner.parley.ssh.client.PublicKeyAuth;
import us.bringardner.parley.ssh.client.SessionChannel;
import us.bringardner.parley.ssh.client.SshClient;

/**
 * The server against the library's own client: every algorithm (so the server side of each
 * key exchange and host key), each login method and the login limits, exec / shell / env /
 * pty with plug-in commands, flow control, and permissions from the access control list.
 */
public class ServerTest {

	@TempDir
	File dir;

	private static KeyPair alicesKey;
	private static KeyPair strangersKey;
	private SshServer server;
	private SshClient client;

	private static KeyPair ec(String curve) throws Exception {
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
		g.initialize(new ECGenParameterSpec(curve));
		return g.generateKeyPair();
	}

	@BeforeAll
	public static void keys() throws Exception {
		alicesKey = ec("secp384r1");
		strangersKey = ec("secp256r1");
	}

	/** Test commands: echo, fail N, cat, big N, env NAME, whoami, sleep */
	static ICommand command(String line) {
		String[] w = line.split(" ", 2);
		String arg = w.length > 1 ? w[1] : "";
		return new AbstractCommand() {
			@Override
			protected int run(CommandEnvironment env, InputStream in, OutputStream out, OutputStream err) throws Exception {
				switch (w[0]) {
				case "echo":
					out.write((arg+"\n").getBytes(StandardCharsets.UTF_8));
					return 0;
				case "fail":
					err.write("failing\n".getBytes(StandardCharsets.UTF_8));
					return Integer.parseInt(arg);
				case "cat":
					in.transferTo(out);
					return 0;
				case "big": {
					Random r = new Random(42);
					byte[] b = new byte[16*1024];
					for (long left = Long.parseLong(arg); left > 0; left -= b.length) {
						r.nextBytes(b);
						out.write(b, 0, (int) Math.min(b.length, left));
					}
					return 0;
				}
				case "env":
					out.write(String.valueOf(env.getEnv().get(arg)).getBytes(StandardCharsets.UTF_8));
					return 0;
				case "whoami":
					out.write(env.getUser().getBytes(StandardCharsets.UTF_8));
					return 0;
				case "sleep":
					Thread.sleep(60000);
					return 0;
				default:
					return 127;
				}
			}
		};
	}

	/** A shell that answers each line with "TERM COLSxROWS> line" until "exit" */
	static ICommand shell() {
		return new AbstractCommand() {
			@Override
			protected int run(CommandEnvironment env, InputStream in, OutputStream out, OutputStream err) throws Exception {
				BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
				PrintStream p = new PrintStream(out, true, "UTF-8");
				String line;
				while( (line = r.readLine()) != null ) {
					if( line.equals("exit") ) {
						return 0;
					}
					p.print(env.getTerm()+" "+env.getColumns()+"x"+env.getRows()+"> "+line+"\n");
				}
				return 1;
			}
		};
	}

	private SshServer start() throws Exception {
		SshServer s = new SshServer(0);
		s.setName("ssh-test");
		s.setHostKeyProvider(HostKeyProviders.ephemeral());
		s.setPasswordAuthenticator((user, pw, ctx) -> "alice".equals(user) && "secret".equals(new String(pw)) ? new SshPrincipal(user) : null);
		File keys = new File(dir, "authorized_keys");
		Files.write(keys.toPath(), (SshPublicKeys.toOpenSsh(alicesKey.getPublic())+" alice@test\n"
				+"no-such-option,command=\"/bin/false\" "+SshPublicKeys.toOpenSsh(strangersKey.getPublic())+"\n").getBytes(StandardCharsets.UTF_8));
		s.setPublicKeyAuthenticator(new AuthorizedKeysAuthenticator(user -> "alice".equals(user) ? keys : null));
		s.setCommandFactory((line, env) -> command(line));
		s.setShellFactory(env -> shell());
		s.setLoginFailureDelay(50);
		server = s;
		return s;
	}

	private ClientSession connect(SshAlgorithms algorithms) throws Exception {
		client = new SshClient();
		// Pinned: the server's own host keys
		client.setHostKeyVerifier(HostKeyVerifiers.only(server.getHostKeys().stream().map(KeyPair::getPublic).toArray(java.security.PublicKey[]::new)));
		if( algorithms != null ) {
			client.setAlgorithms(algorithms);
		}
		return client.connectAndWait("localhost", server.getLocalPort());
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

	/** Each algorithm with the server on the other side */
	@Test
	public void everyAlgorithm() throws Exception {
		start().startAndWait(5000);
		SshAlgorithms d = SshAlgorithms.defaults();
		List<SshAlgorithms> runs = new ArrayList<SshAlgorithms>();
		for (String k : d.getKeyExchangeNames()) {
			runs.add(SshAlgorithms.defaults().setKeyExchanges(k));
		}
		for (String h : new String[] {"ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"}) {
			runs.add(SshAlgorithms.defaults().setHostKeyAlgorithms(h));
		}
		for (String c : d.getCipherNames()) {
			for (String m : d.getMacNames()) {
				runs.add(SshAlgorithms.defaults().setCiphers(c).setMacs(m));
			}
		}
		for (SshAlgorithms a : runs) {
			ClientSession s = connect(a);
			assertTrue(s.isStrictKex(), "both sides do strict key exchange");
			s.authenticateAndWait("alice", new PasswordAuth("secret"));
			assertEquals("hi\n", s.exec("echo hi", null, 10000).getStdoutText(), a.toString());
			s.rekey().get(10, TimeUnit.SECONDS);
			s.close();
			client.close();
		}
	}

	@Test
	public void loginMethods() throws Exception {
		start().startAndWait(5000);
		ClientSession s = connect(null);
		// The stranger's key is in the file but with an option the server doesn't know: not used
		s.authenticateAndWait("alice", new PublicKeyAuth(strangersKey, alicesKey));
		// EXT_INFO follows the server's NEWKEYS; by the time a login is done it has arrived
		assertTrue(s.getServerSignatureAlgorithms().contains("rsa-sha2-512"), "server-sig-algs is sent");
		assertEquals("alice", s.exec("whoami", null, 10000).getStdoutText());
		s.close();
		client.close();

		ClientSession k = connect(null);
		k.authenticateAndWait("alice", KeyboardInteractiveAuth.password("secret".toCharArray()));
		assertTrue(k.isAuthenticated());
		k.close();
		client.close();

		ClientSession bad = connect(null);
		assertThrows(SshException.class, () -> bad.authenticateAndWait("alice", new PublicKeyAuth(strangersKey), new PasswordAuth("wrong")));
		assertThrows(SshException.class, () -> bad.authenticateAndWait("bob", new PasswordAuth("secret")));
		bad.authenticateAndWait("alice", new PasswordAuth("secret"));
		bad.close();
	}

	@Test
	public void tooManyFailuresDisconnects() throws Exception {
		start();
		server.setMaxLoginAttempts(3);
		server.startAndWait(5000);
		ClientSession s = connect(null);
		for (int i = 0; i < 2; i++) {
			assertThrows(SshException.class, () -> s.authenticateAndWait("alice", new PasswordAuth("wrong")));
		}
		SshException e = assertThrows(SshException.class, () -> s.authenticateAndWait("alice", new PasswordAuth("wrong")));
		assertEquals(SshConstants.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, e.getReason(), e.getMessage());
		assertTrue(s.getReadyFuture().isDone());
		Thread.sleep(200);
		assertFalse(s.isOpen(), "the server disconnected");
	}

	@Test
	public void loginTimeLimit() throws Exception {
		start();
		server.setLoginTimeLimit(500);
		server.startAndWait(5000);
		ClientSession s = connect(null);
		Thread.sleep(1500);
		assertFalse(s.isOpen(), "not logged in within the time limit");
	}

	@Test
	public void execShellEnvAndFlowControl() throws Exception {
		start().startAndWait(5000);
		ClientSession s = connect(null);
		s.authenticateAndWait("alice", new PasswordAuth("secret"));

		ExecResult r = s.exec("fail 4", null, 10000);
		assertEquals(4, r.getExitStatus());
		assertEquals("failing\n", r.getStderrText());

		byte[] data = new byte[6*1024*1024];
		new Random(3).nextBytes(data);
		assertArrayEquals(data, s.exec("cat", data, 60000).getStdout(), "6 MB in and out");

		SessionChannel big = s.openSession();
		big.exec("big 30000000");
		InputStream in = big.getInputStream();
		long total = 0;
		byte[] b = new byte[50000];
		int n;
		while( (n = in.read(b)) > 0 ) {
			total += n;
		}
		assertEquals(30_000_000L, total, "30 MB, the server waits for our window");
		assertEquals(0, big.waitForExit(10, TimeUnit.SECONDS));

		SessionChannel e = s.openSession();
		e.setEnv("COLOR", "blue");
		e.exec("env COLOR");
		assertEquals("blue", new String(e.getInputStream().readAllBytes(), StandardCharsets.UTF_8));

		SessionChannel sh = s.openSession();
		sh.requestPty("vt100", 80, 24);
		sh.shell();
		PrintStream p = new PrintStream(sh.getOutputStream(), true, "UTF-8");
		BufferedReader br = new BufferedReader(new InputStreamReader(sh.getInputStream(), StandardCharsets.UTF_8));
		p.print("one\n");
		assertEquals("vt100 80x24> one", br.readLine());
		sh.windowChange(132, 50, 0, 0);
		Thread.sleep(100);
		p.print("two\n");
		assertEquals("vt100 132x50> two", br.readLine());
		p.print("exit\n");
		assertEquals(0, sh.waitForExit(10, TimeUnit.SECONDS));

		// A command still running when the client closes the channel is stopped
		SessionChannel sl = s.openSession();
		sl.exec("sleep");
		sl.close();
		assertTrue(sl.waitForClose(10, TimeUnit.SECONDS));

		// No subsystem "sftp" on this server: refused, the session goes on
		SessionChannel sub = s.openSession();
		assertThrows(SshException.class, () -> sub.subsystem("sftp"));
		sub.close();
		assertEquals("ok\n", s.exec("echo ok", null, 10000).getStdoutText());
	}

	/** With an access control list, users need the permission for what they run */
	@Test
	public void permissionsFromTheAccessControlList() throws Exception {
		String name = "ssh-acl-test";
		System.setProperty(name+".user0", "carol, pw, exec");
		try {
			start();
			server.setName(name);
			server.setPasswordAuthenticator(null);
			PropertyAuthenticator acl = new PropertyAuthenticator();
			acl.initialize(name);
			server.setAccessControl(acl);
			server.startAndWait(5000);
			ClientSession s = connect(null);
			s.authenticateAndWait("carol", new PasswordAuth("pw"));
			assertEquals("carol", s.exec("whoami", null, 10000).getStdoutText());
			SessionChannel sh = s.openSession();
			assertThrows(SshException.class, sh::shell, "carol has no shell permission");
			s.close();
		} finally {
			System.clearProperty(name+".user0");
		}
	}

	/** SSH never speaks TLS, whatever the "secure" property (meant for TLS servers) says */
	@Test
	public void secureNeverMeansTls() throws Exception {
		System.setProperty("secure", "true");
		System.setProperty(SshServer.class.getName()+".secure", "true");
		try {
			start().startAndWait(5000);
			assertFalse(server.isSecure());
			ClientSession s = connect(null);
			s.authenticateAndWait("alice", new PasswordAuth("secret"));
			assertEquals("alice", s.exec("whoami", null, 10000).getStdoutText());
			s.close();
			assertThrows(IllegalArgumentException.class, () -> server.setSecure(true));
			server.setSecure(false);
		} finally {
			System.clearProperty("secure");
			System.clearProperty(SshServer.class.getName()+".secure");
		}
	}

	/** fsh is the shell when none is configured and it is on the class path; "none" turns it off */
	@Test
	public void fshIsTheDefaultShell() throws Exception {
		start();
		server.setShellFactory(null);
		server.startAndWait(5000);
		assertTrue(server.getShellFactory() instanceof us.bringardner.fsh.ssh.FshShellFactory, "the default");
		ClientSession s = connect(null);
		s.authenticateAndWait("alice", new PasswordAuth("secret"));
		SessionChannel sh = s.openSession();
		sh.shell();
		assertEquals("fsh stand-in\n", new String(sh.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
		s.close();
		server.stop(5000, false);

		System.setProperty(SshServer.class.getName()+"."+SshServer.PROPERTY_SHELL_FACTORY, "none");
		try {
			start();
			server.setShellFactory(null);
			server.startAndWait(5000);
			assertNull(server.getShellFactory(), "ShellFactory=none");
			ClientSession t = connect(null);
			t.authenticateAndWait("alice", new PasswordAuth("secret"));
			SessionChannel sh2 = t.openSession();
			assertThrows(SshException.class, sh2::shell);
			t.close();
		} finally {
			System.clearProperty(SshServer.class.getName()+"."+SshServer.PROPERTY_SHELL_FACTORY);
		}
	}

	/** Made by name from the ShellFactory property */
	public static class PropertyShell implements IShellFactory {
		@Override
		public ICommand create(CommandEnvironment env) {
			return shell();
		}
	}

	/** The shell can be configured by class name, with no code */
	@Test
	public void shellFactoryFromProperty() throws Exception {
		String name = "ssh-shell-property-test";
		System.setProperty(SshServer.class.getName()+"."+SshServer.PROPERTY_SHELL_FACTORY, PropertyShell.class.getName());
		try {
			start();
			server.setShellFactory(null);
			server.setName(name);
			server.startAndWait(5000);
			assertTrue(server.getShellFactory() instanceof PropertyShell);
			ClientSession s = connect(null);
			s.authenticateAndWait("alice", new PasswordAuth("secret"));
			SessionChannel sh = s.openSession();
			sh.shell();
			sh.getOutputStream().write("exit\n".getBytes(StandardCharsets.UTF_8));
			sh.getOutputStream().flush();
			assertEquals(0, sh.waitForExit(10, TimeUnit.SECONDS));
			s.close();
		} finally {
			System.clearProperty(SshServer.class.getName()+"."+SshServer.PROPERTY_SHELL_FACTORY);
		}
	}

	/** A class that can't be made stops the server from starting, not the first login */
	@Test
	public void badShellFactoryPropertyStopsStart() throws Exception {
		String name = "ssh-bad-shell-test";
		System.setProperty(SshServer.class.getName()+"."+SshServer.PROPERTY_SHELL_FACTORY, "no.such.ShellFactory");
		try {
			start();
			server.setShellFactory(null);
			server.setName(name);
			IOException e = assertThrows(IOException.class, () -> server.startAndWait(5000));
			assertTrue(e.getMessage().contains("no.such.ShellFactory"), e.getMessage());
			assertEquals(-1, server.getLocalPort());
		} finally {
			System.clearProperty(SshServer.class.getName()+"."+SshServer.PROPERTY_SHELL_FACTORY);
		}
	}

	@Test
	public void hostKeysMadeOnceAndKept() throws Exception {
		File keyDir = new File(dir, "hostkeys");
		List<KeyPair> first = HostKeyProviders.generated(keyDir).getHostKeys();
		assertTrue(new File(keyDir, "ssh_host_ecdsa_key").isFile());
		assertTrue(new File(keyDir, "ssh_host_rsa_key.pub").isFile());
		List<KeyPair> again = HostKeyProviders.generated(keyDir).getHostKeys();
		for (int i = 0; i < first.size(); i++) {
			assertArrayEquals(SshPublicKeys.encode(first.get(i).getPublic()), SshPublicKeys.encode(again.get(i).getPublic()));
		}
		java.util.Set<java.nio.file.attribute.PosixFilePermission> perms = Files.getPosixFilePermissions(new File(keyDir, "ssh_host_rsa_key").toPath());
		assertEquals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"), perms);
	}

	/** zlib@openssh.com starts after the login, zlib at once; data goes through either way */
	@Test
	public void compression() throws Exception {
		start().startAndWait(5000);
		byte[] data = new byte[2*1024*1024];
		// compressible: text-like with some randomness
		Random r = new Random(5);
		for (int i = 0; i < data.length; i++) {
			data[i] = (byte) ('a'+r.nextInt(8));
		}
		for (String comp : new String[] {"zlib@openssh.com", "zlib"}) {
			ClientSession s = connect(SshAlgorithms.defaults().setCompressions(comp));
			assertEquals(comp, s.getNegotiated().getCompressionClientToServer());
			boolean delayed = comp.equals("zlib@openssh.com");
			assertEquals(!delayed, s.isCompressing()[0], comp+" before the login");
			s.authenticateAndWait("alice", new PasswordAuth("secret"));
			Thread.sleep(50);
			assertTrue(s.isCompressing()[0] && s.isCompressing()[1], comp+" after the login, both ways");
			assertArrayEquals(data, s.exec("cat", data, 60000).getStdout(), comp);
			long wire = s.getConnection().getBytesOut();
			assertTrue(wire < data.length/2, comp+" compressed: "+wire+" bytes sent for "+data.length);
			s.rekey().get(10, TimeUnit.SECONDS);
			assertEquals("still\n", s.exec("echo still", null, 10000).getStdoutText(), "compression goes on after a re-key");
			s.close();
			client.close();
		}
	}
}
