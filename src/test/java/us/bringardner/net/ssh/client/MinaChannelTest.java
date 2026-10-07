package us.bringardner.net.ssh.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Session channels against an embedded MINA SSHD server running small test commands: exec
 * with exit status and stderr, stdin, flow control with lots of data and a slow reader,
 * channels in parallel, a pty and shell, env, close and keep-alives.
 */
public class MinaChannelTest {

	private static SshServer sshd;
	private static KeyPair hostKey;
	private SshClient client;
	private ClientSession session;

	/** A test command run on its own thread */
	private abstract static class TestCommand implements Command {
		InputStream in;
		OutputStream out;
		OutputStream err;
		ExitCallback exit;
		Environment env;
		Thread thread;

		@Override
		public void setInputStream(InputStream in) {
			this.in = in;
		}

		@Override
		public void setOutputStream(OutputStream out) {
			this.out = out;
		}

		@Override
		public void setErrorStream(OutputStream err) {
			this.err = err;
		}

		@Override
		public void setExitCallback(ExitCallback exit) {
			this.exit = exit;
		}

		@Override
		public void start(ChannelSession channel, Environment env) {
			this.env = env;
			thread = new Thread(() -> {
				int status;
				try {
					status = run();
					out.flush();
					err.flush();
				} catch (Exception e) {
					status = 99;
				}
				exit.onExit(status);
			});
			thread.setDaemon(true);
			thread.start();
		}

		@Override
		public void destroy(ChannelSession channel) {
			thread.interrupt();
		}

		abstract int run() throws Exception;
	}

	private static Command command(String line) {
		String[] words = line.split(" ", 2);
		String arg = words.length > 1 ? words[1] : "";
		return new TestCommand() {
			@Override
			int run() throws Exception {
				switch (words[0]) {
				case "echo":
					out.write((arg+"\n").getBytes(StandardCharsets.UTF_8));
					return 0;
				case "fail":
					err.write("failing\n".getBytes(StandardCharsets.UTF_8));
					return Integer.parseInt(arg);
				case "cat": {
					byte[] b = new byte[8192];
					int n;
					while( (n = in.read(b)) > 0 ) {
						out.write(b, 0, n);
					}
					return 0;
				}
				case "big": {
					// arg bytes of a known pattern, on stdout and some on stderr
					Random r = new Random(42);
					long left = Long.parseLong(arg);
					byte[] b = new byte[16*1024];
					while( left > 0 ) {
						r.nextBytes(b);
						int n = (int) Math.min(b.length, left);
						out.write(b, 0, n);
						left -= n;
					}
					err.write("done\n".getBytes(StandardCharsets.UTF_8));
					return 0;
				}
				case "env":
					out.write(String.valueOf(env.getEnv().get(arg)).getBytes(StandardCharsets.UTF_8));
					return 0;
				case "sleep":
					Thread.sleep(60000);
					return 0;
				default:
					err.write(("unknown command "+words[0]+"\n").getBytes(StandardCharsets.UTF_8));
					return 127;
				}
			}
		};
	}

	/** A line shell: answers each line with "TERM> line", "exit" ends it */
	private static Command shell() {
		return new TestCommand() {
			@Override
			int run() throws Exception {
				BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
				PrintStream p = new PrintStream(out, true, "UTF-8");
				String term = env.getEnv().get(Environment.ENV_TERM);
				String line;
				while( (line = r.readLine()) != null ) {
					line = line.trim();
					if( line.equals("exit") ) {
						return 0;
					}
					p.print(term+"> "+line+"\n");
				}
				return 1;
			}
		};
	}

	@BeforeAll
	public static void startServer() throws Exception {
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
		g.initialize(new ECGenParameterSpec("secp256r1"));
		hostKey = g.generateKeyPair();
		sshd = SshServer.setUpDefaultServer();
		sshd.setHost("localhost");
		sshd.setPort(0);
		sshd.setKeyPairProvider(KeyPairProvider.wrap(hostKey));
		sshd.setPasswordAuthenticator((user, password, s) -> "test".equals(password));
		sshd.setCommandFactory((channel, line) -> command(line));
		sshd.setShellFactory(channel -> shell());
		sshd.start();
	}

	@AfterAll
	public static void stopServer() throws Exception {
		sshd.stop(true);
	}

	@BeforeEach
	public void connect() throws Exception {
		client = new SshClient();
		client.setHostKeyVerifier(HostKeyVerifiers.only(hostKey.getPublic()));
		session = client.connectAndWait("localhost", sshd.getPort());
		session.authenticateAndWait("test", new PasswordAuth("test"));
	}

	@AfterEach
	public void disconnect() {
		client.close();
	}

	@Test
	public void execOutputAndExitStatus() throws Exception {
		ExecResult r = session.exec("echo hello world", null, 10000);
		assertEquals(0, r.getExitStatus());
		assertEquals("hello world\n", r.getStdoutText());
		assertTrue(r.isSuccess());

		r = session.exec("fail 3", null, 10000);
		assertEquals(3, r.getExitStatus());
		assertEquals("failing\n", r.getStderrText());
		assertEquals("", r.getStdoutText());
		assertFalse(r.isSuccess());

		assertEquals(127, session.exec("nonsense", null, 10000).getExitStatus());
	}

	/** 5 MB in and out: the output stream waits for the server's window, the input opens ours */
	@Test
	public void stdinRoundTrip() throws Exception {
		byte[] data = new byte[5*1024*1024];
		new Random(1).nextBytes(data);
		ExecResult r = session.exec("cat", data, 60000);
		assertEquals(0, r.getExitStatus());
		assertArrayEquals(data, r.getStdout());
	}

	/** 20 MB, ten times our window, read slowly: the server is held back by the window, nothing is lost */
	@Test
	public void flowControlWithASlowReader() throws Exception {
		long size = 20L*1024*1024;
		SessionChannel ch = session.openSession();
		ch.exec("big "+size);
		MessageDigest got = MessageDigest.getInstance("SHA-256");
		InputStream in = ch.getInputStream();
		byte[] b = new byte[64*1024];
		long total = 0;
		int n;
		int reads = 0;
		while( (n = in.read(b)) > 0 ) {
			got.update(b, 0, n);
			total += n;
			if( ++reads % 50 == 0 ) {
				Thread.sleep(5);
			}
		}
		assertEquals(size, total);
		MessageDigest want = MessageDigest.getInstance("SHA-256");
		Random r = new Random(42);
		byte[] chunk = new byte[16*1024];
		for (long left = size; left > 0; left -= chunk.length) {
			r.nextBytes(chunk);
			want.update(chunk, 0, (int) Math.min(chunk.length, left));
		}
		assertArrayEquals(want.digest(), got.digest());
		assertEquals("done\n", new String(ch.getErrorStream().readAllBytes(), StandardCharsets.UTF_8));
		assertEquals(0, ch.waitForExit(10, TimeUnit.SECONDS));
	}

	@Test
	public void parallelChannels() throws Exception {
		ExecutorService pool = Executors.newFixedThreadPool(8);
		try {
			List<Future<Boolean>> results = new ArrayList<Future<Boolean>>();
			for (int i = 0; i < 16; i++) {
				int seed = i;
				results.add(pool.submit(() -> {
					byte[] data = new byte[100_000+seed*10_000];
					new Random(seed).nextBytes(data);
					ExecResult r = session.exec("cat", data, 60000);
					return r.isSuccess() && java.util.Arrays.equals(data, r.getStdout());
				}));
			}
			for (Future<Boolean> f : results) {
				assertTrue(f.get(60, TimeUnit.SECONDS));
			}
		} finally {
			pool.shutdownNow();
		}
		assertEquals(0, session.getConnectionService().getChannels().size(), "every channel closed");
	}

	@Test
	public void ptyShellAndEnv() throws Exception {
		SessionChannel ch = session.openSession();
		ch.requestPty("xterm-256color", 80, 24);
		ch.shell();
		PrintStream p = new PrintStream(ch.getOutputStream(), true, "UTF-8");
		BufferedReader r = new BufferedReader(new InputStreamReader(ch.getInputStream(), StandardCharsets.UTF_8));
		p.print("ls\n");
		assertEquals("xterm-256color> ls", r.readLine());
		p.print("pwd\n");
		assertEquals("xterm-256color> pwd", r.readLine());
		ch.windowChange(120, 40, 0, 0);
		p.print("exit\n");
		assertEquals(0, ch.waitForExit(10, TimeUnit.SECONDS));

		SessionChannel e = session.openSession();
		assertTrue(e.setEnv("BJL_TEST", "42"));
		e.exec("env BJL_TEST");
		assertEquals("42", new String(e.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
		e.close();
	}

	@Test
	public void closeAndTimeout() throws Exception {
		SessionChannel ch = session.openSession();
		ch.exec("sleep");
		ch.close();
		assertTrue(ch.waitForClose(10, TimeUnit.SECONDS), "closed by both sides");
		assertTrue(ch.isClosed());
		assertThrows(IOException.class, () -> ch.getOutputStream().write(1));

		assertThrows(SocketTimeoutException.class, () -> session.exec("sleep", null, 300));
		// The session goes on
		assertEquals("ok\n", session.exec("echo ok", null, 10000).getStdoutText());
	}

	@Test
	public void keepAlive() throws Exception {
		client.close();
		client = new SshClient();
		client.setHostKeyVerifier(HostKeyVerifiers.only(hostKey.getPublic()));
		client.setKeepAliveInterval(300);
		session = client.connectAndWait("localhost", sshd.getPort());
		session.authenticateAndWait("test", new PasswordAuth("test"));
		// Idle for several intervals: keep-alives go out, answers come back, the session stays
		Thread.sleep(2500);
		assertTrue(session.isOpen());
		assertEquals("ok\n", session.exec("echo ok", null, 10000).getStdoutText());
	}

	/** Output stream writes go out in order, also when the window splits them */
	@Test
	public void streamsInOrder() throws Exception {
		SessionChannel ch = session.openSession();
		ch.exec("cat");
		OutputStream out = ch.getOutputStream();
		ByteArrayOutputStream want = new ByteArrayOutputStream();
		for (int i = 0; i < 2000; i++) {
			byte[] line = ("line "+i+"\n").getBytes(StandardCharsets.UTF_8);
			out.write(line);
			want.write(line);
		}
		out.close();
		assertArrayEquals(want.toByteArray(), ch.getInputStream().readAllBytes());
		assertEquals(0, ch.waitForExit(10, TimeUnit.SECONDS));
	}
}
