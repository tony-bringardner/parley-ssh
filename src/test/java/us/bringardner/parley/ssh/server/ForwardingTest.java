package us.bringardner.parley.ssh.server;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.ssh.client.ClientSession;
import us.bringardner.parley.ssh.client.HostKeyVerifiers;
import us.bringardner.parley.ssh.client.PasswordAuth;
import us.bringardner.parley.ssh.client.PortForwarder;
import us.bringardner.parley.ssh.client.SshClient;
import us.bringardner.parley.ssh.connection.ForwardingChannel;

/**
 * Port forwarding between the library's client and server: -L (direct-tcpip), -R
 * (tcpip-forward), many connections at once with data both ways, and the filter.
 */
public class ForwardingTest {

	private SshServer server;
	private SshClient client;
	private ServerSocket echo;
	private final ExecutorService pool = Executors.newCachedThreadPool();

	/** A TCP echo server */
	static ServerSocket echoServer(ExecutorService pool) throws IOException {
		ServerSocket ss = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
		pool.execute(() -> {
			while( !ss.isClosed() ) {
				try {
					Socket s = ss.accept();
					pool.execute(() -> {
						try (Socket c = s) {
							c.getInputStream().transferTo(c.getOutputStream());
						} catch (IOException e) {
							// done
						}
					});
				} catch (IOException e) {
					break;
				}
			}
		});
		return ss;
	}

	/** Send data through a TCP connection to host:port, read the echo */
	static boolean roundTrip(String host, int port, int size, long seed, ExecutorService pool) throws Exception {
		byte[] data = new byte[size];
		new Random(seed).nextBytes(data);
		try (Socket s = new Socket()) {
			s.connect(new InetSocketAddress(host, port), 10000);
			s.setSoTimeout(30000);
			OutputStream out = s.getOutputStream();
			Future<?> w = pool.submit(() -> {
				out.write(data);
				s.shutdownOutput();
				return null;
			});
			InputStream in = s.getInputStream();
			byte[] got = in.readAllBytes();
			w.get(30, TimeUnit.SECONDS);
			return java.util.Arrays.equals(data, got);
		}
	}

	@BeforeEach
	public void start() throws Exception {
		echo = echoServer(pool);
		server = new SshServer(0);
		server.setHostKeyProvider(HostKeyProviders.ephemeral());
		server.setPasswordAuthenticator((user, pw, ctx) -> "secret".equals(new String(pw)) ? new SshPrincipal(user) : null);
		server.setForwardingFilter(ForwardingFilters.localOnly());
		server.startAndWait(5000);
	}

	@AfterEach
	public void stop() throws Exception {
		if( client != null ) {
			client.close();
		}
		server.stop(5000, false);
		echo.close();
		pool.shutdownNow();
	}

	private ClientSession session() throws Exception {
		client = new SshClient();
		client.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
		ClientSession s = client.connectAndWait("localhost", server.getLocalPort());
		s.authenticateAndWait("alice", new PasswordAuth("secret"));
		return s;
	}

	private void parallel(String host, int port) throws Exception {
		List<Future<Boolean>> results = new ArrayList<Future<Boolean>>();
		for (int i = 0; i < 8; i++) {
			int n = i;
			results.add(pool.submit(() -> roundTrip(host, port, 3*1024*1024+n, n, pool)));
		}
		for (Future<Boolean> f : results) {
			assertTrue(f.get(60, TimeUnit.SECONDS));
		}
	}

	@Test
	public void localForwarding() throws Exception {
		ClientSession s = session();
		try (PortForwarder f = s.startLocalForwarding("localhost", 0, "127.0.0.1", echo.getLocalPort())) {
			parallel("localhost", f.getBoundPort());
		}
		// The channel directly, no local port
		ForwardingChannel ch = s.openDirectTcpip("127.0.0.1", echo.getLocalPort());
		ch.getOutputStream().write("ping".getBytes());
		ch.sendEof();
		assertArrayEquals("ping".getBytes(), ch.getInputStream().readAllBytes());
	}

	@Test
	public void remoteForwarding() throws Exception {
		ClientSession s = session();
		PortForwarder f = s.startRemoteForwarding("localhost", 0, "127.0.0.1", echo.getLocalPort());
		assertTrue(f.getBoundPort() > 0, "the server chose a port");
		parallel("localhost", f.getBoundPort());
		f.close();
		Thread.sleep(300);
		assertThrows(IOException.class, () -> new Socket("localhost", f.getBoundPort()).close(), "no longer listening");
	}

	@Test
	public void theFilterDecides() throws Exception {
		ClientSession s = session();
		// localOnly: not to other hosts, not on all addresses, not on low ports
		assertThrows(IOException.class, () -> s.openDirectTcpip("192.0.2.1", 80));
		assertThrows(IOException.class, () -> s.startRemoteForwarding("0.0.0.0", 0, "127.0.0.1", 1));
		assertThrows(IOException.class, () -> s.startRemoteForwarding("localhost", 80, "127.0.0.1", 1));

		// Without a filter: nothing
		server.setForwardingFilter(null);
		assertThrows(IOException.class, () -> s.openDirectTcpip("127.0.0.1", echo.getLocalPort()));
		assertThrows(IOException.class, () -> s.startRemoteForwarding("localhost", 0, "127.0.0.1", 1));
		assertTrue(s.isOpen(), "a refusal leaves the session alone");
	}
}
