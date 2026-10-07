package us.bringardner.parley.ssh.sftp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.ssh.client.ClientSession;
import us.bringardner.parley.ssh.client.HostKeyVerifiers;
import us.bringardner.parley.ssh.client.PasswordAuth;
import us.bringardner.parley.ssh.client.SshClient;

/**
 * The SFTP client against MINA SSHD's SFTP server (a virtual file system rooted in a temp
 * directory, so the results can be checked on the local disk too).
 */
public class MinaSftpTest {

	@TempDir
	static File root;

	private static SshServer sshd;
	private static KeyPair hostKey;
	private SshClient client;
	private ClientSession session;
	private SftpClient sftp;

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
		sshd.setSubsystemFactories(Collections.singletonList(new SftpSubsystemFactory()));
		sshd.setFileSystemFactory(new VirtualFileSystemFactory(root.toPath()));
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
		sftp = SftpClient.open(session);
	}

	@AfterEach
	public void disconnect() {
		sftp.close();
		client.close();
	}

	private static byte[] random(int size, long seed) {
		byte[] b = new byte[size];
		new Random(seed).nextBytes(b);
		return b;
	}

	private void put(String path, byte[] data) throws Exception {
		try (OutputStream out = sftp.write(path, false)) {
			out.write(data);
		}
	}

	private byte[] get(String path) throws Exception {
		try (InputStream in = sftp.read(path, 0)) {
			return in.readAllBytes();
		}
	}

	/** Our client with MINA's server (which speaks 3 to 6) at each version */
	@Test
	public void eachVersion() throws Exception {
		for (int v = 3; v <= 6; v++) {
			try (SftpClient s = SftpClient.open(session, v)) {
				SftpVersionCheck.roundTrip(s, "/v"+v, v, false);
			}
		}
	}

	@Test
	public void versionAndPaths() throws Exception {
		assertEquals(3, sftp.getServerVersion());
		assertEquals("/", sftp.realpath("."));
		assertEquals("/", sftp.realpath("a/.."));
	}

	@Test
	public void filesAndDirectories() throws Exception {
		sftp.mkdir("/basic");
		assertTrue(sftp.stat("/basic").isDirectory());
		byte[] data = "hello sftp".getBytes(StandardCharsets.UTF_8);
		put("/basic/a.txt", data);
		assertArrayEquals(data, Files.readAllBytes(new File(root, "basic/a.txt").toPath()), "on the server's disk");
		assertArrayEquals(data, get("/basic/a.txt"));
		SftpAttrs a = sftp.stat("/basic/a.txt");
		assertEquals(data.length, a.getSize());
		assertTrue(a.isRegularFile());

		List<String> names = sftp.list("/basic").stream().map(SftpDirEntry::getName).filter(n -> !n.startsWith(".")).collect(Collectors.toList());
		assertEquals(Collections.singletonList("a.txt"), names);

		sftp.rename("/basic/a.txt", "/basic/b.txt");
		SftpException e = assertThrows(SftpException.class, () -> sftp.stat("/basic/a.txt"));
		assertEquals(SftpConstants.SSH_FX_NO_SUCH_FILE, e.getStatus());

		// Replace an existing file atomically when the server has the extension
		put("/basic/c.txt", new byte[] {1});
		if( sftp.hasExtension(SftpConstants.EXT_POSIX_RENAME) ) {
			sftp.posixRename("/basic/b.txt", "/basic/c.txt");
			assertArrayEquals(data, get("/basic/c.txt"));
		}

		sftp.setStat("/basic/c.txt", SftpAttrs.NONE.withTimes(1_000_000_000L, 1_200_000_000L));
		assertEquals(1_200_000_000L, sftp.stat("/basic/c.txt").getModifyTime());

		for (SftpDirEntry d : sftp.list("/basic")) {
			if( !d.getName().startsWith(".") ) {
				sftp.remove("/basic/"+d.getName());
			}
		}
		sftp.rmdir("/basic");
		assertFalse(new File(root, "basic").exists());
		assertThrows(SftpException.class, () -> sftp.rmdir("/basic"));
	}

	@Test
	public void links() throws Exception {
		put("/target.txt", "t".getBytes(StandardCharsets.UTF_8));
		sftp.symlink("target.txt", "/link.txt");
		assertTrue(Files.isSymbolicLink(new File(root, "link.txt").toPath()), "link.txt is the link (OpenSSH argument order)");
		assertTrue(sftp.lstat("/link.txt").isSymbolicLink());
		assertTrue(sftp.stat("/link.txt").isRegularFile());
		assertTrue(sftp.readlink("/link.txt").endsWith("target.txt"));
		sftp.remove("/link.txt");
		sftp.remove("/target.txt");
	}

	@Test
	public void appendAndRandomAccess() throws Exception {
		put("/app.txt", "one ".getBytes(StandardCharsets.UTF_8));
		try (OutputStream out = sftp.write("/app.txt", true)) {
			out.write("two".getBytes(StandardCharsets.UTF_8));
		}
		assertEquals("one two", new String(get("/app.txt"), StandardCharsets.UTF_8));

		try (SftpHandle h = sftp.open("/app.txt", SftpConstants.SSH_FXF_READ | SftpConstants.SSH_FXF_WRITE, SftpAttrs.NONE)) {
			byte[] x = "ONE".getBytes(StandardCharsets.UTF_8);
			sftp.write(h, 0, x, 0, x.length);
			assertEquals("two", new String(sftp.read(h, 4, 100), StandardCharsets.UTF_8));
			assertEquals(null, sftp.read(h, 1000, 10), "past the end");
			sftp.fsetStat(h, SftpAttrs.NONE.withSize(3));
		}
		assertEquals("ONE", new String(get("/app.txt"), StandardCharsets.UTF_8));
		// From an offset
		try (InputStream in = sftp.read("/app.txt", 1)) {
			assertEquals("NE", new String(in.readAllBytes(), StandardCharsets.UTF_8));
		}
		sftp.remove("/app.txt");
	}

	/** 20 MB through the pipelined streams, checked on the server's disk, and how fast */
	@Test
	public void largeFiles() throws Exception {
		byte[] data = random(20*1024*1024+123, 7);
		long t0 = System.nanoTime();
		put("/big.bin", data);
		long t1 = System.nanoTime();
		assertArrayEquals(data, Files.readAllBytes(new File(root, "big.bin").toPath()));
		long t2 = System.nanoTime();
		assertArrayEquals(data, get("/big.bin"));
		long t3 = System.nanoTime();
		System.out.printf("SFTP 20 MB: write %.0f MB/s, read %.0f MB/s%n", 20e9/(t1-t0)/1.0, 20e9/(t3-t2)/1.0);

		// Skip, and one request at a time gives the same bytes
		try (InputStream in = sftp.read("/big.bin", 0)) {
			assertEquals(5_000_000, in.skip(5_000_000));
			byte[] b = new byte[1000];
			assertEquals(1000, in.readNBytes(b, 0, 1000));
			assertArrayEquals(java.util.Arrays.copyOfRange(data, 5_000_000, 5_001_000), b);
		}
		sftp.setOutstanding(1);
		assertArrayEquals(data, get("/big.bin"));
		sftp.remove("/big.bin");
	}

	@Test
	public void concurrentUseOfOneClient() throws Exception {
		ExecutorService pool = Executors.newFixedThreadPool(8);
		try {
			List<Future<Boolean>> results = new ArrayList<Future<Boolean>>();
			for (int i = 0; i < 16; i++) {
				int n = i;
				results.add(pool.submit(() -> {
					byte[] d = random(200_000+n*5000, n);
					put("/c"+n+".bin", d);
					boolean ok = java.util.Arrays.equals(d, get("/c"+n+".bin"));
					sftp.remove("/c"+n+".bin");
					return ok;
				}));
			}
			for (Future<Boolean> f : results) {
				assertTrue(f.get(60, TimeUnit.SECONDS));
			}
		} finally {
			pool.shutdownNow();
		}
	}

	@Test
	public void errors() throws Exception {
		SftpException e = assertThrows(SftpException.class, () -> sftp.read("/no/such/file", 0));
		assertEquals(SftpConstants.SSH_FX_NO_SUCH_FILE, e.getStatus());
		assertThrows(SftpException.class, () -> sftp.list("/nothing-here"));
		assertThrows(SftpException.class, () -> sftp.remove("/nothing-here"));
		// The client goes on after errors
		sftp.mkdir("/after");
		sftp.rmdir("/after");
		assertTrue(sftp.isOpen());
	}
}
