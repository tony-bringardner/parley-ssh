package us.bringardner.parley.ssh.sftp.server;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Duration;
import java.util.List;
import java.util.Random;
import java.util.Vector;
import java.util.stream.Collectors;

import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.fileproxy.FileProxyFactory;
import us.bringardner.parley.files.memory.MemoryFileSourceFactory;
import us.bringardner.parley.ssh.client.ClientSession;
import us.bringardner.parley.ssh.client.HostKeyVerifiers;
import us.bringardner.parley.ssh.client.PasswordAuth;
import us.bringardner.parley.ssh.client.SshClient;
import us.bringardner.parley.ssh.server.HostKeyProviders;
import us.bringardner.parley.ssh.server.SshPrincipal;
import us.bringardner.parley.ssh.server.SshServer;
import us.bringardner.parley.ssh.sftp.SftpAttrs;
import us.bringardner.parley.ssh.sftp.SftpClient;
import us.bringardner.parley.ssh.sftp.SftpConstants;
import us.bringardner.parley.ssh.sftp.SftpDirEntry;
import us.bringardner.parley.ssh.sftp.SftpException;

/**
 * The SFTP server on FileSource: the library's client (every operation, the root as a
 * sandbox), MINA's and JSch's SFTP clients, read-only mode and an in-memory file system.
 */
public class SftpServerTest {

	@TempDir
	File dir;

	private SshServer server;
	private SshClient client;
	private SftpSubsystemFactory sftpFactory;
	private File rootDir;

	private void start(FileSource root) throws Exception {
		server = new SshServer(0);
		server.setHostKeyProvider(HostKeyProviders.ephemeral());
		server.setPasswordAuthenticator((user, pw, ctx) -> "secret".equals(new String(pw)) ? new SshPrincipal(user) : null);
		sftpFactory = SftpSubsystemFactory.forRoot(root);
		server.addSubsystem(sftpFactory);
		server.startAndWait(5000);
	}

	private File startOnDisk() throws Exception {
		rootDir = new File(dir, "root");
		assertTrue(rootDir.mkdirs());
		start(new FileProxyFactory().createFileSource(rootDir.getCanonicalPath()));
		return rootDir;
	}

	private SftpClient sftp() throws Exception {
		client = new SshClient();
		client.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
		ClientSession s = client.connectAndWait("localhost", server.getLocalPort());
		s.authenticateAndWait("alice", new PasswordAuth("secret"));
		return SftpClient.open(s);
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

	private static void put(SftpClient sftp, String path, byte[] data) throws Exception {
		try (OutputStream out = sftp.write(path, false)) {
			out.write(data);
		}
	}

	private static byte[] get(SftpClient sftp, String path) throws Exception {
		try (InputStream in = sftp.read(path, 0)) {
			return in.readAllBytes();
		}
	}

	@Test
	public void everyOperation() throws Exception {
		File root = startOnDisk();
		try (SftpClient sftp = sftp()) {
			assertTrue(sftp.hasExtension(SftpConstants.EXT_POSIX_RENAME));
			assertEquals("/", sftp.realpath("."));
			assertEquals("/a", sftp.realpath("/x/../a/./"));

			sftp.mkdir("/docs");
			byte[] data = new byte[3*1024*1024+5];
			new Random(1).nextBytes(data);
			put(sftp, "/docs/data.bin", data);
			assertArrayEquals(data, Files.readAllBytes(new File(root, "docs/data.bin").toPath()), "on disk");
			assertArrayEquals(data, get(sftp, "/docs/data.bin"));
			SftpAttrs a = sftp.stat("/docs/data.bin");
			assertEquals(data.length, a.getSize());
			assertTrue(a.isRegularFile());
			assertTrue(sftp.stat("/docs").isDirectory());

			List<String> names = sftp.list("/docs").stream().map(SftpDirEntry::getName).collect(Collectors.toList());
			assertEquals(List.of(".", "..", "data.bin"), names);
			assertTrue(sftp.list("/docs").get(2).getLongName().startsWith("-rw"));

			try (OutputStream out = sftp.write("/docs/data.bin", true)) {
				out.write("TAIL".getBytes(StandardCharsets.UTF_8));
			}
			assertEquals(data.length+4, sftp.stat("/docs/data.bin").getSize(), "append");
			sftp.setStat("/docs/data.bin", SftpAttrs.NONE.withSize(10));
			assertEquals(10, new File(root, "docs/data.bin").length(), "truncate");
			sftp.setStat("/docs/data.bin", SftpAttrs.NONE.withTimes(1_100_000_000L, 1_200_000_000L).withPermissions(0640));
			assertEquals(1_200_000_000L, sftp.stat("/docs/data.bin").getModifyTime());
			assertEquals(0640, sftp.stat("/docs/data.bin").getPermissions() & 0777);

			put(sftp, "/docs/other.txt", "o".getBytes(StandardCharsets.UTF_8));
			SftpException e = assertThrows(SftpException.class, () -> sftp.rename("/docs/data.bin", "/docs/other.txt"));
			assertEquals(SftpConstants.SSH_FX_FAILURE, e.getStatus(), "plain rename doesn't replace");
			sftp.posixRename("/docs/data.bin", "/docs/other.txt");
			assertEquals(10, sftp.stat("/docs/other.txt").getSize());
			sftp.rename("/docs/other.txt", "/docs/moved.txt");

			// Exclusive create
			assertThrows(SftpException.class, () -> sftp.open("/docs/moved.txt",
					SftpConstants.SSH_FXF_WRITE | SftpConstants.SSH_FXF_CREAT | SftpConstants.SSH_FXF_EXCL, SftpAttrs.NONE));

			sftp.symlink("moved.txt", "/docs/link");
			assertTrue(sftp.lstat("/docs/link").isSymbolicLink());
			assertTrue(sftp.stat("/docs/link").isRegularFile());
			assertEquals("/docs/moved.txt", sftp.readlink("/docs/link"));
			sftp.hardlink("/docs/moved.txt", "/docs/hard");
			assertEquals(10, sftp.stat("/docs/hard").getSize());

			assertThrows(SftpException.class, () -> sftp.rmdir("/docs"), "not empty");
			for (String n : new String[] {"link", "hard", "moved.txt"}) {
				sftp.remove("/docs/"+n);
			}
			sftp.rmdir("/docs");
			assertFalse(new File(root, "docs").exists());

			e = assertThrows(SftpException.class, () -> sftp.stat("/nothing"));
			assertEquals(SftpConstants.SSH_FX_NO_SUCH_FILE, e.getStatus());
			e = assertThrows(SftpException.class, () -> sftp.setStat("/", SftpAttrs.NONE.withOwner(0, 0)));
			assertEquals(SftpConstants.SSH_FX_OP_UNSUPPORTED, e.getStatus());
		}
	}

	/** Nothing outside the root, by ".." or by a link */
	@Test
	public void theRootIsASandbox() throws Exception {
		File root = startOnDisk();
		File secret = new File(dir, "secret.txt");
		Files.write(secret.toPath(), "top secret".getBytes(StandardCharsets.UTF_8));
		Files.createSymbolicLink(new File(root, "escape").toPath(), secret.toPath());
		Files.createSymbolicLink(new File(root, "escapedir").toPath(), dir.toPath());
		try (SftpClient sftp = sftp()) {
			// ".." can't climb above "/"
			assertEquals("/", sftp.realpath("/../../.."));
			assertThrows(SftpException.class, () -> get(sftp, "/../secret.txt"));
			assertThrows(SftpException.class, () -> get(sftp, "../../secret.txt"));

			// A link that leads out: seen and removable, not followed
			assertTrue(sftp.lstat("/escape").isSymbolicLink());
			SftpException e = assertThrows(SftpException.class, () -> get(sftp, "/escape"));
			assertEquals(SftpConstants.SSH_FX_PERMISSION_DENIED, e.getStatus());
			e = assertThrows(SftpException.class, () -> sftp.stat("/escape"));
			assertEquals(SftpConstants.SSH_FX_PERMISSION_DENIED, e.getStatus());
			e = assertThrows(SftpException.class, () -> sftp.readlink("/escape"));
			assertEquals(SftpConstants.SSH_FX_PERMISSION_DENIED, e.getStatus(), "doesn't say where it points");
			assertThrows(SftpException.class, () -> sftp.list("/escapedir"));
			assertThrows(SftpException.class, () -> put(sftp, "/escapedir/new.txt", new byte[1]));
			assertFalse(new File(dir, "new.txt").exists());
			// No new link out can be made: through the link that leads out...
			e = assertThrows(SftpException.class, () -> sftp.symlink("/escape", "/again"));
			assertEquals(SftpConstants.SSH_FX_PERMISSION_DENIED, e.getStatus());
			assertFalse(new File(root, "again").exists());
			// ...and ".." stays at "/": this link is to /secret.txt in the root, which doesn't exist
			sftp.symlink("/../secret.txt", "/inside");
			assertEquals("/secret.txt", sftp.readlink("/inside"));
			e = assertThrows(SftpException.class, () -> get(sftp, "/inside"));
			assertEquals(SftpConstants.SSH_FX_NO_SUCH_FILE, e.getStatus());
			assertEquals(new File(root, "secret.txt").getCanonicalPath(), Files.readSymbolicLink(new File(root, "inside").toPath()).toFile().getCanonicalPath());
			sftp.remove("/inside");
			sftp.remove("/escape");
			assertTrue(secret.exists(), "only the link went");
			assertEquals("top secret", new String(Files.readAllBytes(secret.toPath()), StandardCharsets.UTF_8));
		}
	}

	@Test
	public void readOnly() throws Exception {
		File root = startOnDisk();
		sftpFactory.setReadOnly(true);
		Files.write(new File(root, "r.txt").toPath(), "read me".getBytes(StandardCharsets.UTF_8));
		try (SftpClient sftp = sftp()) {
			assertEquals("read me", new String(get(sftp, "/r.txt"), StandardCharsets.UTF_8));
			for (SftpException e : new SftpException[] {
					assertThrows(SftpException.class, () -> put(sftp, "/w.txt", new byte[1])),
					assertThrows(SftpException.class, () -> sftp.remove("/r.txt")),
					assertThrows(SftpException.class, () -> sftp.mkdir("/d")),
					assertThrows(SftpException.class, () -> sftp.rename("/r.txt", "/x.txt")),
			}) {
				assertEquals(SftpConstants.SSH_FX_PERMISSION_DENIED, e.getStatus());
			}
			assertTrue(new File(root, "r.txt").exists());
		}
	}

	/** Any FileSource: here an in-memory file system */
	@Test
	public void inMemory() throws Exception {
		MemoryFileSourceFactory mem = new MemoryFileSourceFactory();
		FileSource root = mem.createFileSource("/sftp");
		assertTrue(root.mkdirs());
		start(root);
		try (SftpClient sftp = sftp()) {
			byte[] data = new byte[1_000_000];
			new Random(2).nextBytes(data);
			sftp.mkdir("/m");
			put(sftp, "/m/f.bin", data);
			assertArrayEquals(data, get(sftp, "/m/f.bin"));
			assertEquals(data.length, root.getChild("m").getChild("f.bin").length(), "in the memory file system");
		}
	}

	private static void packet(OutputStream out, us.bringardner.parley.ssh.SshBuffer b) throws Exception {
		byte[] body = b.toByteArray();
		out.write(new us.bringardner.parley.ssh.SshBuffer().putInt(body.length).putRaw(body).toByteArray());
		out.flush();
	}

	private static us.bringardner.parley.ssh.SshBuffer packet(InputStream in) throws Exception {
		java.io.DataInputStream d = new java.io.DataInputStream(in);
		byte[] b = new byte[d.readInt()];
		d.readFully(b);
		return new us.bringardner.parley.ssh.SshBuffer(b);
	}

	/** A client that starts with version 3 moves to 5 with version-select (draft 13, 5.5) */
	@Test
	public void versionSelect() throws Exception {
		startOnDisk();
		client = new SshClient();
		client.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
		ClientSession s = client.connectAndWait("localhost", server.getLocalPort());
		s.authenticateAndWait("alice", new PasswordAuth("secret"));
		us.bringardner.parley.ssh.client.SessionChannel ch = s.openSession();
		ch.subsystem("sftp");
		OutputStream out = ch.getOutputStream();
		InputStream in = ch.getInputStream();
		packet(out, new us.bringardner.parley.ssh.SshBuffer().putByte(SftpConstants.SSH_FXP_INIT).putInt(3));
		us.bringardner.parley.ssh.SshBuffer v = packet(in);
		assertEquals(SftpConstants.SSH_FXP_VERSION, v.getByte());
		assertEquals(3, v.getInt());
		java.util.Map<String, String> ext = new java.util.HashMap<String, String>();
		while( v.available() > 0 ) {
			ext.put(v.getStringUtf8(), v.getStringUtf8());
		}
		assertEquals("3,4,5,6", ext.get(SftpConstants.EXT_VERSIONS));
		packet(out, new us.bringardner.parley.ssh.SshBuffer().putByte(SftpConstants.SSH_FXP_EXTENDED).putInt(1)
				.putString(SftpConstants.EXT_VERSION_SELECT).putString("5"));
		us.bringardner.parley.ssh.SshBuffer r = packet(in);
		assertEquals(SftpConstants.SSH_FXP_STATUS, r.getByte());
		assertEquals(1, r.getInt());
		assertEquals(SftpConstants.SSH_FX_OK, r.getInt());
		// Now version 5: STAT carries flags, and the attributes start with a type byte
		packet(out, new us.bringardner.parley.ssh.SshBuffer().putByte(SftpConstants.SSH_FXP_STAT).putInt(2).putString("/").putInt(0x0f));
		r = packet(in);
		assertEquals(SftpConstants.SSH_FXP_ATTRS, r.getByte());
		assertEquals(2, r.getInt());
		SftpAttrs root = SftpAttrs.read(r, 5);
		assertTrue(root.isDirectory(), root.toString());
		assertEquals(SftpAttrs.TYPE_DIRECTORY, root.getType());
		// version-select only as the first request
		packet(out, new us.bringardner.parley.ssh.SshBuffer().putByte(SftpConstants.SSH_FXP_EXTENDED).putInt(3)
				.putString(SftpConstants.EXT_VERSION_SELECT).putString("6"));
		r = packet(in);
		assertEquals(SftpConstants.SSH_FXP_STATUS, r.getByte());
		r.getInt();
		assertEquals(SftpConstants.SSH_FX_OP_UNSUPPORTED, r.getInt(), "not first: an unknown extension");
		ch.close();
	}

	/** Our client with our server at each version */
	@Test
	public void ourClientAtEachVersion() throws Exception {
		File root = startOnDisk();
		client = new SshClient();
		client.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
		ClientSession s = client.connectAndWait("localhost", server.getLocalPort());
		s.authenticateAndWait("alice", new PasswordAuth("secret"));
		for (int v = 3; v <= 6; v++) {
			try (SftpClient sftp = SftpClient.open(s, v)) {
				us.bringardner.parley.ssh.sftp.SftpVersionCheck.roundTrip(sftp, "/ours"+v, v, true);
			}
			assertFalse(new File(root, "ours"+v).exists());
		}
	}

	/** MINA's SFTP client at each version (it speaks 3 to 6; it asks for 6 by default) */
	@Test
	public void minaSftpClient() throws Exception {
		File root = startOnDisk();
		org.apache.sshd.client.SshClient c = org.apache.sshd.client.SshClient.setUpDefaultClient();
		c.setServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE);
		c.start();
		try (org.apache.sshd.client.session.ClientSession s = c.connect("alice", "localhost", server.getLocalPort()).verify(Duration.ofSeconds(15)).getSession()) {
			s.addPasswordIdentity("secret");
			s.auth().verify(Duration.ofSeconds(15));
			try (org.apache.sshd.sftp.client.SftpClient sftp = SftpClientFactory.instance().createSftpClient(s)) {
				assertEquals(6, sftp.getVersion(), "the highest both speak");
			}
			for (int v = 3; v <= 6; v++) {
				try (org.apache.sshd.sftp.client.SftpClient sftp = SftpClientFactory.instance().createSftpClient(s,
						org.apache.sshd.sftp.client.SftpVersionSelector.fixedVersionSelector(v))) {
					assertEquals(v, sftp.getVersion());
					try {
						minaRoundTrip(sftp, root, "/mina"+v, v);
					} catch (java.io.IOException e) {
						throw new AssertionError("version "+v+": "+e, e);
					}
				}
				assertFalse(new File(root, "mina"+v).exists());
			}
		} finally {
			c.stop();
		}
	}

	private static void minaRoundTrip(org.apache.sshd.sftp.client.SftpClient sftp, File root, String dir, int v) throws Exception {
		String at = "version "+v+": ";
		sftp.mkdir(dir);
		byte[] data = new byte[1024*1024+17];
		new Random(3+v).nextBytes(data);
		try (OutputStream out = sftp.write(dir+"/f.bin")) {
			out.write(data);
		}
		try (InputStream in = sftp.read(dir+"/f.bin")) {
			assertArrayEquals(data, in.readAllBytes(), at+"read back");
		}
		org.apache.sshd.sftp.client.SftpClient.Attributes a = sftp.stat(dir+"/f.bin");
		assertEquals(data.length, a.getSize(), at);
		assertTrue(a.isRegularFile(), at+a);
		assertTrue(sftp.stat(dir).isDirectory(), at);
		if( v >= 4 ) {
			assertNotNull(a.getOwner(), at+"owner names in the attributes");
		}
		// Setting times (version 3 sets both or neither; MINA sends whole seconds)
		long when = 1_600_000_000_000L;
		sftp.setStat(dir+"/f.bin", new org.apache.sshd.sftp.client.SftpClient.Attributes()
				.accessTime(java.nio.file.attribute.FileTime.fromMillis(when)).modifyTime(java.nio.file.attribute.FileTime.fromMillis(when)));
		assertEquals(when, sftp.stat(dir+"/f.bin").getModifyTime().toMillis(), at+"mtime");
		// The server sends milliseconds from version 4, whole seconds to 3
		assertTrue(new File(root, dir.substring(1)+"/f.bin").setLastModified(when+123));
		assertEquals(v >= 4 ? when+123 : when, sftp.stat(dir+"/f.bin").getModifyTime().toMillis(), at+"subsecond mtime");

		// Exclusive create of an existing file: FILE_ALREADY_EXISTS from 4, FAILURE in 3
		org.apache.sshd.sftp.common.SftpException e = assertThrows(org.apache.sshd.sftp.common.SftpException.class,
				() -> sftp.open(dir+"/f.bin", org.apache.sshd.sftp.client.SftpClient.OpenMode.Write,
						org.apache.sshd.sftp.client.SftpClient.OpenMode.Create, org.apache.sshd.sftp.client.SftpClient.OpenMode.Exclusive).close());
		assertEquals(v >= 4 ? SftpConstants.SSH_FX_FILE_ALREADY_EXISTS : SftpConstants.SSH_FX_FAILURE, e.getStatus(), at);

		// Append (version 5+ sends it as a flag of its own)
		try (OutputStream out = sftp.write(dir+"/f.bin", org.apache.sshd.sftp.client.SftpClient.OpenMode.Write,
				org.apache.sshd.sftp.client.SftpClient.OpenMode.Append)) {
			out.write(new byte[] {1, 2, 3});
		}
		assertEquals(data.length+3, sftp.stat(dir+"/f.bin").getSize(), at+"appended");

		// Links: SYMLINK for 3 to 5, LINK for 6
		sftp.symLink(dir+"/link", dir+"/f.bin");
		assertTrue(sftp.lstat(dir+"/link").isSymbolicLink(), at+"a symbolic link");
		assertEquals(dir+"/f.bin", sftp.readLink(dir+"/link"), at);
		if( v >= 6 ) {
			sftp.link(dir+"/hard", dir+"/f.bin", false);
			assertEquals(data.length+3, sftp.stat(dir+"/hard").getSize(), at+"hard link");
			sftp.remove(dir+"/hard");
		}

		int n = 0;
		for (org.apache.sshd.sftp.client.SftpClient.DirEntry de : sftp.readDir(dir)) {
			n++;
			if( de.getFilename().equals("f.bin") ) {
				assertEquals(data.length+3, de.getAttributes().getSize(), at);
			}
		}
		assertEquals(4, n, at+". .. f.bin link");

		// Rename over an existing file: only with overwrite (a flag from version 5)
		try (OutputStream out = sftp.write(dir+"/g.bin")) {
			out.write(1);
		}
		assertThrows(org.apache.sshd.sftp.common.SftpException.class, () -> sftp.rename(dir+"/f.bin", dir+"/g.bin"), at);
		if( v >= 5 ) {
			sftp.rename(dir+"/f.bin", dir+"/g.bin", org.apache.sshd.sftp.client.SftpClient.CopyMode.Overwrite);
			assertEquals(data.length+3, sftp.stat(dir+"/g.bin").getSize(), at+"replaced");
		} else {
			sftp.remove(dir+"/f.bin");
		}
		org.apache.sshd.sftp.common.SftpException notEmpty = assertThrows(org.apache.sshd.sftp.common.SftpException.class, () -> sftp.rmdir(dir));
		assertEquals(v >= 6 ? SftpConstants.SSH_FX_DIR_NOT_EMPTY : SftpConstants.SSH_FX_FAILURE, notEmpty.getStatus(), at);
		sftp.remove(dir+"/g.bin");
		sftp.remove(dir+"/link");
		sftp.rmdir(dir);
	}

	@Test
	public void jschSftpClient() throws Exception {
		File root = startOnDisk();
		Session s = new JSch().getSession("alice", "localhost", server.getLocalPort());
		s.setPassword("secret");
		s.setConfig("StrictHostKeyChecking", "no");
		s.connect(15000);
		try {
			ChannelSftp sftp = (ChannelSftp) s.openChannel("sftp");
			sftp.connect(10000);
			assertEquals("/", sftp.pwd());
			sftp.mkdir("jsch");
			byte[] data = new byte[2*1024*1024+3];
			new Random(4).nextBytes(data);
			sftp.put(new ByteArrayInputStream(data), "jsch/f.bin");
			ByteArrayOutputStream got = new ByteArrayOutputStream();
			sftp.get("jsch/f.bin", got);
			assertArrayEquals(data, got.toByteArray());
			assertArrayEquals(data, Files.readAllBytes(new File(root, "jsch/f.bin").toPath()));
			Vector<?> ls = sftp.ls("jsch");
			assertEquals(3, ls.size());
			sftp.rename("jsch/f.bin", "jsch/g.bin");
			sftp.chmod(0600, "jsch/g.bin");
			assertEquals(0600, sftp.stat("jsch/g.bin").getPermissions() & 0777);
			sftp.rm("jsch/g.bin");
			sftp.rmdir("jsch");
			sftp.disconnect();
		} finally {
			s.disconnect();
		}
		assertFalse(new File(root, "jsch").exists());
	}
}
