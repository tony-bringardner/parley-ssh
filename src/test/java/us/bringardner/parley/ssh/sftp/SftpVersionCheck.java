package us.bringardner.parley.ssh.sftp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * What our client does at an SFTP version, against any server: the same calls work at
 * every version (they are sent as each version wants them).
 */
public final class SftpVersionCheck {

	private SftpVersionCheck() {
	}

	/**
	 * @param exactCodes true to check the status codes too (our server's choice of codes)
	 */
	public static void roundTrip(SftpClient sftp, String dir, int v, boolean exactCodes) throws Exception {
		String at = "version "+v+": ";
		assertEquals(v, sftp.getServerVersion(), at);
		sftp.mkdir(dir);
		assertTrue(sftp.stat(dir).isDirectory(), at);

		byte[] data = new byte[512*1024+5];
		new Random(10+v).nextBytes(data);
		try (OutputStream out = sftp.write(dir+"/f.bin", false)) {
			out.write(data);
		}
		try (InputStream in = sftp.read(dir+"/f.bin", 0)) {
			assertArrayEquals(data, in.readAllBytes(), at+"read back");
		}
		SftpAttrs a = sftp.stat(dir+"/f.bin");
		assertEquals(data.length, a.getSize(), at);
		assertTrue(a.isRegularFile(), at+a);
		if( v >= 4 ) {
			assertTrue(a.hasOwnerNames(), at+"owner names: "+a);
			assertNotNull(a.getOwner(), at);
		}

		// Times
		sftp.setStat(dir+"/f.bin", SftpAttrs.NONE.withTimes(1_600_000_000L, 1_600_000_100L));
		assertEquals(1_600_000_100L, sftp.stat(dir+"/f.bin").getModifyTime(), at+"mtime");

		// Append (version 5+ says it in the open flags)
		try (OutputStream out = sftp.write(dir+"/f.bin", true)) {
			out.write(new byte[] {7, 8, 9});
		}
		assertEquals(data.length+3, sftp.stat(dir+"/f.bin").getSize(), at+"appended");

		// Create exclusively: refused for a file that exists
		SftpException e = assertThrows(SftpException.class, () -> sftp.open(dir+"/f.bin",
				SftpConstants.SSH_FXF_WRITE | SftpConstants.SSH_FXF_CREAT | SftpConstants.SSH_FXF_EXCL, SftpAttrs.NONE).close());
		if( exactCodes ) {
			assertEquals(v >= 4 ? SftpConstants.SSH_FX_FILE_ALREADY_EXISTS : SftpConstants.SSH_FX_FAILURE, e.getStatus(), at);
		}
		// Truncate an existing file (version 5+: TRUNCATE_EXISTING)
		sftp.open(dir+"/f.bin", SftpConstants.SSH_FXF_WRITE | SftpConstants.SSH_FXF_TRUNC, SftpAttrs.NONE).close();
		assertEquals(0, sftp.stat(dir+"/f.bin").getSize(), at+"truncated");
		try (OutputStream out = sftp.write(dir+"/f.bin", false)) {
			out.write(data);
		}

		// Links: SYMLINK, or LINK in version 6
		sftp.symlink(dir+"/f.bin", dir+"/link");
		assertTrue(sftp.lstat(dir+"/link").isSymbolicLink(), at);
		assertEquals(data.length, sftp.stat(dir+"/link").getSize(), at+"followed");
		assertTrue(sftp.readlink(dir+"/link").endsWith("/f.bin"), at+sftp.readlink(dir+"/link"));
		boolean hard = sftp.hasExtension(SftpConstants.EXT_HARDLINK) || v >= 6;
		if( hard ) {
			sftp.hardlink(dir+"/f.bin", dir+"/hard");
			assertEquals(data.length, sftp.stat(dir+"/hard").getSize(), at+"hard link");
		}

		// Listing: version 4+ has no long names, the client makes them
		List<String> names = new ArrayList<String>();
		for (SftpDirEntry d : sftp.list(dir)) {
			names.add(d.getName());
			assertFalse(d.getLongName().isEmpty(), at);
			if( d.getName().equals("f.bin") ) {
				assertEquals(data.length, d.getAttrs().getSize(), at);
				assertTrue(d.getLongName().startsWith("-"), at+d.getLongName());
				assertTrue(d.getLongName().endsWith(" f.bin"), at+d.getLongName());
			}
		}
		assertTrue(names.contains("f.bin") && names.contains("link"), at+names);

		// Rename: refused over an existing file; posixRename replaces it
		try (OutputStream out = sftp.write(dir+"/g.bin", false)) {
			out.write(1);
		}
		assertThrows(SftpException.class, () -> sftp.rename(dir+"/g.bin", dir+"/f.bin"), at);
		sftp.rename(dir+"/g.bin", dir+"/h.bin");
		if( sftp.hasExtension(SftpConstants.EXT_POSIX_RENAME) || v >= 5 ) {
			sftp.posixRename(dir+"/h.bin", dir+"/f.bin");
			assertEquals(1, sftp.stat(dir+"/f.bin").getSize(), at+"replaced");
		} else {
			sftp.remove(dir+"/h.bin");
		}

		SftpException notEmpty = assertThrows(SftpException.class, () -> sftp.rmdir(dir));
		if( exactCodes ) {
			assertEquals(v >= 6 ? SftpConstants.SSH_FX_DIR_NOT_EMPTY : SftpConstants.SSH_FX_FAILURE, notEmpty.getStatus(), at);
		}
		SftpException missing = assertThrows(SftpException.class, () -> sftp.stat(dir+"/nothing"));
		assertEquals(SftpConstants.SSH_FX_NO_SUCH_FILE, missing.getStatus(), at);
		sftp.remove(dir+"/link");
		if( hard ) {
			sftp.remove(dir+"/hard");
		}
		sftp.remove(dir+"/f.bin");
		sftp.rmdir(dir);
	}
}
