/**
 * <PRE>
 * 
 * Copyright Tony Bringardner 1998, 2026 <A href="http://bringardner.com/tony">Tony Bringardner</A>
 * 
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       <A href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</A>
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *  </PRE>
 *   
 *   
 *	@author Tony Bringardner   
 *
 *
 * ~version~V000.00.01-V000.00.00-
 */
package us.bringardner.net.ssh.sftp.server;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.AccessDeniedException;
import java.nio.file.NoSuchFileException;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.UserPrincipal;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import us.bringardner.io.filesource.FileSource;
import us.bringardner.io.filesource.IRandomAccessStream;
import us.bringardner.net.ssh.SshBuffer;
import us.bringardner.net.ssh.server.AbstractCommand;
import us.bringardner.net.ssh.server.CommandEnvironment;
import us.bringardner.net.ssh.sftp.SftpAttrs;
import us.bringardner.net.ssh.sftp.SftpConstants;

/**
 * One SFTP version 3 session (draft-ietf-secsh-filexfer-02 as OpenSSH implements it, with
 * OpenSSH's posix-rename, hardlink and fsync extensions) on a {@link FileSource} root.
 * <p>
 * The client sees the root as "/" (also its login directory). Every path is checked with
 * {@link FileSource#isChildOfMine(FileSource)}, which resolves symbolic links, so nothing
 * outside the root can be read, written or listed. Operations on a link itself (lstat,
 * remove, rename, readlink) check its directory instead, so a link that points outside can
 * still be seen and removed but not followed. Error messages don't show real paths.
 * <p>
 * Requests are answered in order on one thread, which is what SFTP clients expect.
 *
 * @author Tony Bringardner
 */
public class SftpServer extends AbstractCommand {

	/** Largest request accepted (a 256 KB write and its header fit) */
	private static final int MAX_PACKET = 1024*1024;
	/** Most bytes one READ returns (OpenSSH's limit) */
	private static final int MAX_READ = 255*1024;
	private static final int MAX_HANDLES = 256;
	private static final int DIR_BATCH = 100;
	private static final int S_IFDIR = 0040000;
	private static final int S_IFREG = 0100000;
	private static final int S_IFLNK = 0120000;

	/** A status to send, with the message the client sees */
	private static final class Status extends IOException {
		private static final long serialVersionUID = 1L;
		final int code;

		Status(int code, String message) {
			super(message);
			this.code = code;
		}
	}

	private static final class FileHandle {
		final FileSource file;
		final IRandomAccessStream raf;
		final boolean writable;
		final boolean append;

		FileHandle(FileSource file, IRandomAccessStream raf, boolean writable, boolean append) {
			this.file = file;
			this.raf = raf;
			this.writable = writable;
			this.append = append;
		}
	}

	private static final class DirHandle {
		final FileSource dir;
		final Deque<FileSource> entries;
		boolean dotsSent;

		DirHandle(FileSource dir, Deque<FileSource> entries) {
			this.dir = dir;
			this.entries = entries;
		}
	}

	private final FileSource root;
	private final boolean readOnly;
	private final Map<String, Object> handles = new HashMap<String, Object>();
	private int nextHandle;
	private OutputStream out;

	public SftpServer(FileSource root, boolean readOnly) {
		this.root = root;
		this.readOnly = readOnly;
	}

	@Override
	protected int run(CommandEnvironment env, InputStream in, OutputStream out, OutputStream err) throws Exception {
		this.out = out;
		DataInputStream din = new DataInputStream(in);
		try {
			while( !isDestroyed() ) {
				int len;
				try {
					len = din.readInt();
				} catch (EOFException e) {
					return 0;
				}
				if( len < 1 || len > MAX_PACKET ) {
					logDebug("SFTP packet of "+len+" bytes, closing");
					return 1;
				}
				byte[] packet = new byte[len];
				din.readFully(packet);
				process(new SshBuffer(packet));
			}
			return 0;
		} finally {
			closeAll();
		}
	}

	private void closeAll() {
		for (Object h : handles.values()) {
			if( h instanceof FileHandle ) {
				try {
					((FileHandle) h).raf.close();
				} catch (IOException e) {
					// closing anyway
				}
			}
		}
		handles.clear();
	}

	// ------------------------------------------------------------------ dispatch

	private void process(SshBuffer p) throws IOException {
		int type = p.getByte();
		if( type == SftpConstants.SSH_FXP_INIT ) {
			p.getInt();
			SshBuffer b = new SshBuffer().putByte(SftpConstants.SSH_FXP_VERSION).putInt(SftpConstants.SFTP_VERSION);
			b.putString(SftpConstants.EXT_POSIX_RENAME).putString("1");
			b.putString(SftpConstants.EXT_HARDLINK).putString("1");
			b.putString(SftpConstants.EXT_FSYNC).putString("1");
			send(b);
			return;
		}
		int id = p.getInt();
		try {
			switch (type) {
			case SftpConstants.SSH_FXP_OPEN: open(id, p); break;
			case SftpConstants.SSH_FXP_CLOSE: close(id, p); break;
			case SftpConstants.SSH_FXP_READ: read(id, p); break;
			case SftpConstants.SSH_FXP_WRITE: write(id, p); break;
			case SftpConstants.SSH_FXP_STAT: attrs(id, attributes(followed(p.getStringUtf8()), true)); break;
			case SftpConstants.SSH_FXP_LSTAT: attrs(id, attributes(notFollowed(p.getStringUtf8()), false)); break;
			case SftpConstants.SSH_FXP_FSTAT: attrs(id, attributes(fileHandle(p.getString()).file, true)); break;
			case SftpConstants.SSH_FXP_SETSTAT: setStat(id, p); break;
			case SftpConstants.SSH_FXP_FSETSTAT: fsetStat(id, p); break;
			case SftpConstants.SSH_FXP_OPENDIR: openDir(id, p); break;
			case SftpConstants.SSH_FXP_READDIR: readDir(id, p); break;
			case SftpConstants.SSH_FXP_REMOVE: remove(id, p); break;
			case SftpConstants.SSH_FXP_MKDIR: mkdir(id, p); break;
			case SftpConstants.SSH_FXP_RMDIR: rmdir(id, p); break;
			case SftpConstants.SSH_FXP_REALPATH: realpath(id, p); break;
			case SftpConstants.SSH_FXP_RENAME: rename(id, p.getStringUtf8(), p.getStringUtf8(), false); break;
			case SftpConstants.SSH_FXP_READLINK: readlink(id, p); break;
			case SftpConstants.SSH_FXP_SYMLINK: symlink(id, p); break;
			case SftpConstants.SSH_FXP_EXTENDED: extended(id, p); break;
			default:
				status(id, SftpConstants.SSH_FX_OP_UNSUPPORTED, "Unsupported request "+type);
			}
		} catch (Status s) {
			status(id, s.code, s.getMessage());
		} catch (NoSuchFileException | FileNotFoundException e) {
			status(id, SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
		} catch (AccessDeniedException | SecurityException e) {
			status(id, SftpConstants.SSH_FX_PERMISSION_DENIED, "Permission denied");
		} catch (us.bringardner.net.ssh.SshException e) {
			status(id, SftpConstants.SSH_FX_BAD_MESSAGE, "Bad message");
		} catch (IOException | RuntimeException e) {
			// The message may hold real paths: logged, not sent
			logDebug("SFTP request "+type+" failed", e);
			status(id, SftpConstants.SSH_FX_FAILURE, "Failure");
		}
	}

	// ------------------------------------------------------------------ paths

	/**
	 * @return the path as the client sees it: absolute, "." and ".." resolved, never above "/"
	 */
	static String normalize(String path) {
		Deque<String> parts = new ArrayDeque<String>();
		for (String seg : path.replace('\\', '/').split("/")) {
			if( seg.isEmpty() || seg.equals(".") ) {
				continue;
			}
			if( seg.equals("..") ) {
				parts.pollLast();
			} else {
				parts.add(seg);
			}
		}
		return "/"+String.join("/", parts);
	}

	private FileSource resolve(String vpath) throws IOException {
		FileSource f = root;
		for (String seg : normalize(vpath).split("/")) {
			if( !seg.isEmpty() ) {
				f = f.getChild(seg);
			}
		}
		return f;
	}

	/**
	 * The path with links followed; it must be inside the root.
	 */
	private FileSource followed(String path) throws IOException {
		FileSource f = resolve(path);
		if( !root.isChildOfMine(f) ) {
			throw new Status(SftpConstants.SSH_FX_PERMISSION_DENIED, "Permission denied");
		}
		return f;
	}

	/**
	 * The path itself (a link is not followed); its directory must be inside the root.
	 */
	private FileSource notFollowed(String path) throws IOException {
		String n = normalize(path);
		if( n.equals("/") ) {
			return root;
		}
		int i = n.lastIndexOf('/');
		FileSource parent = followed(n.substring(0, Math.max(1, i)));
		return parent.getChild(n.substring(i+1));
	}

	private void writable() throws Status {
		if( readOnly ) {
			throw new Status(SftpConstants.SSH_FX_PERMISSION_DENIED, "Read-only");
		}
	}

	private static boolean isLink(FileSource f) {
		try {
			return f.getLinkedTo() != null;
		} catch (IOException | RuntimeException e) {
			return false;
		}
	}

	// ------------------------------------------------------------------ files

	private void open(int id, SshBuffer p) throws IOException {
		String path = p.getStringUtf8();
		int flags = (int) p.getUInt();
		SftpAttrs attrs = SftpAttrs.read(p);
		boolean write = (flags & (SftpConstants.SSH_FXF_WRITE | SftpConstants.SSH_FXF_APPEND)) != 0;
		boolean creat = (flags & SftpConstants.SSH_FXF_CREAT) != 0;
		if( write || creat || (flags & SftpConstants.SSH_FXF_TRUNC) != 0 ) {
			writable();
		}
		if( handles.size() >= MAX_HANDLES ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Too many open files");
		}
		FileSource f = followed(path);
		boolean exists = f.exists();
		if( exists && f.isDirectory() ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Is a directory");
		}
		if( !exists ) {
			if( !creat ) {
				throw new Status(SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
			}
			if( !f.createNewFile() && (flags & SftpConstants.SSH_FXF_EXCL) != 0 ) {
				throw new Status(SftpConstants.SSH_FX_FAILURE, "File exists");
			}
			if( attrs.hasPermissions() ) {
				setPermissions(f, attrs.getPermissions());
			}
		} else if( creat && (flags & SftpConstants.SSH_FXF_EXCL) != 0 ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "File exists");
		}
		IRandomAccessStream raf = f.getRandomAccessStream(write ? "rw" : "r");
		try {
			if( write && (flags & SftpConstants.SSH_FXF_TRUNC) != 0 ) {
				raf.setLength(0);
			}
		} catch (IOException | RuntimeException e) {
			raf.close();
			throw e;
		}
		handle(id, new FileHandle(f, raf, write, (flags & SftpConstants.SSH_FXF_APPEND) != 0));
	}

	private void read(int id, SshBuffer p) throws IOException {
		FileHandle h = fileHandle(p.getString());
		long offset = p.getLong();
		int len = (int) Math.min(p.getUInt(), MAX_READ);
		if( offset < 0 ) {
			throw new Status(SftpConstants.SSH_FX_BAD_MESSAGE, "Bad offset");
		}
		if( offset >= h.raf.length() ) {
			status(id, SftpConstants.SSH_FX_EOF, "End of file");
			return;
		}
		h.raf.seek(offset);
		byte[] buf = new byte[len];
		int n = 0;
		while( n < len ) {
			int k = h.raf.read(buf, n, len-n);
			if( k <= 0 ) {
				break;
			}
			n += k;
		}
		if( n == 0 ) {
			status(id, SftpConstants.SSH_FX_EOF, "End of file");
			return;
		}
		send(new SshBuffer(n+16).putByte(SftpConstants.SSH_FXP_DATA).putInt(id).putString(buf, 0, n));
	}

	private void write(int id, SshBuffer p) throws IOException {
		FileHandle h = fileHandle(p.getString());
		long offset = p.getLong();
		byte[] data = p.getString();
		if( !h.writable ) {
			throw new Status(SftpConstants.SSH_FX_PERMISSION_DENIED, "Not open for writing");
		}
		if( offset < 0 ) {
			throw new Status(SftpConstants.SSH_FX_BAD_MESSAGE, "Bad offset");
		}
		h.raf.seek(h.append ? h.raf.length() : offset);
		h.raf.write(data, 0, data.length);
		ok(id);
	}

	private void close(int id, SshBuffer p) throws IOException {
		Object h = handles.remove(new String(p.getString(), java.nio.charset.StandardCharsets.ISO_8859_1));
		if( h == null ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Bad handle");
		}
		if( h instanceof FileHandle ) {
			((FileHandle) h).raf.close();
		}
		ok(id);
	}

	private void setStat(int id, SshBuffer p) throws IOException {
		FileSource f = followed(p.getStringUtf8());
		SftpAttrs a = SftpAttrs.read(p);
		writable();
		if( !f.exists() ) {
			throw new Status(SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
		}
		apply(id, f, null, a);
	}

	private void fsetStat(int id, SshBuffer p) throws IOException {
		FileHandle h = fileHandle(p.getString());
		SftpAttrs a = SftpAttrs.read(p);
		writable();
		apply(id, h.file, h.raf, a);
	}

	private void apply(int id, FileSource f, IRandomAccessStream raf, SftpAttrs a) throws IOException {
		if( a.hasSize() ) {
			if( raf != null ) {
				raf.setLength(a.getSize());
			} else {
				try (IRandomAccessStream r = f.getRandomAccessStream("rw")) {
					r.setLength(a.getSize());
				}
			}
		}
		if( a.hasPermissions() ) {
			setPermissions(f, a.getPermissions());
		}
		if( a.hasTimes() ) {
			f.setLastAccessTime(a.getAccessTime()*1000);
			f.setLastModifiedTime(a.getModifyTime()*1000);
		}
		if( a.hasOwner() ) {
			// Numeric owners mean nothing to a FileSource
			throw new Status(SftpConstants.SSH_FX_OP_UNSUPPORTED, "Changing the owner is not supported");
		}
		ok(id);
	}

	private static void setPermissions(FileSource f, int mode) throws IOException {
		f.setOwnerReadable((mode & 0400) != 0);
		f.setOwnerWritable((mode & 0200) != 0);
		f.setOwnerExecutable((mode & 0100) != 0);
		f.setGroupReadable((mode & 0040) != 0);
		f.setGroupWritable((mode & 0020) != 0);
		f.setGroupExecutable((mode & 0010) != 0);
		f.setOtherReadable((mode & 0004) != 0);
		f.setOtherWritable((mode & 0002) != 0);
		f.setOtherExecutable((mode & 0001) != 0);
	}

	// ------------------------------------------------------------------ directories

	private void openDir(int id, SshBuffer p) throws IOException {
		FileSource d = followed(p.getStringUtf8());
		if( !d.exists() ) {
			throw new Status(SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
		}
		if( !d.isDirectory() ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Not a directory");
		}
		if( handles.size() >= MAX_HANDLES ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Too many open directories");
		}
		FileSource[] list = d.listFiles();
		if( list == null ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Can't list");
		}
		handle(id, new DirHandle(d, new ArrayDeque<FileSource>(Arrays.asList(list))));
	}

	private void readDir(int id, SshBuffer p) throws IOException {
		Object o = handles.get(new String(p.getString(), java.nio.charset.StandardCharsets.ISO_8859_1));
		if( !(o instanceof DirHandle) ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Bad handle");
		}
		DirHandle h = (DirHandle) o;
		List<Object[]> batch = new ArrayList<Object[]>();
		if( !h.dotsSent ) {
			h.dotsSent = true;
			SftpAttrs a = attributes(h.dir, true);
			batch.add(new Object[] {".", longName(".", h.dir, a), a});
			batch.add(new Object[] {"..", longName("..", h.dir, a), a});
		}
		while( batch.size() < DIR_BATCH && !h.entries.isEmpty() ) {
			FileSource e = h.entries.poll();
			try {
				SftpAttrs a = attributes(e, false);
				batch.add(new Object[] {e.getName(), longName(e.getName(), e, a), a});
			} catch (IOException | RuntimeException ex) {
				// gone or unreadable since the listing: left out
			}
		}
		if( batch.isEmpty() ) {
			status(id, SftpConstants.SSH_FX_EOF, "End of directory");
			return;
		}
		SshBuffer b = new SshBuffer().putByte(SftpConstants.SSH_FXP_NAME).putInt(id).putInt(batch.size());
		for (Object[] e : batch) {
			b.putString((String) e[0]).putString((String) e[1]);
			((SftpAttrs) e[2]).write(b);
		}
		send(b);
	}

	private void mkdir(int id, SshBuffer p) throws IOException {
		FileSource d = notFollowed(p.getStringUtf8());
		SftpAttrs a = SftpAttrs.read(p);
		writable();
		if( d.exists() || isLink(d) ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "File exists");
		}
		if( !d.mkdir() ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Can't create the directory");
		}
		if( a.hasPermissions() ) {
			setPermissions(d, a.getPermissions());
		}
		ok(id);
	}

	private void rmdir(int id, SshBuffer p) throws IOException {
		FileSource d = notFollowed(p.getStringUtf8());
		writable();
		if( d == root ) {
			throw new Status(SftpConstants.SSH_FX_PERMISSION_DENIED, "Permission denied");
		}
		if( !d.exists() ) {
			throw new Status(SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
		}
		if( !d.isDirectory() || isLink(d) ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Not a directory");
		}
		FileSource[] list = d.listFiles();
		if( list != null && list.length > 0 ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Directory not empty");
		}
		if( !d.delete() ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Can't remove the directory");
		}
		ok(id);
	}

	private void remove(int id, SshBuffer p) throws IOException {
		FileSource f = notFollowed(p.getStringUtf8());
		writable();
		boolean link = isLink(f);
		if( !link && !f.exists() ) {
			throw new Status(SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
		}
		if( !link && f.isDirectory() ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Is a directory");
		}
		if( !f.delete() ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Can't remove the file");
		}
		ok(id);
	}

	private void rename(int id, String from, String to, boolean replace) throws IOException {
		FileSource src = notFollowed(from);
		FileSource dst = notFollowed(to);
		writable();
		if( src == root || dst == root ) {
			throw new Status(SftpConstants.SSH_FX_PERMISSION_DENIED, "Permission denied");
		}
		if( !src.exists() && !isLink(src) ) {
			throw new Status(SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
		}
		boolean dstExists = dst.exists() || isLink(dst);
		if( dstExists && !replace ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "File exists");
		}
		if( !src.renameTo(dst) ) {
			if( !(replace && dstExists && !dst.isDirectory() && dst.delete() && src.renameTo(dst)) ) {
				throw new Status(SftpConstants.SSH_FX_FAILURE, "Can't rename");
			}
		}
		ok(id);
	}

	private void realpath(int id, SshBuffer p) throws IOException {
		String n = normalize(p.getStringUtf8());
		SshBuffer b = new SshBuffer().putByte(SftpConstants.SSH_FXP_NAME).putInt(id).putInt(1).putString(n).putString(n);
		SftpAttrs.NONE.write(b);
		send(b);
	}

	// ------------------------------------------------------------------ links

	private void readlink(int id, SshBuffer p) throws IOException {
		FileSource f = notFollowed(p.getStringUtf8());
		FileSource target = f.getLinkedTo();
		if( target == null ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Not a link");
		}
		String virtual = virtualPath(target);
		if( virtual == null ) {
			// Don't tell where outside the root it points
			throw new Status(SftpConstants.SSH_FX_PERMISSION_DENIED, "Permission denied");
		}
		SshBuffer b = new SshBuffer().putByte(SftpConstants.SSH_FXP_NAME).putInt(id).putInt(1).putString(virtual).putString(virtual);
		SftpAttrs.NONE.write(b);
		send(b);
	}

	/**
	 * @return the client's path for a file, or null if it isn't inside the root
	 */
	private String virtualPath(FileSource f) throws IOException {
		if( !root.isChildOfMine(f) ) {
			return null;
		}
		String r = root.getCanonicalPath();
		String c = f.getCanonicalPath();
		String rel = c.substring(r.length()).replace('\\', '/');
		return normalize(rel);
	}

	/**
	 * SSH_FXP_SYMLINK in OpenSSH's order: target first, then the link. The target must be
	 * inside the root.
	 */
	private void symlink(int id, SshBuffer p) throws IOException {
		String target = p.getStringUtf8();
		String linkPath = p.getStringUtf8();
		writable();
		FileSource link = notFollowed(linkPath);
		String n = normalize(linkPath);
		String vtarget = target.startsWith("/") ? target : n.substring(0, n.lastIndexOf('/')+1)+target;
		FileSource t = followed(vtarget);
		if( link.exists() || isLink(link) ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "File exists");
		}
		root.getFileSourceFactory().createSymbolicLink(link, t);
		ok(id);
	}

	private void extended(int id, SshBuffer p) throws IOException {
		String name = p.getStringUtf8();
		switch (name) {
		case SftpConstants.EXT_POSIX_RENAME:
			rename(id, p.getStringUtf8(), p.getStringUtf8(), true);
			return;
		case SftpConstants.EXT_HARDLINK: {
			FileSource existing = notFollowed(p.getStringUtf8());
			FileSource link = notFollowed(p.getStringUtf8());
			writable();
			if( !existing.exists() ) {
				throw new Status(SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
			}
			if( link.exists() ) {
				throw new Status(SftpConstants.SSH_FX_FAILURE, "File exists");
			}
			root.getFileSourceFactory().createLink(link, existing);
			ok(id);
			return;
		}
		case SftpConstants.EXT_FSYNC:
			fileHandle(p.getString());
			// Writes go straight to the FileSource; nothing is held back here
			ok(id);
			return;
		default:
			status(id, SftpConstants.SSH_FX_OP_UNSUPPORTED, "Unsupported extension "+name);
		}
	}

	// ------------------------------------------------------------------ attributes

	private SftpAttrs attributes(FileSource f, boolean follow) throws IOException {
		if( !follow && isLink(f) ) {
			long mtime = 0;
			try {
				mtime = f.lastModified()/1000;
			} catch (IOException | RuntimeException e) {
				// a dangling link
			}
			return SftpAttrs.NONE.withSize(0).withPermissions(S_IFLNK | 0777).withTimes(mtime, mtime);
		}
		if( !f.exists() ) {
			throw new Status(SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
		}
		boolean dir = f.isDirectory();
		int mode = (dir ? S_IFDIR : S_IFREG)
				| (f.canOwnerRead() ? 0400 : 0) | (f.canOwnerWrite() ? 0200 : 0) | (f.canOwnerExecute() ? 0100 : 0)
				| (f.canGroupRead() ? 0040 : 0) | (f.canGroupWrite() ? 0020 : 0) | (f.canGroupExecute() ? 0010 : 0)
				| (f.canOtherRead() ? 0004 : 0) | (f.canOtherWrite() ? 0002 : 0) | (f.canOtherExecute() ? 0001 : 0);
		long size = dir ? 0 : f.length();
		long mtime = f.lastModified()/1000;
		long atime = mtime;
		try {
			long a = f.lastAccessTime();
			if( a > 0 ) {
				atime = a/1000;
			}
		} catch (IOException | RuntimeException e) {
			// not every file system has it
		}
		return SftpAttrs.NONE.withSize(size).withPermissions(mode).withTimes(atime, mtime);
	}

	/**
	 * "ls -l" style: what version 3 clients show (it is the only place for owner and group names).
	 */
	private static String longName(String name, FileSource f, SftpAttrs a) {
		String owner = "-";
		String group = "-";
		try {
			UserPrincipal u = f.getOwner();
			if( u != null ) {
				owner = u.getName();
			}
			GroupPrincipal g = f.getGroup();
			if( g != null ) {
				group = g.getName();
			}
		} catch (IOException | RuntimeException e) {
			// not known
		}
		int m = a.getPermissions();
		StringBuilder perms = new StringBuilder();
		int type = m & 0170000;
		perms.append(type == S_IFDIR ? 'd' : type == S_IFLNK ? 'l' : '-');
		String rwx = "rwxrwxrwx";
		for (int i = 0; i < 9; i++) {
			perms.append((m & (0400 >> i)) != 0 ? rwx.charAt(i) : '-');
		}
		long mtime = a.getModifyTime()*1000;
		boolean recent = Math.abs(System.currentTimeMillis()-mtime) < 180L*24*60*60*1000;
		String date = new SimpleDateFormat(recent ? "MMM dd HH:mm" : "MMM dd  yyyy", Locale.US).format(new Date(mtime));
		return String.format(Locale.US, "%s %3d %-8s %-8s %8d %s %s", perms, 1, owner, group, a.getSize(), date, name);
	}

	// ------------------------------------------------------------------ replies

	private FileHandle fileHandle(byte[] id) throws Status {
		Object h = handles.get(new String(id, java.nio.charset.StandardCharsets.ISO_8859_1));
		if( !(h instanceof FileHandle) ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Bad handle");
		}
		return (FileHandle) h;
	}

	private void handle(int id, Object h) throws IOException {
		String key = Integer.toString(nextHandle++);
		handles.put(key, h);
		send(new SshBuffer().putByte(SftpConstants.SSH_FXP_HANDLE).putInt(id).putString(key.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)));
	}

	private void attrs(int id, SftpAttrs a) throws IOException {
		send(a.write(new SshBuffer().putByte(SftpConstants.SSH_FXP_ATTRS).putInt(id)));
	}

	private void ok(int id) throws IOException {
		status(id, SftpConstants.SSH_FX_OK, "");
	}

	private void status(int id, int code, String message) throws IOException {
		send(new SshBuffer().putByte(SftpConstants.SSH_FXP_STATUS).putInt(id).putInt(code).putString(message).putString(""));
	}

	private void send(SshBuffer payload) throws IOException {
		int len = payload.available();
		byte[] head = {(byte) (len >>> 24), (byte) (len >>> 16), (byte) (len >>> 8), (byte) len};
		// One write per packet, so header and body go out together
		byte[] packet = new byte[4+len];
		System.arraycopy(head, 0, packet, 0, 4);
		System.arraycopy(payload.array(), payload.readPosition(), packet, 4, len);
		out.write(packet);
	}
}
