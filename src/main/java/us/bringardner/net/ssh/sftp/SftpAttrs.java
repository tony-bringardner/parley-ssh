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
package us.bringardner.net.ssh.sftp;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import us.bringardner.net.ssh.SshBuffer;
import us.bringardner.net.ssh.SshException;

/**
 * SFTP version 3 file attributes (draft 02, 5): each field is present or not, as the flags
 * say. For SETSTAT only the fields that are set are sent, so the others don't change.
 * Immutable; the with... methods return a copy.
 *
 * @author Tony Bringardner
 */
public final class SftpAttrs {

	private static final int S_IFMT = 0170000;
	private static final int S_IFDIR = 0040000;
	private static final int S_IFLNK = 0120000;
	private static final int S_IFREG = 0100000;

	/** No attributes (nothing changes when sent) */
	public static final SftpAttrs NONE = new SftpAttrs(0, 0, 0, 0, 0, 0, 0, Collections.<String, String>emptyMap());

	private final int flags;
	private final long size;
	private final int uid;
	private final int gid;
	private final int permissions;
	private final long atime;
	private final long mtime;
	private final Map<String, String> extended;

	private SftpAttrs(int flags, long size, int uid, int gid, int permissions, long atime, long mtime, Map<String, String> extended) {
		this.flags = flags;
		this.size = size;
		this.uid = uid;
		this.gid = gid;
		this.permissions = permissions;
		this.atime = atime;
		this.mtime = mtime;
		this.extended = extended;
	}

	public static SftpAttrs read(SshBuffer b) throws SshException {
		int flags = (int) b.getUInt();
		long size = 0;
		int uid = 0, gid = 0, perms = 0;
		long atime = 0, mtime = 0;
		Map<String, String> ext = Collections.emptyMap();
		if( (flags & SftpConstants.SSH_FILEXFER_ATTR_SIZE) != 0 ) {
			size = b.getLong();
		}
		if( (flags & SftpConstants.SSH_FILEXFER_ATTR_UIDGID) != 0 ) {
			uid = (int) b.getUInt();
			gid = (int) b.getUInt();
		}
		if( (flags & SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS) != 0 ) {
			perms = (int) b.getUInt();
		}
		if( (flags & SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME) != 0 ) {
			atime = b.getUInt();
			mtime = b.getUInt();
		}
		if( (flags & SftpConstants.SSH_FILEXFER_ATTR_EXTENDED) != 0 ) {
			long n = b.getUInt();
			if( n > 1000 ) {
				throw new SshException("Too many extended attributes");
			}
			ext = new LinkedHashMap<String, String>();
			for (long i = 0; i < n; i++) {
				ext.put(b.getStringUtf8(), b.getStringUtf8());
			}
			ext = Collections.unmodifiableMap(ext);
		}
		return new SftpAttrs(flags, size, uid, gid, perms, atime, mtime, ext);
	}

	public SshBuffer write(SshBuffer b) {
		int f = flags & ~SftpConstants.SSH_FILEXFER_ATTR_EXTENDED;
		if( !extended.isEmpty() ) {
			f |= SftpConstants.SSH_FILEXFER_ATTR_EXTENDED;
		}
		b.putInt(f);
		if( (f & SftpConstants.SSH_FILEXFER_ATTR_SIZE) != 0 ) {
			b.putLong(size);
		}
		if( (f & SftpConstants.SSH_FILEXFER_ATTR_UIDGID) != 0 ) {
			b.putInt(uid & 0xffffffffL).putInt(gid & 0xffffffffL);
		}
		if( (f & SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS) != 0 ) {
			b.putInt(permissions & 0xffffffffL);
		}
		if( (f & SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME) != 0 ) {
			b.putInt(atime).putInt(mtime);
		}
		if( !extended.isEmpty() ) {
			b.putInt(extended.size());
			for (Map.Entry<String, String> e : extended.entrySet()) {
				b.putString(e.getKey()).putString(e.getValue());
			}
		}
		return b;
	}

	// ------------------------------------------------------------------ builders

	public SftpAttrs withSize(long size) {
		return new SftpAttrs(flags | SftpConstants.SSH_FILEXFER_ATTR_SIZE, size, uid, gid, permissions, atime, mtime, extended);
	}

	public SftpAttrs withOwner(int uid, int gid) {
		return new SftpAttrs(flags | SftpConstants.SSH_FILEXFER_ATTR_UIDGID, size, uid, gid, permissions, atime, mtime, extended);
	}

	/**
	 * @param permissions mode bits (the file type bits are ignored by servers)
	 */
	public SftpAttrs withPermissions(int permissions) {
		return new SftpAttrs(flags | SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS, size, uid, gid, permissions, atime, mtime, extended);
	}

	/**
	 * @param atime seconds since 1970
	 * @param mtime seconds since 1970
	 */
	public SftpAttrs withTimes(long atime, long mtime) {
		return new SftpAttrs(flags | SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME, size, uid, gid, permissions, atime, mtime, extended);
	}

	// ------------------------------------------------------------------ getters

	public int getFlags() {
		return flags;
	}

	public boolean hasSize() {
		return (flags & SftpConstants.SSH_FILEXFER_ATTR_SIZE) != 0;
	}

	public boolean hasOwner() {
		return (flags & SftpConstants.SSH_FILEXFER_ATTR_UIDGID) != 0;
	}

	public boolean hasPermissions() {
		return (flags & SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS) != 0;
	}

	public boolean hasTimes() {
		return (flags & SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME) != 0;
	}

	public long getSize() {
		return size;
	}

	public int getUid() {
		return uid;
	}

	public int getGid() {
		return gid;
	}

	/**
	 * @return st_mode: file type and permission bits
	 */
	public int getPermissions() {
		return permissions;
	}

	/** Seconds since 1970 */
	public long getAccessTime() {
		return atime;
	}

	/** Seconds since 1970 */
	public long getModifyTime() {
		return mtime;
	}

	public Map<String, String> getExtended() {
		return extended;
	}

	public boolean isDirectory() {
		return (permissions & S_IFMT) == S_IFDIR;
	}

	public boolean isRegularFile() {
		return (permissions & S_IFMT) == S_IFREG;
	}

	public boolean isSymbolicLink() {
		return (permissions & S_IFMT) == S_IFLNK;
	}

	@Override
	public String toString() {
		return "SftpAttrs[size="+(hasSize() ? size : "-")+" uid="+(hasOwner() ? uid+"/"+gid : "-")
				+" mode="+(hasPermissions() ? Integer.toOctalString(permissions) : "-")+" mtime="+(hasTimes() ? mtime : "-")+"]";
	}
}
