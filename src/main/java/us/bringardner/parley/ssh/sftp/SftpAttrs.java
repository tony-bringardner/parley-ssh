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
package us.bringardner.parley.ssh.sftp;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshException;

/**
 * SFTP file attributes, as each version sends them: version 3 (draft 02, 5) and versions 4
 * to 6 (drafts 04, 05 and 13, 7), which add the file type, owner and group as names,
 * 64-bit times with nanoseconds, the creation time and more. Each field is present or not;
 * for SETSTAT only the fields that are set are sent, so the others don't change.
 * <p>
 * The same object works with every version: {@link #getPermissions()} always has the file
 * type bits (version 4+ sends the type separately), and owner names that are numbers are
 * also uid/gid. Immutable; the with... methods return a copy.
 *
 * @author Tony Bringardner
 */
public final class SftpAttrs {

	private static final int S_IFMT = 0170000;
	private static final int S_IFSOCK = 0140000;
	private static final int S_IFLNK = 0120000;
	private static final int S_IFREG = 0100000;
	private static final int S_IFBLK = 0060000;
	private static final int S_IFDIR = 0040000;
	private static final int S_IFCHR = 0020000;
	private static final int S_IFIFO = 0010000;

	/** Version 4+ file types */
	public static final int TYPE_REGULAR = 1;
	public static final int TYPE_DIRECTORY = 2;
	public static final int TYPE_SYMLINK = 3;
	public static final int TYPE_SPECIAL = 4;
	public static final int TYPE_UNKNOWN = 5;
	public static final int TYPE_SOCKET = 6;
	public static final int TYPE_CHAR_DEVICE = 7;
	public static final int TYPE_BLOCK_DEVICE = 8;
	public static final int TYPE_FIFO = 9;

	// Version 4+ attribute flags
	private static final int V4_SIZE = 0x00000001;
	private static final int V4_PERMISSIONS = 0x00000004;
	private static final int V4_ACCESSTIME = 0x00000008;
	private static final int V4_CREATETIME = 0x00000010;
	private static final int V4_MODIFYTIME = 0x00000020;
	private static final int V4_ACL = 0x00000040;
	private static final int V4_OWNERGROUP = 0x00000080;
	private static final int V4_SUBSECOND_TIMES = 0x00000100;
	private static final int V5_BITS = 0x00000200;
	private static final int V6_ALLOCATION_SIZE = 0x00000400;
	private static final int V6_TEXT_HINT = 0x00000800;
	private static final int V6_MIME_TYPE = 0x00001000;
	private static final int V6_LINK_COUNT = 0x00002000;
	private static final int V6_UNTRANSLATED_NAME = 0x00004000;
	private static final int V6_CTIME = 0x00008000;
	private static final int EXTENDED = 0x80000000;

	// Which fields are set
	private static final int F_SIZE = 0x01;
	private static final int F_UIDGID = 0x02;
	private static final int F_PERMISSIONS = 0x04;
	private static final int F_ATIME = 0x08;
	private static final int F_MTIME = 0x10;
	private static final int F_NAMES = 0x20;
	private static final int F_CREATETIME = 0x40;
	private static final int F_NANOS = 0x80;
	private static final int F_LINKS = 0x100;
	// The file type is known (from version 4+'s type byte), without the permissions
	private static final int F_TYPE = 0x200;

	/** No attributes (nothing changes when sent) */
	public static final SftpAttrs NONE = new Builder().build();

	private final int fields;
	private final long size;
	private final int uid;
	private final int gid;
	private final String owner;
	private final String group;
	private final int permissions;
	private final long atime;
	private final int atimeNanos;
	private final long mtime;
	private final int mtimeNanos;
	private final long createTime;
	private final int createNanos;
	private final int linkCount;
	private final Map<String, String> extended;

	private SftpAttrs(Builder b) {
		this.fields = b.fields;
		this.size = b.size;
		this.uid = b.uid;
		this.gid = b.gid;
		this.owner = b.owner;
		this.group = b.group;
		this.permissions = b.permissions;
		this.atime = b.atime;
		this.atimeNanos = b.atimeNanos;
		this.mtime = b.mtime;
		this.mtimeNanos = b.mtimeNanos;
		this.createTime = b.createTime;
		this.createNanos = b.createNanos;
		this.linkCount = b.linkCount;
		this.extended = b.extended;
	}

	private static final class Builder {
		int fields;
		long size;
		int uid;
		int gid;
		String owner;
		String group;
		int permissions;
		long atime;
		int atimeNanos;
		long mtime;
		int mtimeNanos;
		long createTime;
		int createNanos;
		int linkCount;
		Map<String, String> extended = Collections.emptyMap();

		Builder() {
		}

		Builder(SftpAttrs a) {
			fields = a.fields;
			size = a.size;
			uid = a.uid;
			gid = a.gid;
			owner = a.owner;
			group = a.group;
			permissions = a.permissions;
			atime = a.atime;
			atimeNanos = a.atimeNanos;
			mtime = a.mtime;
			mtimeNanos = a.mtimeNanos;
			createTime = a.createTime;
			createNanos = a.createNanos;
			linkCount = a.linkCount;
			extended = a.extended;
		}

		SftpAttrs build() {
			return new SftpAttrs(this);
		}
	}

	// ------------------------------------------------------------------ reading

	/**
	 * @return version 3 attributes
	 */
	public static SftpAttrs read(SshBuffer b) throws SshException {
		return read(b, 3);
	}

	/**
	 * @param version the session's SFTP version, 3 to 6
	 */
	public static SftpAttrs read(SshBuffer b, int version) throws SshException {
		Builder r = new Builder();
		int flags = (int) b.getUInt();
		if( version <= 3 ) {
			if( (flags & SftpConstants.SSH_FILEXFER_ATTR_SIZE) != 0 ) {
				r.fields |= F_SIZE;
				r.size = b.getLong();
			}
			if( (flags & SftpConstants.SSH_FILEXFER_ATTR_UIDGID) != 0 ) {
				r.fields |= F_UIDGID;
				r.uid = (int) b.getUInt();
				r.gid = (int) b.getUInt();
			}
			if( (flags & SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS) != 0 ) {
				r.fields |= F_PERMISSIONS;
				r.permissions = (int) b.getUInt();
			}
			if( (flags & SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME) != 0 ) {
				r.fields |= F_ATIME | F_MTIME;
				r.atime = b.getUInt();
				r.mtime = b.getUInt();
			}
		} else {
			int type = b.getByte();
			if( (flags & V4_SIZE) != 0 ) {
				r.fields |= F_SIZE;
				r.size = b.getLong();
			}
			if( version >= 6 && (flags & V6_ALLOCATION_SIZE) != 0 ) {
				b.getLong();
			}
			if( (flags & V4_OWNERGROUP) != 0 ) {
				r.fields |= F_NAMES;
				r.owner = b.getStringUtf8();
				r.group = b.getStringUtf8();
				// Numeric names are uid and gid (as OpenSSH-style servers send them)
				if( r.owner.matches("[0-9]{1,10}") && r.group.matches("[0-9]{1,10}") ) {
					r.fields |= F_UIDGID;
					r.uid = (int) Long.parseLong(r.owner);
					r.gid = (int) Long.parseLong(r.group);
				}
			}
			int perms = 0;
			if( (flags & V4_PERMISSIONS) != 0 ) {
				perms = (int) b.getUInt();
			}
			boolean nanos = (flags & V4_SUBSECOND_TIMES) != 0;
			if( nanos ) {
				r.fields |= F_NANOS;
			}
			if( (flags & V4_ACCESSTIME) != 0 ) {
				r.fields |= F_ATIME;
				r.atime = b.getLong();
				r.atimeNanos = nanos ? b.getInt() : 0;
			}
			if( (flags & V4_CREATETIME) != 0 ) {
				r.fields |= F_CREATETIME;
				r.createTime = b.getLong();
				r.createNanos = nanos ? b.getInt() : 0;
			}
			if( (flags & V4_MODIFYTIME) != 0 ) {
				r.fields |= F_MTIME;
				r.mtime = b.getLong();
				r.mtimeNanos = nanos ? b.getInt() : 0;
			}
			if( version >= 6 && (flags & V6_CTIME) != 0 ) {
				b.getLong();
				if( nanos ) {
					b.getInt();
				}
			}
			if( (flags & V4_ACL) != 0 ) {
				b.getString();
			}
			if( version >= 5 && (flags & V5_BITS) != 0 ) {
				b.getInt();
				if( version >= 6 ) {
					b.getInt();
				}
			}
			if( version >= 6 ) {
				if( (flags & V6_TEXT_HINT) != 0 ) {
					b.getByte();
				}
				if( (flags & V6_MIME_TYPE) != 0 ) {
					b.getString();
				}
				if( (flags & V6_LINK_COUNT) != 0 ) {
					r.fields |= F_LINKS;
					r.linkCount = b.getInt();
				}
				if( (flags & V6_UNTRANSLATED_NAME) != 0 ) {
					b.getString();
				}
			}
			// The type is separate: put it in the mode's file type bits too (only PERMISSIONS
			// means the permission bits are set: a SETSTAT with just a type changes nothing)
			int typeBits = typeBits(type);
			if( (flags & V4_PERMISSIONS) != 0 ) {
				r.fields |= F_PERMISSIONS;
			}
			if( typeBits != 0 ) {
				r.fields |= F_TYPE;
			}
			r.permissions = (perms & ~S_IFMT) | (typeBits != 0 ? typeBits : perms & S_IFMT);
		}
		if( (flags & EXTENDED) != 0 ) {
			long n = b.getUInt();
			if( n > 1000 ) {
				throw new SshException("Too many extended attributes");
			}
			Map<String, String> ext = new LinkedHashMap<String, String>();
			for (long i = 0; i < n; i++) {
				ext.put(b.getStringUtf8(), b.getStringUtf8());
			}
			r.extended = Collections.unmodifiableMap(ext);
		}
		return r.build();
	}

	private static int typeBits(int type) {
		switch (type) {
		case TYPE_REGULAR: return S_IFREG;
		case TYPE_DIRECTORY: return S_IFDIR;
		case TYPE_SYMLINK: return S_IFLNK;
		case TYPE_SOCKET: return S_IFSOCK;
		case TYPE_CHAR_DEVICE: return S_IFCHR;
		case TYPE_BLOCK_DEVICE: return S_IFBLK;
		case TYPE_FIFO: return S_IFIFO;
		default: return 0;
		}
	}

	/**
	 * @return the version 4+ file type, from the mode's file type bits
	 */
	public int getType() {
		if( !hasPermissions() && (fields & F_TYPE) == 0 ) {
			return TYPE_UNKNOWN;
		}
		switch (permissions & S_IFMT) {
		case S_IFREG: return TYPE_REGULAR;
		case S_IFDIR: return TYPE_DIRECTORY;
		case S_IFLNK: return TYPE_SYMLINK;
		case S_IFSOCK: return TYPE_SOCKET;
		case S_IFCHR: return TYPE_CHAR_DEVICE;
		case S_IFBLK: return TYPE_BLOCK_DEVICE;
		case S_IFIFO: return TYPE_FIFO;
		case 0: return TYPE_UNKNOWN;
		default: return TYPE_SPECIAL;
		}
	}

	// ------------------------------------------------------------------ writing

	/**
	 * Write as version 3.
	 */
	public SshBuffer write(SshBuffer b) {
		return write(b, 3);
	}

	/**
	 * @param version the session's SFTP version, 3 to 6
	 */
	public SshBuffer write(SshBuffer b, int version) {
		if( version <= 3 ) {
			int f = 0;
			if( hasSize() ) {
				f |= SftpConstants.SSH_FILEXFER_ATTR_SIZE;
			}
			if( hasOwner() ) {
				f |= SftpConstants.SSH_FILEXFER_ATTR_UIDGID;
			}
			if( hasPermissions() ) {
				f |= SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS;
			}
			if( hasTimes() ) {
				f |= SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME;
			}
			if( !extended.isEmpty() ) {
				f |= SftpConstants.SSH_FILEXFER_ATTR_EXTENDED;
			}
			b.putInt(f & 0xffffffffL);
			if( hasSize() ) {
				b.putLong(size);
			}
			if( hasOwner() ) {
				b.putInt(uid & 0xffffffffL).putInt(gid & 0xffffffffL);
			}
			if( hasPermissions() ) {
				b.putInt(permissions & 0xffffffffL);
			}
			if( hasTimes() ) {
				b.putInt(atime & 0xffffffffL).putInt(mtime & 0xffffffffL);
			}
		} else {
			boolean names = (fields & (F_NAMES | F_UIDGID)) != 0;
			boolean nanos = (fields & F_NANOS) != 0;
			int f = 0;
			if( hasSize() ) {
				f |= V4_SIZE;
			}
			if( names ) {
				f |= V4_OWNERGROUP;
			}
			if( hasPermissions() ) {
				f |= V4_PERMISSIONS;
			}
			if( (fields & F_ATIME) != 0 ) {
				f |= V4_ACCESSTIME;
			}
			if( (fields & F_CREATETIME) != 0 ) {
				f |= V4_CREATETIME;
			}
			if( (fields & F_MTIME) != 0 ) {
				f |= V4_MODIFYTIME;
			}
			if( nanos && (fields & (F_ATIME | F_MTIME | F_CREATETIME)) != 0 ) {
				f |= V4_SUBSECOND_TIMES;
			} else {
				nanos = false;
			}
			if( version >= 6 && (fields & F_LINKS) != 0 ) {
				f |= V6_LINK_COUNT;
			}
			if( !extended.isEmpty() ) {
				f |= EXTENDED;
			}
			b.putInt(f & 0xffffffffL);
			b.putByte(getType());
			if( hasSize() ) {
				b.putLong(size);
			}
			if( names ) {
				b.putString((fields & F_NAMES) != 0 ? owner : Integer.toUnsignedString(uid));
				b.putString((fields & F_NAMES) != 0 ? group : Integer.toUnsignedString(gid));
			}
			if( hasPermissions() ) {
				b.putInt(permissions & 07777);
			}
			if( (fields & F_ATIME) != 0 ) {
				b.putLong(atime);
				if( nanos ) {
					b.putInt(atimeNanos);
				}
			}
			if( (fields & F_CREATETIME) != 0 ) {
				b.putLong(createTime);
				if( nanos ) {
					b.putInt(createNanos);
				}
			}
			if( (fields & F_MTIME) != 0 ) {
				b.putLong(mtime);
				if( nanos ) {
					b.putInt(mtimeNanos);
				}
			}
			if( version >= 6 && (fields & F_LINKS) != 0 ) {
				b.putInt(linkCount);
			}
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
		Builder b = new Builder(this);
		b.fields |= F_SIZE;
		b.size = size;
		return b.build();
	}

	public SftpAttrs withOwner(int uid, int gid) {
		Builder b = new Builder(this);
		b.fields |= F_UIDGID;
		b.fields &= ~F_NAMES;
		b.uid = uid;
		b.gid = gid;
		b.owner = null;
		b.group = null;
		return b.build();
	}

	/**
	 * @param owner the owner's name (versions 4+; numbers are sent as uid/gid to version 3)
	 * @param group the group's name
	 */
	public SftpAttrs withOwnerNames(String owner, String group) {
		Builder b = new Builder(this);
		b.fields |= F_NAMES;
		b.owner = owner;
		b.group = group;
		b.fields &= ~F_UIDGID;
		if( owner.matches("[0-9]{1,10}") && group.matches("[0-9]{1,10}") ) {
			b.fields |= F_UIDGID;
			b.uid = (int) Long.parseLong(owner);
			b.gid = (int) Long.parseLong(group);
		}
		return b.build();
	}

	/**
	 * @param permissions mode bits (the file type bits are ignored by servers)
	 */
	public SftpAttrs withPermissions(int permissions) {
		Builder b = new Builder(this);
		b.fields |= F_PERMISSIONS;
		b.permissions = permissions;
		return b.build();
	}

	/**
	 * @param atime seconds since 1970
	 * @param mtime seconds since 1970
	 */
	public SftpAttrs withTimes(long atime, long mtime) {
		Builder b = new Builder(this);
		b.fields |= F_ATIME | F_MTIME;
		b.atime = atime;
		b.mtime = mtime;
		return b.build();
	}

	/**
	 * Times with nanoseconds (versions 4+; version 3 sends whole seconds).
	 */
	public SftpAttrs withTimes(long atime, int atimeNanos, long mtime, int mtimeNanos) {
		Builder b = new Builder(withTimes(atime, mtime));
		b.fields |= F_NANOS;
		b.atimeNanos = atimeNanos;
		b.mtimeNanos = mtimeNanos;
		return b.build();
	}

	/**
	 * @param seconds the creation time (versions 4+ only)
	 */
	public SftpAttrs withCreateTime(long seconds, int nanos) {
		Builder b = new Builder(this);
		b.fields |= F_CREATETIME;
		b.createTime = seconds;
		b.createNanos = nanos;
		if( nanos != 0 ) {
			b.fields |= F_NANOS;
		}
		return b.build();
	}

	/**
	 * @param links the number of hard links (version 6 only)
	 */
	public SftpAttrs withLinkCount(int links) {
		Builder b = new Builder(this);
		b.fields |= F_LINKS;
		b.linkCount = links;
		return b.build();
	}

	// ------------------------------------------------------------------ getters

	/**
	 * @return the version 3 attribute flags of the fields that are set
	 */
	public int getFlags() {
		int f = 0;
		if( hasSize() ) {
			f |= SftpConstants.SSH_FILEXFER_ATTR_SIZE;
		}
		if( hasOwner() ) {
			f |= SftpConstants.SSH_FILEXFER_ATTR_UIDGID;
		}
		if( hasPermissions() ) {
			f |= SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS;
		}
		if( hasTimes() ) {
			f |= SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME;
		}
		if( !extended.isEmpty() ) {
			f |= SftpConstants.SSH_FILEXFER_ATTR_EXTENDED;
		}
		return f;
	}

	public boolean hasSize() {
		return (fields & F_SIZE) != 0;
	}

	/** @return true if uid and gid are known */
	public boolean hasOwner() {
		return (fields & F_UIDGID) != 0;
	}

	/** @return true if the owner and group are known by name (versions 4+) */
	public boolean hasOwnerNames() {
		return (fields & F_NAMES) != 0;
	}

	public boolean hasPermissions() {
		return (fields & F_PERMISSIONS) != 0;
	}

	/** @return true if both the access and the modification time are set */
	public boolean hasTimes() {
		return (fields & (F_ATIME | F_MTIME)) == (F_ATIME | F_MTIME);
	}

	public boolean hasAccessTime() {
		return (fields & F_ATIME) != 0;
	}

	public boolean hasModifyTime() {
		return (fields & F_MTIME) != 0;
	}

	public boolean hasCreateTime() {
		return (fields & F_CREATETIME) != 0;
	}

	public boolean hasLinkCount() {
		return (fields & F_LINKS) != 0;
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

	/** @return the owner's name (versions 4+), or null */
	public String getOwner() {
		return owner;
	}

	/** @return the group's name (versions 4+), or null */
	public String getGroup() {
		return group;
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

	public int getAccessTimeNanos() {
		return atimeNanos;
	}

	/** Seconds since 1970 */
	public long getModifyTime() {
		return mtime;
	}

	public int getModifyTimeNanos() {
		return mtimeNanos;
	}

	/** Seconds since 1970 (versions 4+) */
	public long getCreateTime() {
		return createTime;
	}

	public int getCreateTimeNanos() {
		return createNanos;
	}

	public int getLinkCount() {
		return linkCount;
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
		return "SftpAttrs[size="+(hasSize() ? size : "-")+" owner="+(hasOwnerNames() ? owner+"/"+group : hasOwner() ? uid+"/"+gid : "-")
				+" mode="+(hasPermissions() ? Integer.toOctalString(permissions) : "-")+" mtime="+(hasModifyTime() ? mtime : "-")+"]";
	}
}
