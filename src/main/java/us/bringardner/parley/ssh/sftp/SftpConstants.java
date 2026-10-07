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

/**
 * SFTP constants: version 3 (draft-ietf-secsh-filexfer-02, what OpenSSH speaks) and what
 * versions 4 to 6 add (drafts 04, 05 and 13): packet types, status codes, open flags and
 * attribute flags.
 *
 * @author Tony Bringardner
 */
public final class SftpConstants {

	private SftpConstants() {
	}

	/** The version OpenSSH speaks, and the client's default */
	public static final int SFTP_VERSION = 3;
	/** The highest version this library speaks */
	public static final int SFTP_MAX_VERSION = 6;

	public static final int SSH_FXP_INIT = 1;
	public static final int SSH_FXP_VERSION = 2;
	public static final int SSH_FXP_OPEN = 3;
	public static final int SSH_FXP_CLOSE = 4;
	public static final int SSH_FXP_READ = 5;
	public static final int SSH_FXP_WRITE = 6;
	public static final int SSH_FXP_LSTAT = 7;
	public static final int SSH_FXP_FSTAT = 8;
	public static final int SSH_FXP_SETSTAT = 9;
	public static final int SSH_FXP_FSETSTAT = 10;
	public static final int SSH_FXP_OPENDIR = 11;
	public static final int SSH_FXP_READDIR = 12;
	public static final int SSH_FXP_REMOVE = 13;
	public static final int SSH_FXP_MKDIR = 14;
	public static final int SSH_FXP_RMDIR = 15;
	public static final int SSH_FXP_REALPATH = 16;
	public static final int SSH_FXP_STAT = 17;
	public static final int SSH_FXP_RENAME = 18;
	public static final int SSH_FXP_READLINK = 19;
	/** Versions 3 to 5; version 6 has {@link #SSH_FXP_LINK} */
	public static final int SSH_FXP_SYMLINK = 20;
	/** Version 6: string new-link-path, string existing-path, bool symlink */
	public static final int SSH_FXP_LINK = 21;
	/** Version 6 byte range locks */
	public static final int SSH_FXP_BLOCK = 22;
	public static final int SSH_FXP_UNBLOCK = 23;
	public static final int SSH_FXP_STATUS = 101;
	public static final int SSH_FXP_HANDLE = 102;
	public static final int SSH_FXP_DATA = 103;
	public static final int SSH_FXP_NAME = 104;
	public static final int SSH_FXP_ATTRS = 105;
	public static final int SSH_FXP_EXTENDED = 200;
	public static final int SSH_FXP_EXTENDED_REPLY = 201;

	public static final int SSH_FX_OK = 0;
	public static final int SSH_FX_EOF = 1;
	public static final int SSH_FX_NO_SUCH_FILE = 2;
	public static final int SSH_FX_PERMISSION_DENIED = 3;
	public static final int SSH_FX_FAILURE = 4;
	public static final int SSH_FX_BAD_MESSAGE = 5;
	public static final int SSH_FX_NO_CONNECTION = 6;
	public static final int SSH_FX_CONNECTION_LOST = 7;
	public static final int SSH_FX_OP_UNSUPPORTED = 8;
	// Version 4
	public static final int SSH_FX_INVALID_HANDLE = 9;
	public static final int SSH_FX_NO_SUCH_PATH = 10;
	public static final int SSH_FX_FILE_ALREADY_EXISTS = 11;
	public static final int SSH_FX_WRITE_PROTECT = 12;
	public static final int SSH_FX_NO_MEDIA = 13;
	// Version 5
	public static final int SSH_FX_NO_SPACE_ON_FILESYSTEM = 14;
	public static final int SSH_FX_QUOTA_EXCEEDED = 15;
	public static final int SSH_FX_UNKNOWN_PRINCIPAL = 16;
	public static final int SSH_FX_LOCK_CONFLICT = 17;
	// Version 6
	public static final int SSH_FX_DIR_NOT_EMPTY = 18;
	public static final int SSH_FX_NOT_A_DIRECTORY = 19;
	public static final int SSH_FX_INVALID_FILENAME = 20;
	public static final int SSH_FX_LINK_LOOP = 21;
	public static final int SSH_FX_CANNOT_DELETE = 22;
	public static final int SSH_FX_INVALID_PARAMETER = 23;
	public static final int SSH_FX_FILE_IS_A_DIRECTORY = 24;
	public static final int SSH_FX_BYTE_RANGE_LOCK_CONFLICT = 25;
	public static final int SSH_FX_BYTE_RANGE_LOCK_REFUSED = 26;
	public static final int SSH_FX_DELETE_PENDING = 27;
	public static final int SSH_FX_FILE_CORRUPT = 28;
	public static final int SSH_FX_OWNER_INVALID = 29;
	public static final int SSH_FX_GROUP_INVALID = 30;
	public static final int SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK = 31;

	public static final int SSH_FXF_READ = 0x01;
	public static final int SSH_FXF_WRITE = 0x02;
	public static final int SSH_FXF_APPEND = 0x04;
	public static final int SSH_FXF_CREAT = 0x08;
	public static final int SSH_FXF_TRUNC = 0x10;
	public static final int SSH_FXF_EXCL = 0x20;
	/** Version 4: text mode (not converted by this library) */
	public static final int SSH_FXF_TEXT = 0x40;

	// Version 5+ open: desired access (ACE4 mask bits)
	public static final int ACE4_READ_DATA = 0x00000001;
	public static final int ACE4_WRITE_DATA = 0x00000002;
	public static final int ACE4_APPEND_DATA = 0x00000004;
	public static final int ACE4_READ_ATTRIBUTES = 0x00000080;
	public static final int ACE4_WRITE_ATTRIBUTES = 0x00000100;
	// Version 5+ open: flags (the low 3 bits are the disposition)
	public static final int SSH_FXF_ACCESS_DISPOSITION = 0x00000007;
	public static final int SSH_FXF_CREATE_NEW = 0x00000000;
	public static final int SSH_FXF_CREATE_TRUNCATE = 0x00000001;
	public static final int SSH_FXF_OPEN_EXISTING = 0x00000002;
	public static final int SSH_FXF_OPEN_OR_CREATE = 0x00000003;
	public static final int SSH_FXF_TRUNCATE_EXISTING = 0x00000004;
	public static final int SSH_FXF_APPEND_DATA = 0x00000008;
	public static final int SSH_FXF_APPEND_DATA_ATOMIC = 0x00000010;
	public static final int SSH_FXF_TEXT_MODE = 0x00000020;

	// Version 5+ rename flags
	public static final int SSH_FXF_RENAME_OVERWRITE = 0x00000001;
	public static final int SSH_FXF_RENAME_ATOMIC = 0x00000002;
	public static final int SSH_FXF_RENAME_NATIVE = 0x00000004;

	public static final int SSH_FILEXFER_ATTR_SIZE = 0x01;
	public static final int SSH_FILEXFER_ATTR_UIDGID = 0x02;
	public static final int SSH_FILEXFER_ATTR_PERMISSIONS = 0x04;
	public static final int SSH_FILEXFER_ATTR_ACMODTIME = 0x08;
	public static final int SSH_FILEXFER_ATTR_EXTENDED = 0x80000000;

	/** OpenSSH extensions (PROTOCOL in the OpenSSH sources) */
	public static final String EXT_POSIX_RENAME = "posix-rename@openssh.com";
	public static final String EXT_HARDLINK = "hardlink@openssh.com";
	public static final String EXT_FSYNC = "fsync@openssh.com";
	public static final String EXT_STATVFS = "statvfs@openssh.com";
	/** Version negotiation (draft 13, 5.5): the versions a server speaks, sent with version 3 */
	public static final String EXT_VERSIONS = "versions";
	/** The first request of a client that moves from version 3 to one of "versions" */
	public static final String EXT_VERSION_SELECT = "version-select";

	/**
	 * @return the highest status code a version has (8 for version 3, 13, 17, 31)
	 */
	public static int maxStatus(int version) {
		return version <= 3 ? SSH_FX_OP_UNSUPPORTED : version == 4 ? SSH_FX_NO_MEDIA : version == 5 ? SSH_FX_LOCK_CONFLICT : SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK;
	}

	/**
	 * @return the code to send to a version that may not know it: newer codes become the
	 * nearest older one (e.g. NO_SUCH_PATH is NO_SUCH_FILE for version 3), else FAILURE
	 */
	public static int statusFor(int code, int version) {
		if( code <= maxStatus(version) ) {
			return code;
		}
		switch (code) {
		case SSH_FX_NO_SUCH_PATH:
			return SSH_FX_NO_SUCH_FILE;
		case SSH_FX_WRITE_PROTECT:
		case SSH_FX_CANNOT_DELETE:
			return SSH_FX_PERMISSION_DENIED;
		default:
			return SSH_FX_FAILURE;
		}
	}

	/**
	 * @return the status code's name, e.g. "SSH_FX_NO_SUCH_FILE"
	 */
	public static String statusName(int code) {
		switch (code) {
		case SSH_FX_OK: return "SSH_FX_OK";
		case SSH_FX_EOF: return "SSH_FX_EOF";
		case SSH_FX_NO_SUCH_FILE: return "SSH_FX_NO_SUCH_FILE";
		case SSH_FX_PERMISSION_DENIED: return "SSH_FX_PERMISSION_DENIED";
		case SSH_FX_FAILURE: return "SSH_FX_FAILURE";
		case SSH_FX_BAD_MESSAGE: return "SSH_FX_BAD_MESSAGE";
		case SSH_FX_NO_CONNECTION: return "SSH_FX_NO_CONNECTION";
		case SSH_FX_CONNECTION_LOST: return "SSH_FX_CONNECTION_LOST";
		case SSH_FX_OP_UNSUPPORTED: return "SSH_FX_OP_UNSUPPORTED";
		case SSH_FX_INVALID_HANDLE: return "SSH_FX_INVALID_HANDLE";
		case SSH_FX_NO_SUCH_PATH: return "SSH_FX_NO_SUCH_PATH";
		case SSH_FX_FILE_ALREADY_EXISTS: return "SSH_FX_FILE_ALREADY_EXISTS";
		case SSH_FX_WRITE_PROTECT: return "SSH_FX_WRITE_PROTECT";
		case SSH_FX_NO_MEDIA: return "SSH_FX_NO_MEDIA";
		case SSH_FX_NO_SPACE_ON_FILESYSTEM: return "SSH_FX_NO_SPACE_ON_FILESYSTEM";
		case SSH_FX_QUOTA_EXCEEDED: return "SSH_FX_QUOTA_EXCEEDED";
		case SSH_FX_UNKNOWN_PRINCIPAL: return "SSH_FX_UNKNOWN_PRINCIPAL";
		case SSH_FX_LOCK_CONFLICT: return "SSH_FX_LOCK_CONFLICT";
		case SSH_FX_DIR_NOT_EMPTY: return "SSH_FX_DIR_NOT_EMPTY";
		case SSH_FX_NOT_A_DIRECTORY: return "SSH_FX_NOT_A_DIRECTORY";
		case SSH_FX_INVALID_FILENAME: return "SSH_FX_INVALID_FILENAME";
		case SSH_FX_LINK_LOOP: return "SSH_FX_LINK_LOOP";
		case SSH_FX_CANNOT_DELETE: return "SSH_FX_CANNOT_DELETE";
		case SSH_FX_INVALID_PARAMETER: return "SSH_FX_INVALID_PARAMETER";
		case SSH_FX_FILE_IS_A_DIRECTORY: return "SSH_FX_FILE_IS_A_DIRECTORY";
		default: return "SSH_FX_"+code;
		}
	}
}
