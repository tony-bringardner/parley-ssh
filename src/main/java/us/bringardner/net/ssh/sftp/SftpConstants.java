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

/**
 * SFTP version 3 (draft-ietf-secsh-filexfer-02, what OpenSSH speaks): packet types, status
 * codes, open flags and attribute flags.
 *
 * @author Tony Bringardner
 */
public final class SftpConstants {

	private SftpConstants() {
	}

	public static final int SFTP_VERSION = 3;

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
	public static final int SSH_FXP_SYMLINK = 20;
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

	public static final int SSH_FXF_READ = 0x01;
	public static final int SSH_FXF_WRITE = 0x02;
	public static final int SSH_FXF_APPEND = 0x04;
	public static final int SSH_FXF_CREAT = 0x08;
	public static final int SSH_FXF_TRUNC = 0x10;
	public static final int SSH_FXF_EXCL = 0x20;

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
		default: return "SSH_FX_"+code;
		}
	}
}
