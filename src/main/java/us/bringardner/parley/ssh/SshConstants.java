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
package us.bringardner.parley.ssh;

/**
 * Message numbers, disconnect reasons and names from the SSH RFCs (4250-4254, 8308, 8731...).
 *
 * @author Tony Bringardner
 */
public final class SshConstants {

	private SshConstants() {
	}

	// ------------------------------------------------------------------ transport (RFC 4253)
	public static final int SSH_MSG_DISCONNECT = 1;
	public static final int SSH_MSG_IGNORE = 2;
	public static final int SSH_MSG_UNIMPLEMENTED = 3;
	public static final int SSH_MSG_DEBUG = 4;
	public static final int SSH_MSG_SERVICE_REQUEST = 5;
	public static final int SSH_MSG_SERVICE_ACCEPT = 6;
	/** RFC 8308 */
	public static final int SSH_MSG_EXT_INFO = 7;
	public static final int SSH_MSG_KEXINIT = 20;
	public static final int SSH_MSG_NEWKEYS = 21;
	/** First key exchange method specific message (KEXDH_INIT, KEX_ECDH_INIT) */
	public static final int SSH_MSG_KEX_FIRST = 30;
	public static final int SSH_MSG_KEXDH_INIT = 30;
	public static final int SSH_MSG_KEXDH_REPLY = 31;
	public static final int SSH_MSG_KEX_LAST = 49;

	// ------------------------------------------------------------------ user auth (RFC 4252)
	public static final int SSH_MSG_USERAUTH_REQUEST = 50;
	public static final int SSH_MSG_USERAUTH_FAILURE = 51;
	public static final int SSH_MSG_USERAUTH_SUCCESS = 52;
	public static final int SSH_MSG_USERAUTH_BANNER = 53;
	/** publickey PK_OK, password PASSWD_CHANGEREQ, keyboard-interactive INFO_REQUEST */
	public static final int SSH_MSG_USERAUTH_60 = 60;
	public static final int SSH_MSG_USERAUTH_INFO_RESPONSE = 61;

	// ------------------------------------------------------------------ connection (RFC 4254)
	public static final int SSH_MSG_GLOBAL_REQUEST = 80;
	public static final int SSH_MSG_REQUEST_SUCCESS = 81;
	public static final int SSH_MSG_REQUEST_FAILURE = 82;
	public static final int SSH_MSG_CHANNEL_OPEN = 90;
	public static final int SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
	public static final int SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
	public static final int SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
	public static final int SSH_MSG_CHANNEL_DATA = 94;
	public static final int SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
	public static final int SSH_MSG_CHANNEL_EOF = 96;
	public static final int SSH_MSG_CHANNEL_CLOSE = 97;
	public static final int SSH_MSG_CHANNEL_REQUEST = 98;
	public static final int SSH_MSG_CHANNEL_SUCCESS = 99;
	public static final int SSH_MSG_CHANNEL_FAILURE = 100;

	// ------------------------------------------------------------------ disconnect reasons (RFC 4253 11.1)
	public static final int SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1;
	public static final int SSH_DISCONNECT_PROTOCOL_ERROR = 2;
	public static final int SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3;
	public static final int SSH_DISCONNECT_RESERVED = 4;
	public static final int SSH_DISCONNECT_MAC_ERROR = 5;
	public static final int SSH_DISCONNECT_COMPRESSION_ERROR = 6;
	public static final int SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7;
	public static final int SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8;
	public static final int SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9;
	public static final int SSH_DISCONNECT_CONNECTION_LOST = 10;
	public static final int SSH_DISCONNECT_BY_APPLICATION = 11;
	public static final int SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12;
	public static final int SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13;
	public static final int SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14;
	public static final int SSH_DISCONNECT_ILLEGAL_USER_NAME = 15;

	// ------------------------------------------------------------------ names
	public static final String SERVICE_USERAUTH = "ssh-userauth";
	public static final String SERVICE_CONNECTION = "ssh-connection";
	/** Strict key exchange (the Terrapin fix, CVE-2023-48795), client side marker */
	public static final String KEX_STRICT_CLIENT = "kex-strict-c-v00@openssh.com";
	/** Strict key exchange, server side marker */
	public static final String KEX_STRICT_SERVER = "kex-strict-s-v00@openssh.com";
	/** RFC 8308: the client accepts SSH_MSG_EXT_INFO */
	public static final String EXT_INFO_CLIENT = "ext-info-c";
	/** RFC 8308: the server accepts SSH_MSG_EXT_INFO */
	public static final String EXT_INFO_SERVER = "ext-info-s";
	public static final String COMPRESSION_NONE = "none";

	/**
	 * @return the message's name for logs, e.g. "SSH_MSG_KEXINIT(20)"
	 */
	public static String messageName(int msg) {
		String name;
		switch (msg) {
		case SSH_MSG_DISCONNECT: name = "DISCONNECT"; break;
		case SSH_MSG_IGNORE: name = "IGNORE"; break;
		case SSH_MSG_UNIMPLEMENTED: name = "UNIMPLEMENTED"; break;
		case SSH_MSG_DEBUG: name = "DEBUG"; break;
		case SSH_MSG_SERVICE_REQUEST: name = "SERVICE_REQUEST"; break;
		case SSH_MSG_SERVICE_ACCEPT: name = "SERVICE_ACCEPT"; break;
		case SSH_MSG_EXT_INFO: name = "EXT_INFO"; break;
		case SSH_MSG_KEXINIT: name = "KEXINIT"; break;
		case SSH_MSG_NEWKEYS: name = "NEWKEYS"; break;
		case SSH_MSG_USERAUTH_REQUEST: name = "USERAUTH_REQUEST"; break;
		case SSH_MSG_USERAUTH_FAILURE: name = "USERAUTH_FAILURE"; break;
		case SSH_MSG_USERAUTH_SUCCESS: name = "USERAUTH_SUCCESS"; break;
		case SSH_MSG_USERAUTH_BANNER: name = "USERAUTH_BANNER"; break;
		case SSH_MSG_GLOBAL_REQUEST: name = "GLOBAL_REQUEST"; break;
		case SSH_MSG_CHANNEL_OPEN: name = "CHANNEL_OPEN"; break;
		case SSH_MSG_CHANNEL_DATA: name = "CHANNEL_DATA"; break;
		case SSH_MSG_CHANNEL_CLOSE: name = "CHANNEL_CLOSE"; break;
		case SSH_MSG_CHANNEL_REQUEST: name = "CHANNEL_REQUEST"; break;
		default:
			name = (msg >= SSH_MSG_KEX_FIRST && msg <= SSH_MSG_KEX_LAST) ? "KEX" : "MSG";
		}
		return "SSH_MSG_"+name+"("+msg+")";
	}
}
