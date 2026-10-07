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
package us.bringardner.parley.ssh.client;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.channels.SocketChannel;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.connection.UnixSockets;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.SshCertificate;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;

/**
 * A connection to an SSH agent (ssh-agent, or OpenSSH's agent service on Windows): the
 * keys it holds, and signatures made with them, so private keys never leave the agent
 * (draft-miller-ssh-agent). Use it to log in with {@link PublicKeyAuth#fromAgent(SshAgent)}.
 * <p>
 * On Unix the agent is the socket named by SSH_AUTH_SOCK, which needs Java 16 or later
 * (Unix domain sockets); see {@link #isSupported()}. On Windows it is the named pipe
 * \\.\pipe\openssh-ssh-agent, or PuTTY's Pageant ({@link #connectPageant()}).
 * <p>
 * One request at a time (requests are synchronized).
 *
 * @author Tony Bringardner
 */
public class SshAgent implements Closeable {

	public static final String WINDOWS_PIPE = "\\\\.\\pipe\\openssh-ssh-agent";

	private static final int SSH_AGENT_FAILURE = 5;
	private static final int SSH_AGENTC_REQUEST_IDENTITIES = 11;
	private static final int SSH_AGENT_IDENTITIES_ANSWER = 12;
	private static final int SSH_AGENTC_SIGN_REQUEST = 13;
	private static final int SSH_AGENT_SIGN_RESPONSE = 14;
	/** Sign flags: RSA keys sign with rsa-sha2-256 / rsa-sha2-512 instead of SHA-1 ssh-rsa */
	public static final int SSH_AGENT_RSA_SHA2_256 = 2;
	public static final int SSH_AGENT_RSA_SHA2_512 = 4;
	/** Answers bigger than this are refused */
	private static final int MAX_MESSAGE = 256*1024;

	/**
	 * A key the agent holds: its blob (a certificate's blob for a certificate), and comment.
	 */
	public static final class Identity {
		private final byte[] blob;
		private final String comment;

		Identity(byte[] blob, String comment) {
			this.blob = blob;
			this.comment = comment;
		}

		public byte[] getBlob() {
			return blob.clone();
		}

		public String getComment() {
			return comment;
		}

		/** @return e.g. "ssh-ed25519" or "ssh-ed25519-cert-v01@openssh.com" */
		public String getType() throws SshException {
			return SshPublicKeys.blobType(blob);
		}

		public boolean isCertificate() throws SshException {
			return SshCertificate.isCertificateType(getType());
		}

		/** @return the key (the certified key for a certificate) */
		public PublicKey getPublicKey() throws SshException {
			return isCertificate() ? SshCertificate.decode(blob).getPublicKey() : SshPublicKeys.decode(blob);
		}

		@Override
		public String toString() {
			try {
				return getType()+" "+SshPublicKeys.fingerprint(blob)+" "+comment;
			} catch (SshException e) {
				return "unknown key "+comment;
			}
		}
	}

	private final Closeable channel;
	private final InputStream in;
	private final OutputStream out;

	private SshAgent(Closeable channel, InputStream in, OutputStream out) {
		this.channel = channel;
		this.in = in;
		this.out = out;
	}

	/**
	 * @return true if this JVM can reach an agent: Java 16+ on Unix (Unix domain sockets), any on Windows
	 */
	public static boolean isSupported() {
		return isWindows() || UnixSockets.isSupported();
	}

	/**
	 * @return true if there is an agent to connect to: SSH_AUTH_SOCK is set (or on Windows,
	 * the agent's pipe exists)
	 */
	public static boolean isAvailable() {
		if( isWindows() ) {
			String sock = System.getenv("SSH_AUTH_SOCK");
			return (sock != null && !sock.isEmpty()) || new File(WINDOWS_PIPE).exists() || findPageantPipe() != null;
		}
		String sock = System.getenv("SSH_AUTH_SOCK");
		return sock != null && !sock.isEmpty() && isSupported();
	}

	/**
	 * Connect to the user's agent: SSH_AUTH_SOCK, or on Windows the OpenSSH agent's pipe,
	 * else Pageant's ({@link #connectPageant()}).
	 */
	public static SshAgent connect() throws IOException {
		String sock = System.getenv("SSH_AUTH_SOCK");
		if( sock == null || sock.isEmpty() ) {
			if( isWindows() ) {
				if( new File(WINDOWS_PIPE).exists() || findPageantPipe() == null ) {
					return connect(WINDOWS_PIPE);
				}
				return connectPageant();
			}
			throw new SshException("No SSH agent: SSH_AUTH_SOCK is not set");
		}
		return connect(sock);
	}

	/**
	 * Connect to PuTTY's Pageant (0.75 and later) through its named pipe,
	 * \\.\pipe\pageant.USER.HASH, which speaks the same agent protocol. Windows only.
	 *
	 * @throws SshException if Pageant isn't running
	 */
	public static SshAgent connectPageant() throws IOException {
		String pipe = findPageantPipe();
		if( pipe == null ) {
			throw new SshException("Pageant is not running (no \\\\.\\pipe\\pageant."+System.getProperty("user.name")+".* pipe)");
		}
		return connect(pipe);
	}

	/**
	 * @return Pageant's pipe for this user, or null
	 */
	static String findPageantPipe() {
		if( !isWindows() ) {
			return null;
		}
		List<String> names = new ArrayList<String>();
		try (java.nio.file.DirectoryStream<java.nio.file.Path> pipes = java.nio.file.Files.newDirectoryStream(java.nio.file.Paths.get("\\\\.\\pipe\\"))) {
			for (java.nio.file.Path p : pipes) {
				names.add(p.getFileName() == null ? p.toString() : p.getFileName().toString());
			}
		} catch (IOException | RuntimeException e) {
			return null;
		}
		return pageantPipe(names, System.getProperty("user.name"));
	}

	/**
	 * @param names the names of the named pipes
	 * @return Pageant's pipe for the user, or null
	 */
	static String pageantPipe(Iterable<String> names, String user) {
		String prefix = "pageant."+user.toLowerCase(Locale.ROOT)+".";
		for (String n : names) {
			String name = n.replace('/', '\\');
			name = name.substring(name.lastIndexOf('\\')+1);
			if( name.toLowerCase(Locale.ROOT).startsWith(prefix) && name.length() > prefix.length() ) {
				return "\\\\.\\pipe\\"+name;
			}
		}
		return null;
	}

	/**
	 * The agent named by an OpenSSH config file, as Pageant --openssh-config writes it
	 * ("IdentityAgent \"\\.\pipe\pageant...\"").
	 *
	 * @return the IdentityAgent's path, or null if the file names none
	 */
	public static String identityAgent(File openSshConfig) throws IOException {
		for (String line : java.nio.file.Files.readAllLines(openSshConfig.toPath(), java.nio.charset.StandardCharsets.UTF_8)) {
			String l = line.trim();
			if( l.regionMatches(true, 0, "IdentityAgent", 0, 13) && l.length() > 13 && (Character.isWhitespace(l.charAt(13)) || l.charAt(13) == '=') ) {
				String v = l.substring(14).trim();
				if( v.startsWith("=") ) {
					v = v.substring(1).trim();
				}
				if( v.length() >= 2 && v.startsWith("\"") && v.endsWith("\"") ) {
					v = v.substring(1, v.length()-1);
				}
				return v.isEmpty() || v.equalsIgnoreCase("none") ? null : v;
			}
		}
		return null;
	}

	/**
	 * @param path the agent's Unix socket, or a Windows named pipe (\\.\pipe\...)
	 */
	public static SshAgent connect(String path) throws IOException {
		if( path.startsWith("\\\\.\\pipe\\") ) {
			RandomAccessFile pipe = new RandomAccessFile(path, "rw");
			// The file's own read and write: its channel would hold a lock across a blocked read
			InputStream pin = new InputStream() {
				@Override
				public int read() throws IOException {
					return pipe.read();
				}

				@Override
				public int read(byte[] b, int off, int len) throws IOException {
					return pipe.read(b, off, len);
				}
			};
			OutputStream pout = new OutputStream() {
				@Override
				public void write(int b) throws IOException {
					pipe.write(b);
				}

				@Override
				public void write(byte[] b, int off, int len) throws IOException {
					pipe.write(b, off, len);
				}
			};
			return new SshAgent(pipe, pin, pout);
		}
		if( !UnixSockets.isSupported() ) {
			throw new SshException("Connecting to an SSH agent needs Java 16 or later (Unix domain sockets)");
		}
		SocketChannel ch;
		try {
			ch = UnixSockets.connect(path);
		} catch (IOException e) {
			throw new SshException("Can't connect to the SSH agent at "+path+": "+e.getMessage());
		}
		return new SshAgent(ch, UnixSockets.inputStream(ch), UnixSockets.outputStream(ch));
	}

	/**
	 * An agent reached through other streams, e.g. an agent forwarded to a server
	 * (ServerSession.openForwardedAgent).
	 */
	public static SshAgent over(InputStream in, OutputStream out, Closeable closeable) {
		return new SshAgent(closeable, in, out);
	}

	/** The raw agent protocol streams, for forwarding the agent */
	InputStream rawInput() {
		return in;
	}

	OutputStream rawOutput() {
		return out;
	}

	Closeable rawCloseable() {
		return channel;
	}

	private static boolean isWindows() {
		return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
	}

	/**
	 * @return the keys (and certificates) the agent holds
	 */
	public synchronized List<Identity> getIdentities() throws IOException {
		SshBuffer r = request(new SshBuffer().putByte(SSH_AGENTC_REQUEST_IDENTITIES));
		int type = r.getByte();
		if( type != SSH_AGENT_IDENTITIES_ANSWER ) {
			throw new SshException("The SSH agent didn't list its keys (answer "+type+")");
		}
		long n = r.getUInt();
		if( n > 10000 ) {
			throw new SshException("The SSH agent lists "+n+" keys");
		}
		List<Identity> ret = new ArrayList<Identity>();
		for (long i = 0; i < n; i++) {
			ret.add(new Identity(r.getString(), r.getStringUtf8()));
		}
		return Collections.unmodifiableList(ret);
	}

	/**
	 * @param blob the identity's blob
	 * @param data what to sign
	 * @param flags 0, or {@link #SSH_AGENT_RSA_SHA2_256} / {@link #SSH_AGENT_RSA_SHA2_512} for RSA keys
	 * @return the signature blob (string algorithm, string signature)
	 * @throws SshException if the agent refuses (e.g. the user declined a confirmation)
	 */
	public synchronized byte[] sign(byte[] blob, byte[] data, int flags) throws IOException {
		SshBuffer r = request(new SshBuffer().putByte(SSH_AGENTC_SIGN_REQUEST).putString(blob).putString(data).putInt(flags));
		int type = r.getByte();
		if( type == SSH_AGENT_FAILURE ) {
			throw new SshException("The SSH agent refused to sign");
		}
		if( type != SSH_AGENT_SIGN_RESPONSE ) {
			throw new SshException("Unexpected SSH agent answer "+type);
		}
		return r.getString();
	}

	private SshBuffer request(SshBuffer message) throws IOException {
		byte[] m = message.toByteArray();
		out.write(new SshBuffer().putInt(m.length).putRaw(m).toByteArray());
		out.flush();
		byte[] len = readFully(4);
		long n = new SshBuffer(len).getUInt();
		if( n < 1 || n > MAX_MESSAGE ) {
			throw new SshException("Bad SSH agent answer length "+n);
		}
		return new SshBuffer(readFully((int) n));
	}

	private byte[] readFully(int n) throws IOException {
		byte[] b = new byte[n];
		int off = 0;
		while( off < n ) {
			int r = in.read(b, off, n-off);
			if( r < 0 ) {
				throw new SshException("The SSH agent closed the connection");
			}
			off += r;
		}
		return b;
	}

	@Override
	public void close() throws IOException {
		channel.close();
	}
}
