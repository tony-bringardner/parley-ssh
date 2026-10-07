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
package us.bringardner.net.ssh.client;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import us.bringardner.core.BaseObject;
import us.bringardner.net.ssh.algorithms.SshPublicKeys;

/**
 * Host keys from an OpenSSH known_hosts file (sshd(8) "SSH_KNOWN_HOSTS FILE FORMAT"): plain
 * and hashed (|1|salt|hash) host names, [host]:port for other ports, * and ? wildcards,
 * !negation and the @revoked marker. @cert-authority lines are skipped (no certificates yet).
 * <p>
 * A key that doesn't match the one known for the host is always refused: that is what an
 * attacker pretending to be the server looks like. What happens with a host that isn't in the
 * file is the {@link Policy}, like OpenSSH's StrictHostKeyChecking.
 * <p>
 * Thread safe. The file is read when this is created and by {@link #reload()}.
 *
 * @author Tony Bringardner
 */
public class KnownHosts extends BaseObject implements IHostKeyVerifier {

	/**
	 * What to do with a host that isn't known.
	 */
	public enum Policy {
		/** Refuse it (StrictHostKeyChecking yes) */
		REJECT,
		/** Trust it and add it to the file (StrictHostKeyChecking accept-new) */
		ACCEPT_NEW,
		/** Trust it without adding it */
		ACCEPT
	}

	/**
	 * The result of looking up a host's key.
	 */
	public enum Result {
		/** The key is known for the host */
		TRUSTED,
		/** The host isn't in the file */
		UNKNOWN,
		/** The host is known with keys of other types only */
		OTHER_TYPES_KNOWN,
		/** The host is known with a different key of the same type */
		CHANGED,
		/** The key is marked @revoked */
		REVOKED
	}

	private static final class Entry {
		final String marker;
		final String[] patterns;
		final String keyType;
		final byte[] blob;
		final String line;

		Entry(String marker, String[] patterns, String keyType, byte[] blob, String line) {
			this.marker = marker;
			this.patterns = patterns;
			this.keyType = keyType;
			this.blob = blob;
			this.line = line;
		}
	}

	private final File file;
	private volatile Policy policy = Policy.REJECT;
	private volatile boolean hashNewHosts = true;
	private volatile List<Entry> entries = Collections.emptyList();
	private final SecureRandom random = new SecureRandom();

	/**
	 * @param file the known_hosts file (it need not exist)
	 */
	public KnownHosts(File file) throws IOException {
		this.file = file;
		reload();
	}

	/**
	 * In memory, from lines in known_hosts format; new hosts are not saved anywhere.
	 */
	public KnownHosts(List<String> lines) {
		this.file = null;
		entries = parse(lines);
	}

	/**
	 * @return ~/.ssh/known_hosts
	 */
	public static KnownHosts userFile() throws IOException {
		return new KnownHosts(new File(System.getProperty("user.home"), ".ssh"+File.separator+"known_hosts"));
	}

	public Policy getPolicy() {
		return policy;
	}

	public KnownHosts setPolicy(Policy policy) {
		this.policy = policy;
		return this;
	}

	public boolean isHashNewHosts() {
		return hashNewHosts;
	}

	/**
	 * @param hash true (default) to write new hosts hashed, as OpenSSH's HashKnownHosts does,
	 * so the file doesn't list the hosts this user connects to
	 */
	public KnownHosts setHashNewHosts(boolean hash) {
		this.hashNewHosts = hash;
		return this;
	}

	public File getFile() {
		return file;
	}

	/**
	 * Read the file again.
	 */
	public synchronized void reload() throws IOException {
		if( file != null && file.exists() ) {
			entries = parse(Files.readAllLines(file.toPath(), StandardCharsets.UTF_8));
		} else {
			entries = Collections.emptyList();
		}
	}

	private List<Entry> parse(List<String> lines) {
		List<Entry> ret = new ArrayList<Entry>();
		for (String line : lines) {
			String l = line.trim();
			if( l.isEmpty() || l.startsWith("#") ) {
				continue;
			}
			String[] parts = l.split("\\s+");
			int i = 0;
			String marker = null;
			if( parts[0].startsWith("@") ) {
				marker = parts[0];
				i++;
			}
			if( parts.length < i+3 ) {
				logDebug("Skipping malformed known_hosts line: "+line);
				continue;
			}
			byte[] blob;
			try {
				blob = Base64.getDecoder().decode(parts[i+2]);
			} catch (IllegalArgumentException e) {
				logDebug("Skipping known_hosts line with bad base64: "+line);
				continue;
			}
			ret.add(new Entry(marker, parts[i].split(","), parts[i+1], blob, line));
		}
		return Collections.unmodifiableList(ret);
	}

	/**
	 * @return the name hosts are listed under: host, or [host]:port for a port other than 22
	 */
	public static String hostName(String host, int port) {
		String h = host.toLowerCase(java.util.Locale.ROOT);
		return port == 22 ? h : "["+h+"]:"+port;
	}

	/**
	 * Look up a host's key without the policy.
	 */
	public Result check(String host, int port, PublicKey key) {
		String name = hostName(host, port);
		byte[] blob = SshPublicKeys.encode(key);
		String type = SshPublicKeys.keyType(key);
		boolean known = false;
		boolean sameType = false;
		boolean trusted = false;
		for (Entry e : entries) {
			if( "@revoked".equals(e.marker) ) {
				if( Arrays.equals(e.blob, blob) ) {
					return Result.REVOKED;
				}
				continue;
			}
			if( e.marker != null || !matches(e.patterns, name) ) {
				continue;
			}
			known = true;
			if( e.keyType.equals(type) ) {
				sameType = true;
				if( Arrays.equals(e.blob, blob) ) {
					trusted = true;
				}
			}
		}
		if( trusted ) {
			return Result.TRUSTED;
		}
		if( sameType ) {
			return Result.CHANGED;
		}
		return known ? Result.OTHER_TYPES_KNOWN : Result.UNKNOWN;
	}

	@Override
	public boolean verify(String host, int port, PublicKey key) throws IOException {
		Result r = check(host, port, key);
		switch (r) {
		case TRUSTED:
			return true;
		case UNKNOWN:
			if( policy == Policy.ACCEPT_NEW ) {
				add(host, port, key);
				logInfo("Added "+hostName(host, port)+" ("+SshPublicKeys.keyType(key)+" "+SshPublicKeys.fingerprint(key)+") to the known hosts");
				return true;
			}
			if( policy == Policy.ACCEPT ) {
				return true;
			}
			logError("Host key of "+hostName(host, port)+" ("+SshPublicKeys.fingerprint(key)+") is not known");
			return false;
		case OTHER_TYPES_KNOWN:
			// Not added automatically: an attacker could offer a key type the host doesn't have
			if( policy == Policy.ACCEPT ) {
				return true;
			}
			logError("Host "+hostName(host, port)+" is known with other key types, not "+SshPublicKeys.keyType(key));
			return false;
		default:
			logError("HOST KEY OF "+hostName(host, port)+" "+(r == Result.REVOKED ? "IS REVOKED" : "HAS CHANGED")
					+" ("+SshPublicKeys.keyType(key)+" "+SshPublicKeys.fingerprint(key)+"): someone may be pretending to be the host");
			return false;
		}
	}

	@Override
	public List<String> getKnownKeyTypes(String host, int port) {
		String name = hostName(host, port);
		List<String> ret = new ArrayList<String>();
		for (Entry e : entries) {
			if( e.marker == null && matches(e.patterns, name) && !ret.contains(e.keyType) ) {
				ret.add(e.keyType);
			}
		}
		return ret;
	}

	/**
	 * Add a host's key (to the file if there is one).
	 */
	public synchronized void add(String host, int port, PublicKey key) throws IOException {
		String name = hostName(host, port);
		String hosts = hashNewHosts ? hash(name) : name;
		String line = hosts+" "+SshPublicKeys.toOpenSsh(key);
		List<Entry> tmp = new ArrayList<Entry>(entries);
		tmp.addAll(parse(Collections.singletonList(line)));
		entries = Collections.unmodifiableList(tmp);
		if( file != null ) {
			File dir = file.getParentFile();
			if( dir != null && !dir.exists() && !dir.mkdirs() ) {
				throw new IOException("Can't create "+dir);
			}
			Files.write(file.toPath(), (line+System.lineSeparator()).getBytes(StandardCharsets.UTF_8),
					StandardOpenOption.CREATE, StandardOpenOption.APPEND);
		}
	}

	/**
	 * @return |1|salt|HMAC-SHA1(salt, name), base64
	 */
	private String hash(String name) {
		byte[] salt = new byte[20];
		random.nextBytes(salt);
		Base64.Encoder b64 = Base64.getEncoder();
		return "|1|"+b64.encodeToString(salt)+"|"+b64.encodeToString(hmac(salt, name));
	}

	private static byte[] hmac(byte[] salt, String name) {
		try {
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(new SecretKeySpec(salt, "HmacSHA1"));
			return mac.doFinal(name.getBytes(StandardCharsets.UTF_8));
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	/**
	 * A host matches if one pattern matches and no negated pattern does.
	 */
	static boolean matches(String[] patterns, String name) {
		boolean ret = false;
		for (String p : patterns) {
			boolean negate = p.startsWith("!");
			String pattern = negate ? p.substring(1) : p;
			boolean m;
			if( pattern.startsWith("|1|") ) {
				m = matchesHashed(pattern, name);
			} else {
				m = glob(pattern.toLowerCase(java.util.Locale.ROOT), name);
			}
			if( m ) {
				if( negate ) {
					return false;
				}
				ret = true;
			}
		}
		return ret;
	}

	private static boolean matchesHashed(String pattern, String name) {
		String[] parts = pattern.split("\\|");
		// "", "1", salt, hash
		if( parts.length != 4 ) {
			return false;
		}
		try {
			byte[] salt = Base64.getDecoder().decode(parts[2]);
			byte[] want = Base64.getDecoder().decode(parts[3]);
			return MessageDigest.isEqual(want, hmac(salt, name));
		} catch (IllegalArgumentException e) {
			return false;
		}
	}

	private static boolean glob(String pattern, String name) {
		if( pattern.indexOf('*') < 0 && pattern.indexOf('?') < 0 ) {
			return pattern.equals(name);
		}
		StringBuilder re = new StringBuilder();
		for (char c : pattern.toCharArray()) {
			if( c == '*' ) {
				re.append(".*");
			} else if( c == '?' ) {
				re.append('.');
			} else {
				re.append(Pattern.quote(String.valueOf(c)));
			}
		}
		return name.matches(re.toString());
	}
}
