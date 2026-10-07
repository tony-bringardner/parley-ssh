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
package us.bringardner.parley.ssh.server;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.regex.Pattern;

import us.bringardner.parley.core.BaseObject;
import us.bringardner.parley.net.server.IAccessControlList;
import us.bringardner.parley.net.server.IPrincipal;
import us.bringardner.parley.net.server.ImmutablePrincipal;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;

/**
 * Public keys from OpenSSH authorized_keys files ("type base64 comment" per line). A file
 * is read again when it changes.
 * <p>
 * Lines with options (command="...", from="...", no-pty, restrict...) are skipped, with a
 * warning: options limit what a key may do, and ignoring them would let the key do more than
 * its owner meant.
 * <p>
 * The user is the access control list's principal of that name when the server has one
 * (so its permissions apply), else an {@link SshPrincipal}.
 *
 * @author Tony Bringardner
 */
public class AuthorizedKeysAuthenticator extends BaseObject implements IPublicKeyAuthenticator {

	/** User names that can't climb out of a directory */
	private static final Pattern SAFE_USER = Pattern.compile("[A-Za-z0-9._][A-Za-z0-9._-]*");

	private static final class Cached {
		final long modified;
		final long size;
		final List<byte[]> keys;

		Cached(long modified, long size, List<byte[]> keys) {
			this.modified = modified;
			this.size = size;
			this.keys = keys;
		}
	}

	private final Function<String, File> files;
	private final Map<String, Cached> cache = new ConcurrentHashMap<String, Cached>();

	/**
	 * @param files the authorized_keys file of a user (null: the user has none)
	 */
	public AuthorizedKeysAuthenticator(Function<String, File> files) {
		this.files = files;
	}

	/**
	 * Each user's file is home/user/.ssh/authorized_keys.
	 */
	public static AuthorizedKeysAuthenticator forHomes(File home) {
		return new AuthorizedKeysAuthenticator(user -> new File(home, user+File.separator+".ssh"+File.separator+"authorized_keys"));
	}

	/**
	 * One file for every user name.
	 */
	public static AuthorizedKeysAuthenticator forFile(File file) {
		return new AuthorizedKeysAuthenticator(user -> file);
	}

	@Override
	public IPrincipal authenticate(String user, PublicKey key, IServerAuthContext context) throws IOException {
		if( user == null || !SAFE_USER.matcher(user).matches() || user.contains("..") ) {
			return null;
		}
		File f = files.apply(user);
		if( f == null || !f.isFile() ) {
			return null;
		}
		byte[] blob = SshPublicKeys.encode(key);
		for (byte[] k : keys(f)) {
			if( Arrays.equals(k, blob) ) {
				return principal(user, context);
			}
		}
		return null;
	}

	static IPrincipal principal(String user, IServerAuthContext context) {
		IAccessControlList acl = context.getServer().getAccessControl();
		if( acl != null ) {
			IPrincipal p = acl.getPrincipal(user);
			if( p != null ) {
				return new ImmutablePrincipal(p);
			}
		}
		return new SshPrincipal(user);
	}

	private List<byte[]> keys(File f) throws IOException {
		String path = f.getCanonicalPath();
		long modified = f.lastModified();
		long size = f.length();
		Cached c = cache.get(path);
		if( c != null && c.modified == modified && c.size == size ) {
			return c.keys;
		}
		List<byte[]> keys = parse(Files.readAllLines(f.toPath(), StandardCharsets.UTF_8), path);
		cache.put(path, new Cached(modified, size, keys));
		return keys;
	}

	/**
	 * @return the key blobs of the lines that have no options
	 */
	List<byte[]> parse(List<String> lines, String where) {
		List<byte[]> ret = new ArrayList<byte[]>();
		int n = 0;
		for (String raw : lines) {
			n++;
			String line = raw.trim();
			if( line.isEmpty() || line.startsWith("#") ) {
				continue;
			}
			String first = line.split("\\s+", 2)[0];
			if( !first.startsWith("ssh-") && !first.startsWith("ecdsa-") && !first.startsWith("sk-") ) {
				logWarn(where+" line "+n+" has options, which aren't supported: the key is not used");
				continue;
			}
			try {
				ret.add(SshPublicKeys.encode(SshPublicKeys.fromOpenSsh(line)));
			} catch (SshException e) {
				// e.g. an Ed25519 key, not supported yet
				logDebug(where+" line "+n+": "+e.getMessage());
			}
		}
		return Collections.unmodifiableList(ret);
	}
}
