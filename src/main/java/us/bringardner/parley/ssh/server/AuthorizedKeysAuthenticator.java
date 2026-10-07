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
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.regex.Pattern;

import us.bringardner.parley.core.BaseObject;
import us.bringardner.parley.core.util.AddressMatcher;
import us.bringardner.parley.net.server.IAccessControlList;
import us.bringardner.parley.net.server.IPrincipal;
import us.bringardner.parley.net.server.ImmutablePrincipal;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.SshCertificate;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;

/**
 * Public keys from OpenSSH authorized_keys files ("[options] type base64 comment" per line,
 * sshd(8) AUTHORIZED_KEYS FILE FORMAT). A file is read again when it changes.
 * <p>
 * Options: command="...", from="pattern-list", expiry-time="YYYYMMDD[HHMM[SS]][Z]",
 * no-pty, no-port-forwarding, no-agent-forwarding, no-X11-forwarding, no-user-rc,
 * restrict (all of those) and pty, port-forwarding, agent-forwarding, X11-forwarding, user-rc
 * to allow them again, permitopen="host:port", permitlisten="[host:]port", and
 * no-touch-required and verify-required for security keys (sk-ecdsa, sk-ed25519), and
 * cert-authority with principals="...": the line's key is a certificate authority whose
 * user certificates may log in as this user (for the user's name, or one of the principals).
 * environment= and tunnel= are ignored (as OpenSSH does by default). A line with an option
 * not listed here is skipped, with a warning: ignoring it would let the key do more than its
 * owner meant.
 * <p>
 * The user is the access control list's principal of that name when the server has one
 * (so its permissions apply), else an {@link SshPrincipal}.
 *
 * @author Tony Bringardner
 */
public class AuthorizedKeysAuthenticator extends BaseObject implements IPublicKeyAuthenticator {

	/** User names that can't climb out of a directory */
	private static final Pattern SAFE_USER = Pattern.compile("[A-Za-z0-9._][A-Za-z0-9._-]*");

	/** One line: a key (or CA key) and its options */
	static final class Entry {
		final byte[] blob;
		final boolean certAuthority;
		final List<String> principals;
		final String from;
		final long expiry;
		final KeyRestrictions restrictions;

		Entry(byte[] blob, boolean certAuthority, List<String> principals, String from, long expiry, KeyRestrictions restrictions) {
			this.blob = blob;
			this.certAuthority = certAuthority;
			this.principals = principals;
			this.from = from;
			this.expiry = expiry;
			this.restrictions = restrictions;
		}
	}

	private static final class Cached {
		final long modified;
		final long size;
		final List<Entry> entries;

		Cached(long modified, long size, List<Entry> entries) {
			this.modified = modified;
			this.size = size;
			this.entries = entries;
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

	private List<Entry> entries(String user) throws IOException {
		if( user == null || !SAFE_USER.matcher(user).matches() || user.contains("..") ) {
			return Collections.emptyList();
		}
		File f = files.apply(user);
		if( f == null || !f.isFile() ) {
			return Collections.emptyList();
		}
		return entries(f);
	}

	@Override
	public IPrincipal authenticate(String user, PublicKey key, IServerAuthContext context) throws IOException {
		byte[] blob = SshPublicKeys.encode(key);
		for (Entry e : entries(user)) {
			if( !e.certAuthority && Arrays.equals(e.blob, blob) && usable(e, context, user) ) {
				context.getAttributes().put(KeyRestrictions.ATTRIBUTE, e.restrictions);
				return principal(user, context);
			}
		}
		return null;
	}

	/**
	 * A user certificate signed by a cert-authority line's key.
	 */
	@Override
	public IPrincipal authenticate(String user, SshCertificate cert, IServerAuthContext context) throws IOException {
		byte[] ca = cert.getCaKeyBlob();
		for (Entry e : entries(user)) {
			if( e.certAuthority && Arrays.equals(e.blob, ca) && usable(e, context, user) ) {
				String why = UserCertificateAuthenticator.check(cert, e.principals != null ? e.principals : Collections.singletonList(user),
						context.getRemoteAddress());
				if( why != null ) {
					logInfo("Certificate refused for "+user+" ("+cert+"): "+why);
					continue;
				}
				context.getAttributes().put(KeyRestrictions.ATTRIBUTE, e.restrictions);
				return principal(user, context);
			}
		}
		return null;
	}

	/**
	 * from= and expiry-time=
	 */
	private boolean usable(Entry e, IServerAuthContext context, String user) {
		if( e.expiry > 0 && System.currentTimeMillis()/1000 >= e.expiry ) {
			logInfo("Key for "+user+" has expired (expiry-time)");
			return false;
		}
		if( e.from != null && !fromMatches(e.from, context.getRemoteAddress()) ) {
			logInfo("Key for "+user+" is not allowed from "+context.getRemoteAddress()+" (from=\""+e.from+"\")");
			return false;
		}
		return true;
	}

	/**
	 * A pattern-list of addresses: * and ? wildcards, address/masklen, !negation (which
	 * refuses even if another pattern matches). Host names are not looked up, as with
	 * OpenSSH's default UseDNS no.
	 */
	static boolean fromMatches(String list, SocketAddress from) {
		if( !(from instanceof InetSocketAddress) || ((InetSocketAddress) from).getAddress() == null ) {
			return false;
		}
		java.net.InetAddress addr = ((InetSocketAddress) from).getAddress();
		String ip = addr.getHostAddress();
		int pct = ip.indexOf('%');
		if( pct >= 0 ) {
			ip = ip.substring(0, pct);
		}
		boolean ret = false;
		for (String raw : list.split(",")) {
			String p = raw.trim();
			boolean negate = p.startsWith("!");
			if( negate ) {
				p = p.substring(1);
			}
			boolean m;
			if( p.contains("/") ) {
				try {
					m = AddressMatcher.parse(p).matches(addr);
				} catch (IllegalArgumentException e) {
					m = false;
				}
			} else {
				m = glob(p.toLowerCase(java.util.Locale.ROOT), ip.toLowerCase(java.util.Locale.ROOT));
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

	private static boolean glob(String p, String n) {
		StringBuilder re = new StringBuilder();
		for (char c : p.toCharArray()) {
			re.append(c == '*' ? ".*" : c == '?' ? "." : Pattern.quote(String.valueOf(c)));
		}
		return n.matches(re.toString());
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

	private List<Entry> entries(File f) throws IOException {
		String path = f.getCanonicalPath();
		long modified = f.lastModified();
		long size = f.length();
		Cached c = cache.get(path);
		if( c != null && c.modified == modified && c.size == size ) {
			return c.entries;
		}
		List<Entry> entries = parse(Files.readAllLines(f.toPath(), StandardCharsets.UTF_8), path);
		cache.put(path, new Cached(modified, size, entries));
		return entries;
	}

	/**
	 * @return the usable lines
	 */
	List<Entry> parse(List<String> lines, String where) {
		List<Entry> ret = new ArrayList<Entry>();
		int n = 0;
		for (String raw : lines) {
			n++;
			String line = raw.trim();
			if( line.isEmpty() || line.startsWith("#") ) {
				continue;
			}
			try {
				Entry e = parseLine(line);
				if( e != null ) {
					ret.add(e);
				}
			} catch (SshException e) {
				// e.g. an Ed25519 key before Java 15, or a security key
				logDebug(where+" line "+n+": "+e.getMessage());
			} catch (IllegalArgumentException e) {
				logWarn(where+" line "+n+" is skipped: "+e.getMessage());
			}
		}
		return Collections.unmodifiableList(ret);
	}

	private static boolean isKeyType(String token) {
		return token.startsWith("ssh-") || token.startsWith("ecdsa-") || token.startsWith("sk-");
	}

	/**
	 * @throws IllegalArgumentException for an option that isn't supported (the line is skipped)
	 */
	static Entry parseLine(String line) throws SshException {
		String options = null;
		String rest = line;
		String first = line.split("\\s+", 2)[0];
		if( !isKeyType(first) ) {
			int end = optionsEnd(line);
			options = line.substring(0, end);
			rest = line.substring(end).trim();
		}
		byte[] blob = SshPublicKeys.encode(SshPublicKeys.fromOpenSsh(rest));

		String forced = null;
		boolean pty = true, ports = true, agent = true, x11 = true, rc = true;
		List<String> permitOpen = null;
		List<String> permitListen = null;
		List<String> principals = null;
		String from = null;
		long expiry = 0;
		boolean ca = false;
		boolean touch = true;
		boolean verify = false;
		if( options != null ) {
			for (String[] o : splitOptions(options)) {
				String name = o[0].toLowerCase(java.util.Locale.ROOT);
				String value = o[1];
				switch (name) {
				case "restrict": pty = ports = agent = x11 = rc = false; break;
				case "no-pty": pty = false; break;
				case "pty": pty = true; break;
				case "no-port-forwarding": ports = false; break;
				case "port-forwarding": ports = true; break;
				case "no-agent-forwarding": agent = false; break;
				case "agent-forwarding": agent = true; break;
				case "no-x11-forwarding": x11 = false; break;
				case "x11-forwarding": x11 = true; break;
				case "no-user-rc": rc = false; break;
				case "user-rc": rc = true; break;
				case "cert-authority": ca = true; break;
				case "command": forced = need(name, value); break;
				case "from": from = need(name, value); break;
				case "principals": principals = Arrays.asList(need(name, value).split("\\s*,\\s*")); break;
				case "permitopen":
					if( permitOpen == null ) {
						permitOpen = new ArrayList<String>();
					}
					permitOpen.add(need(name, value));
					break;
				case "permitlisten":
					if( permitListen == null ) {
						permitListen = new ArrayList<String>();
					}
					permitListen.add(need(name, value));
					break;
				case "expiry-time": expiry = expiry(need(name, value)); break;
				// Security keys (sk-*): touching the key is not needed / a PIN is
				case "no-touch-required": touch = false; break;
				case "verify-required": verify = true; break;
				// PermitUserEnvironment and tunnel devices aren't supported: nothing to allow
				case "environment":
				case "tunnel":
					break;
				default:
					throw new IllegalArgumentException("unsupported option "+o[0]);
				}
			}
		}
		if( principals != null && !ca ) {
			throw new IllegalArgumentException("principals= without cert-authority");
		}
		return new Entry(blob, ca, principals, from, expiry,
				new KeyRestrictions(forced, pty, ports, agent, x11, rc, permitOpen, permitListen).withSecurityKey(touch, verify));
	}

	private static String need(String name, String value) {
		if( value == null ) {
			throw new IllegalArgumentException(name+" needs a value");
		}
		return value;
	}

	/**
	 * @return where the options end: the first space outside quotes
	 */
	private static int optionsEnd(String line) {
		boolean quoted = false;
		for (int i = 0; i < line.length(); i++) {
			char c = line.charAt(i);
			if( c == '\\' && quoted && i+1 < line.length() ) {
				i++;
			} else if( c == '"' ) {
				quoted = !quoted;
			} else if( !quoted && Character.isWhitespace(c) ) {
				return i;
			}
		}
		throw new IllegalArgumentException("no key after the options");
	}

	/**
	 * @return name, value (null for a flag); quotes removed, \" unescaped
	 */
	private static List<String[]> splitOptions(String options) {
		List<String[]> ret = new ArrayList<String[]>();
		StringBuilder name = new StringBuilder();
		StringBuilder value = null;
		boolean quoted = false;
		for (int i = 0; i <= options.length(); i++) {
			char c = i < options.length() ? options.charAt(i) : ',';
			if( quoted ) {
				if( c == '\\' && i+1 < options.length() && options.charAt(i+1) == '"' ) {
					value.append('"');
					i++;
				} else if( c == '"' ) {
					quoted = false;
				} else {
					value.append(c);
				}
			} else if( c == ',' ) {
				if( name.length() == 0 ) {
					throw new IllegalArgumentException("empty option");
				}
				ret.add(new String[] {name.toString(), value == null ? null : value.toString()});
				name.setLength(0);
				value = null;
			} else if( value != null ) {
				if( c == '"' ) {
					quoted = true;
				} else {
					value.append(c);
				}
			} else if( c == '=' ) {
				value = new StringBuilder();
			} else {
				name.append(c);
			}
		}
		if( quoted ) {
			throw new IllegalArgumentException("unterminated quote");
		}
		return ret;
	}

	/**
	 * YYYYMMDD[HHMM[SS]], local time, or UTC with a Z at the end
	 *
	 * @return seconds since 1970
	 */
	static long expiry(String text) {
		String t = text.trim();
		boolean utc = t.endsWith("Z") || t.endsWith("z");
		if( utc ) {
			t = t.substring(0, t.length()-1);
		}
		String pattern = t.length() == 8 ? "yyyyMMdd" : t.length() == 12 ? "yyyyMMddHHmm" : t.length() == 14 ? "yyyyMMddHHmmss" : null;
		if( pattern == null || !t.matches("[0-9]+") ) {
			throw new IllegalArgumentException("bad expiry-time "+text);
		}
		try {
			LocalDateTime d = t.length() == 8 ? java.time.LocalDate.parse(t, DateTimeFormatter.ofPattern(pattern)).atStartOfDay()
					: LocalDateTime.parse(t, DateTimeFormatter.ofPattern(pattern));
			return d.atZone(utc ? ZoneOffset.UTC : ZoneId.systemDefault()).toEpochSecond();
		} catch (DateTimeParseException e) {
			throw new IllegalArgumentException("bad expiry-time "+text);
		}
	}
}
