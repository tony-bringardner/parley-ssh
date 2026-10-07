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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import us.bringardner.parley.ssh.algorithms.SshCertificate;

/**
 * What a login's key may do: from its authorized_keys options (command=, no-pty,
 * permitopen=, restrict...) and its certificate's critical options and extensions. Both
 * apply when both are there (a cert-authority line's options and the certificate's). The
 * server enforces them on the session, on top of its own settings and permissions.
 * Immutable.
 *
 * @author Tony Bringardner
 */
public final class KeyRestrictions {

	/** The auth context attribute an authenticator puts a key's restrictions in */
	public static final String ATTRIBUTE = KeyRestrictions.class.getName();

	/** No restrictions (a plain key without options, or a password) */
	public static final KeyRestrictions NONE = new KeyRestrictions(null, true, true, true, true, true, null, null);

	/** Security keys: the user must touch the key (unless no-touch-required) */
	private boolean touchRequired = true;
	/** Security keys: the user must also be verified, e.g. with a PIN (verify-required) */
	private boolean verifyRequired;

	private final String forceCommand;
	private final boolean pty;
	private final boolean portForwarding;
	private final boolean agentForwarding;
	private final boolean x11Forwarding;
	private final boolean userRc;
	private final List<String> permitOpen;
	private final List<String> permitListen;

	/**
	 * @param permitOpen host:port destinations -L may reach ("*" for any host or port), null for any
	 * @param permitListen [host:]port -R may listen on, null for any
	 */
	public KeyRestrictions(String forceCommand, boolean pty, boolean portForwarding, boolean agentForwarding,
			boolean x11Forwarding, boolean userRc, List<String> permitOpen, List<String> permitListen) {
		this.forceCommand = forceCommand;
		this.pty = pty;
		this.portForwarding = portForwarding;
		this.agentForwarding = agentForwarding;
		this.x11Forwarding = x11Forwarding;
		this.userRc = userRc;
		this.permitOpen = permitOpen == null ? null : Collections.unmodifiableList(new ArrayList<String>(permitOpen));
		this.permitListen = permitListen == null ? null : Collections.unmodifiableList(new ArrayList<String>(permitListen));
	}

	/**
	 * @return a copy with the security key settings (no-touch-required, verify-required)
	 */
	public KeyRestrictions withSecurityKey(boolean touchRequired, boolean verifyRequired) {
		KeyRestrictions r = new KeyRestrictions(forceCommand, pty, portForwarding, agentForwarding, x11Forwarding, userRc, permitOpen, permitListen);
		r.touchRequired = touchRequired;
		r.verifyRequired = verifyRequired;
		return r;
	}

	/**
	 * @return a certificate's: force-command, only the permit-* extensions it has, and for
	 * security keys no-touch-required (extension) and verify-required (critical option)
	 */
	public static KeyRestrictions of(SshCertificate c) {
		return new KeyRestrictions(c.getCriticalOptions().get(SshCertificate.FORCE_COMMAND),
				c.hasExtension(SshCertificate.PERMIT_PTY), c.hasExtension(SshCertificate.PERMIT_PORT_FORWARDING),
				c.hasExtension(SshCertificate.PERMIT_AGENT_FORWARDING), c.hasExtension(SshCertificate.PERMIT_X11_FORWARDING),
				c.hasExtension(SshCertificate.PERMIT_USER_RC), null, null)
				.withSecurityKey(!c.hasExtension(SshCertificate.NO_TOUCH_REQUIRED), c.getCriticalOptions().containsKey(SshCertificate.VERIFY_REQUIRED));
	}

	/**
	 * @return what both allow, or null if they force different commands (OpenSSH refuses those)
	 */
	public KeyRestrictions and(KeyRestrictions o) {
		if( forceCommand != null && o.forceCommand != null && !forceCommand.equals(o.forceCommand) ) {
			return null;
		}
		// Touch is waived only if both waive it (OpenSSH: the key's options and the certificate)
		return new KeyRestrictions(forceCommand != null ? forceCommand : o.forceCommand, pty && o.pty,
				portForwarding && o.portForwarding, agentForwarding && o.agentForwarding, x11Forwarding && o.x11Forwarding,
				userRc && o.userRc, both(permitOpen, o.permitOpen), both(permitListen, o.permitListen))
				.withSecurityKey(touchRequired || o.touchRequired, verifyRequired || o.verifyRequired);
	}

	private static List<String> both(List<String> a, List<String> b) {
		if( a == null ) {
			return b;
		}
		if( b == null ) {
			return a;
		}
		// Both limit: only what both list
		List<String> ret = new ArrayList<String>(a);
		ret.retainAll(b);
		return ret;
	}

	/** @return true if a security key must report that the user touched it */
	public boolean isTouchRequired() {
		return touchRequired;
	}

	/** @return true if a security key must report that the user was verified (PIN, biometrics) */
	public boolean isVerifyRequired() {
		return verifyRequired;
	}

	/** @return the only command the key may run, or null */
	public String getForceCommand() {
		return forceCommand;
	}

	public boolean isPtyAllowed() {
		return pty;
	}

	public boolean isPortForwardingAllowed() {
		return portForwarding;
	}

	public boolean isAgentForwardingAllowed() {
		return agentForwarding;
	}

	public boolean isX11ForwardingAllowed() {
		return x11Forwarding;
	}

	public boolean isUserRcAllowed() {
		return userRc;
	}

	/**
	 * @return true if -L may reach host:port (permitopen=)
	 */
	public boolean canConnect(String host, int port) {
		return portForwarding && allowed(permitOpen, host, port, false);
	}

	/**
	 * @return true if -R may listen on host:port (permitlisten=)
	 */
	public boolean canListen(String host, int port) {
		return portForwarding && allowed(permitListen, host, port, true);
	}

	private static boolean allowed(List<String> list, String host, int port, boolean listen) {
		if( list == null ) {
			return true;
		}
		for (String spec : list) {
			if( spec.equalsIgnoreCase("none") ) {
				continue;
			}
			String h;
			String p;
			int colon = spec.lastIndexOf(':');
			if( colon < 0 ) {
				// permitlisten="port"
				h = listen ? "*" : spec;
				p = listen ? spec : "*";
			} else {
				h = spec.substring(0, colon);
				p = spec.substring(colon+1);
			}
			if( h.startsWith("[") && h.endsWith("]") ) {
				h = h.substring(1, h.length()-1);
			}
			boolean hostOk = h.equals("*") || h.toLowerCase(Locale.ROOT).equals(host.toLowerCase(Locale.ROOT))
					|| (listen && h.equals("localhost") && (host.isEmpty() || host.equals("127.0.0.1") || host.equals("::1")));
			boolean portOk = p.equals("*") || p.equals(Integer.toString(port));
			if( hostOk && portOk ) {
				return true;
			}
		}
		return false;
	}

	@Override
	public String toString() {
		return "KeyRestrictions[command="+forceCommand+" pty="+pty+" port-forwarding="+portForwarding+" agent-forwarding="+agentForwarding
				+(permitOpen != null ? " permitopen="+permitOpen : "")+(permitListen != null ? " permitlisten="+permitListen : "")+"]";
	}
}
