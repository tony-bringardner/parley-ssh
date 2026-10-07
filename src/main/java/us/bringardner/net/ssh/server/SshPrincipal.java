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
package us.bringardner.net.ssh.server;

import us.bringardner.net.framework.server.AbstractPrincipal;
import us.bringardner.net.framework.server.IPermission;

/**
 * A user that logged in without the access control list knowing them (e.g. only by an
 * authorized key). It holds the permissions it is given; it has no password.
 *
 * @author Tony Bringardner
 */
public class SshPrincipal extends AbstractPrincipal {

	public SshPrincipal(String name, IPermission... permissions) {
		super(name);
		setState(State.Authenticated);
		for (IPermission p : permissions) {
			add(p);
		}
	}

	@Override
	public boolean authenticate(byte[] credentials) {
		return false;
	}
}
