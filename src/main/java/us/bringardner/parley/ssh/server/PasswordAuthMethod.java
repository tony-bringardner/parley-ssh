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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import us.bringardner.parley.net.server.IPrincipal;
import us.bringardner.parley.ssh.SshBuffer;

/**
 * "password" (RFC 4252 8). Password changes are not supported: such a request fails.
 *
 * @author Tony Bringardner
 */
public class PasswordAuthMethod implements IServerAuthMethod {

	private final IPasswordAuthenticator authenticator;

	public PasswordAuthMethod(IPasswordAuthenticator authenticator) {
		this.authenticator = authenticator;
	}

	@Override
	public String getName() {
		return "password";
	}

	@Override
	public Result request(IServerAuthContext context, String user, SshBuffer data) throws IOException {
		boolean change = data.getBoolean();
		byte[] pw = data.getString();
		if( change ) {
			Arrays.fill(pw, (byte) 0);
			return Result.FAILURE;
		}
		char[] password = decode(pw);
		try {
			IPrincipal p = authenticator.authenticate(user, password, context);
			return p == null ? Result.FAILURE : Result.success(p);
		} finally {
			Arrays.fill(password, '\0');
			Arrays.fill(pw, (byte) 0);
		}
	}

	static char[] decode(byte[] utf8) {
		CharBuffer cb = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(utf8));
		char[] ret = new char[cb.remaining()];
		cb.get(ret);
		Arrays.fill(cb.array(), '\0');
		return ret;
	}
}
