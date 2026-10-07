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
import java.util.Arrays;

import us.bringardner.parley.net.server.IPrincipal;
import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshConstants;
import us.bringardner.parley.ssh.SshException;

/**
 * "keyboard-interactive" (RFC 4256) asking for the password, as OpenSSH does with PAM:
 * one INFO_REQUEST with a hidden "Password: " prompt, answered by INFO_RESPONSE.
 *
 * @author Tony Bringardner
 */
public class KeyboardInteractiveAuthMethod implements IServerAuthMethod {

	private static final String USER = KeyboardInteractiveAuthMethod.class.getName()+".user";

	private final IPasswordAuthenticator authenticator;
	private final String prompt;

	public KeyboardInteractiveAuthMethod(IPasswordAuthenticator authenticator) {
		this(authenticator, "Password: ");
	}

	public KeyboardInteractiveAuthMethod(IPasswordAuthenticator authenticator, String prompt) {
		this.authenticator = authenticator;
		this.prompt = prompt;
	}

	@Override
	public String getName() {
		return "keyboard-interactive";
	}

	@Override
	public Result request(IServerAuthContext context, String user, SshBuffer data) throws IOException {
		// language tag, submethods: not used
		context.getAttributes().put(USER, user);
		context.send(SshBuffer.message(SshConstants.SSH_MSG_USERAUTH_60).putString("").putString("").putString("")
				.putInt(1).putString(prompt).putBoolean(false));
		return Result.PENDING;
	}

	@Override
	public Result handle(IServerAuthContext context, int msg, SshBuffer data) throws IOException {
		if( msg != SshConstants.SSH_MSG_USERAUTH_INFO_RESPONSE ) {
			throw new SshException("Unexpected message "+msg+" in keyboard-interactive");
		}
		String user = (String) context.getAttributes().remove(USER);
		int n = data.getInt();
		if( user == null || n != 1 ) {
			return Result.FAILURE;
		}
		byte[] pw = data.getString();
		char[] password = PasswordAuthMethod.decode(pw);
		try {
			IPrincipal p = authenticator.authenticate(user, password, context);
			return p == null ? Result.FAILURE : Result.success(p);
		} finally {
			Arrays.fill(password, '\0');
			Arrays.fill(pw, (byte) 0);
		}
	}
}
