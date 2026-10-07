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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import us.bringardner.net.ssh.SshBuffer;
import us.bringardner.net.ssh.SshConstants;

/**
 * "password" authentication (RFC 4252 8). One attempt. The password is copied, and the copy
 * is wiped once it is sent. A server asking for a password change
 * (SSH_MSG_USERAUTH_PASSWD_CHANGEREQ) counts as a failure.
 *
 * @author Tony Bringardner
 */
public class PasswordAuth implements IClientAuthMethod {

	private char[] password;

	public PasswordAuth(char[] password) {
		this.password = password.clone();
	}

	public PasswordAuth(String password) {
		this(password.toCharArray());
	}

	@Override
	public String getName() {
		return "password";
	}

	@Override
	public boolean start(IClientAuthContext context) throws IOException {
		if( password == null ) {
			return false;
		}
		ByteBuffer bytes = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
		byte[] pw = new byte[bytes.remaining()];
		bytes.get(pw);
		Arrays.fill(bytes.array(), (byte) 0);
		Arrays.fill(password, '\0');
		password = null;
		try {
			context.send(context.newRequest(getName()).putBoolean(false).putString(pw));
		} finally {
			Arrays.fill(pw, (byte) 0);
		}
		return true;
	}

	@Override
	public boolean handle(int msg, SshBuffer message, IClientAuthContext context) throws IOException {
		if( msg == SshConstants.SSH_MSG_USERAUTH_60 ) {
			// PASSWD_CHANGEREQ: changing passwords isn't supported
			context.methodFailed("The server asks for a new password: "+message.getStringUtf8());
			return true;
		}
		return false;
	}

	@Override
	public boolean retry(IClientAuthContext context) {
		return false;
	}
}
