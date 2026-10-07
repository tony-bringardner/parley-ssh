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

import java.io.IOException;
import java.util.Arrays;

import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshConstants;
import us.bringardner.parley.ssh.SshException;

/**
 * "keyboard-interactive" authentication (RFC 4256): the server sends prompts
 * (SSH_MSG_USERAUTH_INFO_REQUEST), a {@link Handler} answers them. Servers that log in
 * through PAM (e.g. macOS) often offer this instead of "password"; {@link #password(char[])}
 * answers their password prompt.
 *
 * @author Tony Bringardner
 */
public class KeyboardInteractiveAuth implements IClientAuthMethod {

	/** More prompts than this in one request is refused (RFC 4256 sets no limit) */
	private static final int MAX_PROMPTS = 100;

	/**
	 * Answers the server's prompts. Called on the session's handler thread; may block (e.g. to ask a user).
	 */
	@FunctionalInterface
	public interface Handler {
		/**
		 * @param name a title, may be empty
		 * @param instruction text to show, may be empty
		 * @param prompts what to ask
		 * @param echo for each prompt, true if the answer may be shown as it is typed
		 * @return one answer per prompt, or null to give up on this method
		 */
		String[] respond(String name, String instruction, String[] prompts, boolean[] echo) throws IOException;
	}

	private final Handler handler;
	private final int maxRounds;
	private int rounds;

	/**
	 * @param handler answers the prompts
	 */
	public KeyboardInteractiveAuth(Handler handler) {
		this(handler, 10);
	}

	/**
	 * @param maxRounds most INFO_REQUESTs answered, so a server can't keep the client asking forever
	 */
	public KeyboardInteractiveAuth(Handler handler, int maxRounds) {
		this.handler = handler;
		this.maxRounds = maxRounds;
	}

	/**
	 * @return a method that answers every hidden (no echo) prompt with the password, once;
	 * prompts shown as typed get an empty answer
	 */
	public static KeyboardInteractiveAuth password(char[] password) {
		char[] copy = password.clone();
		boolean[] used = {false};
		return new KeyboardInteractiveAuth((name, instruction, prompts, echo) -> {
			String[] ret = new String[prompts.length];
			for (int i = 0; i < prompts.length; i++) {
				if( !echo[i] ) {
					if( used[0] ) {
						// A second password prompt means the first was wrong: don't keep sending it
						return null;
					}
					ret[i] = new String(copy);
					used[0] = true;
				} else {
					ret[i] = "";
				}
			}
			if( used[0] ) {
				Arrays.fill(copy, '\0');
			}
			return ret;
		});
	}

	@Override
	public String getName() {
		return "keyboard-interactive";
	}

	@Override
	public boolean start(IClientAuthContext context) throws IOException {
		// language tag, submethods
		context.send(context.newRequest(getName()).putString("").putString(""));
		return true;
	}

	@Override
	public boolean handle(int msg, SshBuffer message, IClientAuthContext context) throws IOException {
		if( msg != SshConstants.SSH_MSG_USERAUTH_60 ) {
			return false;
		}
		if( ++rounds > maxRounds ) {
			context.methodFailed("Too many keyboard-interactive rounds");
			return true;
		}
		String name = message.getStringUtf8();
		String instruction = message.getStringUtf8();
		message.getString();
		int n = message.getInt();
		if( n > MAX_PROMPTS ) {
			throw new SshException("Too many prompts ("+n+")");
		}
		String[] prompts = new String[n];
		boolean[] echo = new boolean[n];
		for (int i = 0; i < n; i++) {
			prompts[i] = message.getStringUtf8();
			echo[i] = message.getBoolean();
		}
		String[] answers = handler.respond(name, instruction, prompts, echo);
		if( answers == null ) {
			context.methodFailed("Keyboard-interactive cancelled");
			return true;
		}
		if( answers.length != n ) {
			throw new IllegalStateException("The handler gave "+answers.length+" answers to "+n+" prompts");
		}
		SshBuffer b = SshBuffer.message(SshConstants.SSH_MSG_USERAUTH_INFO_RESPONSE).putInt(n);
		for (String a : answers) {
			b.putString(a == null ? "" : a);
		}
		context.send(b);
		return true;
	}

	@Override
	public boolean retry(IClientAuthContext context) {
		return false;
	}
}
