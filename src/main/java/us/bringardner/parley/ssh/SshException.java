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
package us.bringardner.parley.ssh;

import java.io.IOException;

/**
 * An SSH protocol failure, with the disconnect reason (RFC 4253 11.1) to send or that was received.
 *
 * @author Tony Bringardner
 */
public class SshException extends IOException {

	private static final long serialVersionUID = 1L;
	private final int reason;

	public SshException(int reason, String message) {
		super(message);
		this.reason = reason;
	}

	public SshException(int reason, String message, Throwable cause) {
		super(message, cause);
		this.reason = reason;
	}

	/**
	 * A protocol error (SSH_DISCONNECT_PROTOCOL_ERROR).
	 */
	public SshException(String message) {
		this(SshConstants.SSH_DISCONNECT_PROTOCOL_ERROR, message);
	}

	/**
	 * @return the disconnect reason code (SshConstants.SSH_DISCONNECT_...)
	 */
	public int getReason() {
		return reason;
	}
}
