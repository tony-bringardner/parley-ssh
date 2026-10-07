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
package us.bringardner.net.ssh.sftp;

import java.io.IOException;

/**
 * An SFTP request failed: the server's SSH_FXP_STATUS code and message.
 *
 * @author Tony Bringardner
 */
public class SftpException extends IOException {

	private static final long serialVersionUID = 1L;
	private final int status;
	private final String path;

	public SftpException(int status, String message, String path) {
		super(SftpConstants.statusName(status)+(path == null ? "" : " "+path)+(message == null || message.isEmpty() ? "" : ": "+message));
		this.status = status;
		this.path = path;
	}

	/**
	 * @return SftpConstants.SSH_FX_...
	 */
	public int getStatus() {
		return status;
	}

	/**
	 * @return the path the request was about, or null
	 */
	public String getPath() {
		return path;
	}
}
