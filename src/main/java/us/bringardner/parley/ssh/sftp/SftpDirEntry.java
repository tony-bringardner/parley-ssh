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
package us.bringardner.parley.ssh.sftp;

/**
 * One entry of a directory listing (SSH_FXP_NAME).
 *
 * @author Tony Bringardner
 */
public final class SftpDirEntry {

	private final String name;
	private final String longName;
	private final SftpAttrs attrs;

	public SftpDirEntry(String name, String longName, SftpAttrs attrs) {
		this.name = name;
		this.longName = longName;
		this.attrs = attrs;
	}

	public String getName() {
		return name;
	}

	/**
	 * @return the server's "ls -l" line (version 3 has the owner and group names only here)
	 */
	public String getLongName() {
		return longName;
	}

	/**
	 * @return the entry's attributes; a link is not followed
	 */
	public SftpAttrs getAttrs() {
		return attrs;
	}

	@Override
	public String toString() {
		return longName == null || longName.isEmpty() ? name : longName;
	}
}
