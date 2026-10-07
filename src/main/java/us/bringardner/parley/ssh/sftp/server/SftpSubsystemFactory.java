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
package us.bringardner.parley.ssh.sftp.server;

import java.io.IOException;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.ssh.server.CommandEnvironment;
import us.bringardner.parley.ssh.server.ICommand;
import us.bringardner.parley.ssh.server.ISubsystemFactory;

/**
 * The "sftp" subsystem: an SFTP version 3 server (what OpenSSH's sftp, scp -s, FileZilla,
 * WinSCP, JSch and MINA speak) on any parley-files {@link FileSource}: the local disk,
 * memory, JDBC, another SFTP server...
 *
 * <pre>
 * server.addSubsystem(new SftpSubsystemFactory(env -&gt;
 *         new FileProxyFactory().createFileSource("/srv/sftp/"+env.getUser())));
 * </pre>
 *
 * @author Tony Bringardner
 */
public class SftpSubsystemFactory implements ISubsystemFactory {

	private final ISftpRootProvider roots;
	private volatile boolean readOnly;

	/**
	 * @param roots each user's root directory
	 */
	public SftpSubsystemFactory(ISftpRootProvider roots) {
		this.roots = roots;
	}

	/**
	 * @return every user gets the same root
	 */
	public static SftpSubsystemFactory forRoot(FileSource root) {
		return new SftpSubsystemFactory(env -> root);
	}

	@Override
	public String getName() {
		return "sftp";
	}

	@Override
	public ICommand create(CommandEnvironment env) throws IOException {
		FileSource root = roots.getRoot(env);
		if( root == null ) {
			return null;
		}
		if( !root.isDirectory() ) {
			throw new IOException("SFTP root is not a directory: "+root);
		}
		return new SftpServer(root, readOnly);
	}

	public boolean isReadOnly() {
		return readOnly;
	}

	/**
	 * @param readOnly true to refuse every change (writes, removes, renames, setstat...)
	 */
	public void setReadOnly(boolean readOnly) {
		this.readOnly = readOnly;
	}
}
