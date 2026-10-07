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

import java.io.File;
import java.util.Arrays;
import java.util.List;

/**
 * The interactive shell of the operating system ("ssh host"): the user's login shell ($SHELL,
 * else /bin/sh) with -l, or cmd.exe on Windows. With pty4j on the class path (an optional
 * dependency) and a client that asks for a terminal (ssh does for a shell), it runs on a
 * real pseudo terminal: prompts, line editing, job control, top and vi work. Without one
 * it reads commands as lines.
 * <p>
 * <b>The shell runs as the user the server runs as</b>, whoever logged in: give it only to
 * users who may do anything that account can (with an access control list, they need the
 * "shell" permission). It is not used unless set with
 * {@link SshServer#setShellFactory(IShellFactory)} or the ShellFactory property.
 *
 * @author Tony Bringardner
 */
public class ProcessShellFactory extends ProcessCommandFactory implements IShellFactory {

	/**
	 * The shell starts in the server's working directory.
	 */
	public ProcessShellFactory() {
		this(null);
	}

	/**
	 * @param directory the shell's working directory, null for the server's
	 */
	public ProcessShellFactory(File directory) {
		super(directory);
	}

	/**
	 * @return the shell's command line
	 */
	protected List<String> shellCommandLine() {
		if( isWindows() ) {
			return Arrays.asList("cmd.exe");
		}
		String shell = System.getenv("SHELL");
		return Arrays.asList(shell == null || shell.isEmpty() ? "/bin/sh" : shell, "-l");
	}

	@Override
	public ICommand create(CommandEnvironment env) {
		return processCommand(shellCommandLine());
	}
}
