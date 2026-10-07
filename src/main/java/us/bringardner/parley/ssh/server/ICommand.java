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
import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.IntConsumer;

/**
 * What a session channel runs: a command (exec), a shell or a subsystem (e.g. sftp).
 * Its stdin, stdout and stderr are the channel's streams; it reports its exit status once.
 *
 * @author Tony Bringardner
 * @see AbstractCommand
 */
public interface ICommand {

	/**
	 * Start. Must not block: run the work on another thread ({@link AbstractCommand} does).
	 *
	 * @param in the client's input (EOF when the client is done)
	 * @param out stdout
	 * @param err stderr
	 * @param exit call once with the exit status when done; the channel then closes
	 */
	void start(CommandEnvironment env, InputStream in, OutputStream out, OutputStream err, IntConsumer exit) throws IOException;

	/**
	 * The channel closed (or the session ended) before the command was done: stop it.
	 */
	default void destroy() {
	}
}
