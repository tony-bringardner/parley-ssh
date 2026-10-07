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
package us.bringardner.net.ssh.server;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.IntConsumer;

import us.bringardner.core.BaseObject;

/**
 * A command that runs {@link #run} on the server's executor and exits with what it returns.
 * {@link #destroy()} interrupts it.
 *
 * @author Tony Bringardner
 */
public abstract class AbstractCommand extends BaseObject implements ICommand {

	private volatile Thread thread;
	private volatile boolean destroyed;

	/**
	 * Do the work, blocking as needed.
	 *
	 * @return the exit status
	 */
	protected abstract int run(CommandEnvironment env, InputStream in, OutputStream out, OutputStream err) throws Exception;

	@Override
	public void start(CommandEnvironment env, InputStream in, OutputStream out, OutputStream err, IntConsumer exit) {
		env.getServer().getExecutor().execute(() -> {
			thread = Thread.currentThread();
			int status;
			try {
				status = destroyed ? 255 : run(env, in, out, err);
				out.flush();
				err.flush();
			} catch (Exception e) {
				if( !destroyed ) {
					logDebug("Command failed", e);
				}
				status = 1;
			} finally {
				thread = null;
				// Don't leave an interrupt behind on a pooled thread
				Thread.interrupted();
			}
			exit.accept(status);
		});
	}

	@Override
	public void destroy() {
		destroyed = true;
		Thread t = thread;
		if( t != null ) {
			t.interrupt();
		}
	}

	protected boolean isDestroyed() {
		return destroyed;
	}
}
