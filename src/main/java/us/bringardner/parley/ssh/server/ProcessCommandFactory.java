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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.IntConsumer;

import us.bringardner.parley.core.BaseObject;

/**
 * Runs exec requests as operating system commands ("sh -c command", or "cmd /c command" on
 * Windows) with ProcessBuilder.
 * <p>
 * <b>The commands run as the user the server runs as</b>, whoever logged in, so only give
 * this to servers whose users may run anything that account can. It is not used unless set
 * with {@link SshServer#setCommandFactory(ICommandFactory)}.
 * <p>
 * Of the client's environment variables only LANG and LC_* are passed on (like OpenSSH's
 * default AcceptEnv). There is no pseudo terminal: Java can't make one.
 *
 * @author Tony Bringardner
 */
public class ProcessCommandFactory extends BaseObject implements ICommandFactory {

	private final File directory;

	/**
	 * @param directory the commands' working directory, null for the server's
	 */
	public ProcessCommandFactory(File directory) {
		this.directory = directory;
	}

	protected List<String> commandLine(String command) {
		boolean windows = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
		return windows ? Arrays.asList("cmd.exe", "/c", command) : Arrays.asList("/bin/sh", "-c", command);
	}

	@Override
	public ICommand create(String command, CommandEnvironment env) {
		return new ICommand() {
			private volatile Process process;

			@Override
			public void start(CommandEnvironment env, InputStream in, OutputStream out, OutputStream err, IntConsumer exit) throws IOException {
				ProcessBuilder pb = new ProcessBuilder(commandLine(command));
				if( directory != null ) {
					pb.directory(directory);
				}
				Map<String, String> penv = pb.environment();
				for (Map.Entry<String, String> e : env.getEnv().entrySet()) {
					if( e.getKey().equals("LANG") || e.getKey().startsWith("LC_") ) {
						penv.put(e.getKey(), e.getValue());
					}
				}
				Process p = pb.start();
				process = p;
				java.util.concurrent.Executor ex = env.getServer().getExecutor();
				ex.execute(() -> pump(in, p.getOutputStream(), true));
				ex.execute(() -> {
					// stdout and stderr are both read before the exit is reported
					Thread errPump = new Thread(() -> pump(p.getErrorStream(), err, false), "ssh-exec-stderr");
					errPump.setDaemon(true);
					errPump.start();
					pump(p.getInputStream(), out, false);
					int status;
					try {
						errPump.join();
						status = p.waitFor();
					} catch (InterruptedException e) {
						Thread.currentThread().interrupt();
						p.destroyForcibly();
						status = 255;
					}
					exit.accept(status);
				});
			}

			@Override
			public void destroy() {
				Process p = process;
				if( p != null ) {
					p.destroy();
				}
			}
		};
	}

	private void pump(InputStream from, OutputStream to, boolean closeTo) {
		byte[] b = new byte[16*1024];
		try {
			int n;
			while( (n = from.read(b)) > 0 ) {
				to.write(b, 0, n);
				to.flush();
			}
		} catch (IOException e) {
			logDebug("Stream copy ended: "+e.getMessage());
		} finally {
			if( closeTo ) {
				try {
					to.close();
				} catch (IOException e) {
					// done
				}
			}
		}
	}
}
