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
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.function.IntConsumer;

import us.bringardner.parley.core.BaseObject;

/**
 * Runs exec requests as operating system commands ("sh -c command", or "cmd /c command" on
 * Windows).
 * <p>
 * <b>The commands run as the user the server runs as</b>, whoever logged in, so only give
 * this to servers whose users may run anything that account can. It is not used unless set
 * with {@link SshServer#setCommandFactory(ICommandFactory)}.
 * <p>
 * Of the client's environment variables only LANG and LC_* are passed on (like OpenSSH's
 * default AcceptEnv), and TERM with a pseudo terminal.
 * <p>
 * <b>Pseudo terminals</b>: when the client asks for one (ssh -t) and pty4j is on the class
 * path (an optional dependency), the command runs on a real pseudo terminal, so interactive
 * programs (top, vi, passwords) work, its size follows the client's window, and stdout and
 * stderr both go to the terminal. Without pty4j, commands run without one.
 *
 * @author Tony Bringardner
 * @see ProcessShellFactory
 */
public class ProcessCommandFactory extends BaseObject implements ICommandFactory {

	private final File directory;

	/**
	 * @param directory the commands' working directory, null for the server's
	 */
	public ProcessCommandFactory(File directory) {
		this.directory = directory;
	}

	/**
	 * @return true if commands can get a pseudo terminal (pty4j is on the class path)
	 */
	public static boolean isPtySupported() {
		return PtyProcesses.isAvailable();
	}

	protected static boolean isWindows() {
		return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
	}

	protected List<String> commandLine(String command) {
		return isWindows() ? Arrays.asList("cmd.exe", "/c", command) : Arrays.asList("/bin/sh", "-c", command);
	}

	public File getDirectory() {
		return directory;
	}

	@Override
	public ICommand create(String command, CommandEnvironment env) {
		return processCommand(commandLine(command));
	}

	/**
	 * @return a command that runs this command line, on a pty when the client asked for one
	 * and pty4j is there
	 */
	protected ICommand processCommand(List<String> commandLine) {
		return new ICommand() {
			private volatile Process process;

			@Override
			public void start(CommandEnvironment env, InputStream in, OutputStream out, OutputStream err, IntConsumer exit) throws IOException {
				boolean pty = env.hasPty() && PtyProcesses.isAvailable();
				Process p;
				if( pty ) {
					Map<String, String> penv = new HashMap<String, String>(System.getenv());
					penv.putAll(clientEnvironment(env));
					penv.put("TERM", env.getTerm() == null || env.getTerm().isEmpty() ? "xterm" : env.getTerm());
					p = PtyProcesses.start(commandLine, penv, directory, env.getColumns(), env.getRows());
					env.addWindowChangeListener(() -> PtyProcesses.resize(p, env.getColumns(), env.getRows()));
				} else {
					ProcessBuilder pb = new ProcessBuilder(commandLine);
					if( directory != null ) {
						pb.directory(directory);
					}
					pb.environment().putAll(clientEnvironment(env));
					p = pb.start();
				}
				process = p;
				Executor ex = env.getServer().getExecutor();
				if( pty ) {
					// Closing a pty's input would hang up the terminal: the client's EOF is typed as ^D
					ex.execute(() -> {
						pump(in, p.getOutputStream(), false);
						try {
							p.getOutputStream().write(4);
							p.getOutputStream().flush();
						} catch (IOException e) {
							// the process is gone
						}
					});
				} else {
					ex.execute(() -> pump(in, p.getOutputStream(), true));
				}
				ex.execute(() -> {
					// stdout and stderr are both read before the exit is reported
					Thread errPump = null;
					if( !pty ) {
						errPump = new Thread(() -> pump(p.getErrorStream(), err, false), "ssh-exec-stderr");
						errPump.setDaemon(true);
						errPump.start();
					}
					pump(p.getInputStream(), out, false);
					int status;
					try {
						if( errPump != null ) {
							errPump.join();
						}
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

	/**
	 * @return LANG and LC_* from the client (like OpenSSH's default AcceptEnv)
	 */
	private static Map<String, String> clientEnvironment(CommandEnvironment env) {
		Map<String, String> ret = new HashMap<String, String>();
		for (Map.Entry<String, String> e : env.getEnv().entrySet()) {
			if( e.getKey().equals("LANG") || e.getKey().startsWith("LC_") ) {
				ret.put(e.getKey(), e.getValue());
			}
		}
		return ret;
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
