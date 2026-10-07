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
import java.util.List;
import java.util.Map;

import com.pty4j.PtyProcess;
import com.pty4j.PtyProcessBuilder;
import com.pty4j.WinSize;

/**
 * Processes on a pseudo terminal, through pty4j (an optional dependency). The only class
 * that uses pty4j, so the others load without it: check {@link #isAvailable()} first.
 *
 * @author Tony Bringardner
 */
final class PtyProcesses {

	private static final boolean AVAILABLE;

	static {
		boolean ok;
		try {
			Class.forName("com.pty4j.PtyProcessBuilder", false, PtyProcesses.class.getClassLoader());
			ok = true;
		} catch (ClassNotFoundException | LinkageError e) {
			ok = false;
		}
		AVAILABLE = ok;
	}

	private PtyProcesses() {
	}

	/**
	 * @return true if pty4j is on the class path
	 */
	static boolean isAvailable() {
		return AVAILABLE;
	}

	/**
	 * @return the process, with stdout and stderr both on the terminal (its input stream)
	 */
	static Process start(List<String> command, Map<String, String> env, File directory, int columns, int rows) throws IOException {
		PtyProcessBuilder b = new PtyProcessBuilder(command.toArray(new String[0]))
				.setEnvironment(env)
				.setInitialColumns(columns > 0 ? columns : 80)
				.setInitialRows(rows > 0 ? rows : 24)
				.setRedirectErrorStream(true);
		if( directory != null ) {
			b.setDirectory(directory.getPath());
		}
		return b.start();
	}

	static void resize(Process p, int columns, int rows) {
		if( p instanceof PtyProcess && columns > 0 && rows > 0 ) {
			((PtyProcess) p).setWinSize(new WinSize(columns, rows));
		}
	}
}
