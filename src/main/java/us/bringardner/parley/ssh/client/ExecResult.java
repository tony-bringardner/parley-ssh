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
package us.bringardner.parley.ssh.client;

import java.nio.charset.StandardCharsets;

/**
 * What a command run by {@link ClientSession#exec(String, byte[], long)} produced.
 *
 * @author Tony Bringardner
 */
public final class ExecResult {

	private final Integer exitStatus;
	private final String exitSignal;
	private final byte[] stdout;
	private final byte[] stderr;

	ExecResult(Integer exitStatus, String exitSignal, byte[] stdout, byte[] stderr) {
		this.exitStatus = exitStatus;
		this.exitSignal = exitSignal;
		this.stdout = stdout;
		this.stderr = stderr;
	}

	/**
	 * @return the exit status, null if the command was killed by a signal or the server didn't say
	 */
	public Integer getExitStatus() {
		return exitStatus;
	}

	public String getExitSignal() {
		return exitSignal;
	}

	public byte[] getStdout() {
		return stdout.clone();
	}

	public byte[] getStderr() {
		return stderr.clone();
	}

	/**
	 * @return stdout as UTF-8 text
	 */
	public String getStdoutText() {
		return new String(stdout, StandardCharsets.UTF_8);
	}

	public String getStderrText() {
		return new String(stderr, StandardCharsets.UTF_8);
	}

	/**
	 * @return true if the command ended with exit status 0
	 */
	public boolean isSuccess() {
		return exitStatus != null && exitStatus == 0;
	}

	@Override
	public String toString() {
		return "ExecResult[exit="+(exitStatus != null ? exitStatus : "signal "+exitSignal)+", stdout="+stdout.length+" bytes, stderr="+stderr.length+" bytes]";
	}
}
