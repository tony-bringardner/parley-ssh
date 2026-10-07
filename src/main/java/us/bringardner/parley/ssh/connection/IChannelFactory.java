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
package us.bringardner.parley.ssh.connection;

import java.io.IOException;

import us.bringardner.parley.ssh.SshBuffer;

/**
 * Accepts channels the peer opens, of one type (a server's "session", a client's
 * "forwarded-tcpip"...). Registered with {@link ConnectionService#addChannelFactory(String, IChannelFactory)}.
 *
 * @author Tony Bringardner
 */
@FunctionalInterface
public interface IChannelFactory {

	/**
	 * @param type the channel type
	 * @param openData the type specific data of SSH_MSG_CHANNEL_OPEN
	 * @return the new channel, or null to refuse it (SSH_OPEN_ADMINISTRATIVELY_PROHIBITED)
	 */
	SshChannel create(String type, SshBuffer openData) throws IOException;
}
