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
package us.bringardner.net.ssh.transport;

import java.util.List;

import us.bringardner.net.ssh.SshConstants;
import us.bringardner.net.ssh.SshException;
import us.bringardner.net.ssh.algorithms.ISshCipher;
import us.bringardner.net.ssh.algorithms.NamedFactory;
import us.bringardner.net.ssh.algorithms.SshAlgorithms;

/**
 * The algorithms both sides agreed on (RFC 4253 7.1): for each list, the first of the
 * client's names that the server also offers. With an AEAD cipher there is no MAC for that
 * direction.
 *
 * @author Tony Bringardner
 */
public final class NegotiatedAlgorithms {

	private final String kex;
	private final String hostKey;
	private final String cipherC2S;
	private final String cipherS2C;
	private final String macC2S;
	private final String macS2C;
	private final String compressionC2S;
	private final String compressionS2C;

	private NegotiatedAlgorithms(String kex, String hostKey, String cipherC2S, String cipherS2C,
			String macC2S, String macS2C, String compressionC2S, String compressionS2C) {
		this.kex = kex;
		this.hostKey = hostKey;
		this.cipherC2S = cipherC2S;
		this.cipherS2C = cipherS2C;
		this.macC2S = macC2S;
		this.macS2C = macS2C;
		this.compressionC2S = compressionC2S;
		this.compressionS2C = compressionS2C;
	}

	/**
	 * @param client the client's proposal
	 * @param server the server's proposal
	 * @param local this side's algorithms, to know which ciphers are AEAD
	 * @throws SshException (KEY_EXCHANGE_FAILED) if a list has nothing in common
	 */
	public static NegotiatedAlgorithms negotiate(KexProposal client, KexProposal server, SshAlgorithms local) throws SshException {
		String kex = pick("key exchange", client, server, KexProposal.KEX, local.getKeyExchangeNames());
		String hostKey = pick("host key", client, server, KexProposal.HOST_KEY, local.getHostKeyAlgorithmNames());
		String c2s = pick("cipher (client to server)", client, server, KexProposal.CIPHER_C2S, local.getCipherNames());
		String s2c = pick("cipher (server to client)", client, server, KexProposal.CIPHER_S2C, local.getCipherNames());
		String macC2S = isAead(local, c2s) ? null : pick("MAC (client to server)", client, server, KexProposal.MAC_C2S, local.getMacNames());
		String macS2C = isAead(local, s2c) ? null : pick("MAC (server to client)", client, server, KexProposal.MAC_S2C, local.getMacNames());
		String compC2S = pick("compression (client to server)", client, server, KexProposal.COMPRESSION_C2S, local.getCompressions());
		String compS2C = pick("compression (server to client)", client, server, KexProposal.COMPRESSION_S2C, local.getCompressions());
		return new NegotiatedAlgorithms(kex, hostKey, c2s, s2c, macC2S, macS2C, compC2S, compS2C);
	}

	private static boolean isAead(SshAlgorithms local, String cipher) {
		NamedFactory<ISshCipher> f = local.findCipher(cipher);
		return f != null && f.create().isAead();
	}

	/**
	 * The first client name the server has, that this side can also run (the lists may hold
	 * markers like kex-strict-c-v00@openssh.com that aren't algorithms).
	 */
	private static String pick(String what, KexProposal client, KexProposal server, int index, List<String> supported) throws SshException {
		List<String> s = server.get(index);
		for (String name : client.get(index)) {
			if( s.contains(name) && supported.contains(name) ) {
				return name;
			}
		}
		throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
				"No common "+what+" algorithm: client "+client.get(index)+", server "+s);
	}

	public String getKeyExchange() {
		return kex;
	}

	public String getHostKey() {
		return hostKey;
	}

	public String getCipherClientToServer() {
		return cipherC2S;
	}

	public String getCipherServerToClient() {
		return cipherS2C;
	}

	/** null with an AEAD cipher */
	public String getMacClientToServer() {
		return macC2S;
	}

	/** null with an AEAD cipher */
	public String getMacServerToClient() {
		return macS2C;
	}

	public String getCompressionClientToServer() {
		return compressionC2S;
	}

	public String getCompressionServerToClient() {
		return compressionS2C;
	}

	@Override
	public String toString() {
		return "kex="+kex+" hostkey="+hostKey+" c2s="+cipherC2S+(macC2S == null ? "" : "/"+macC2S)
				+" s2c="+cipherS2C+(macS2C == null ? "" : "/"+macS2C);
	}
}
