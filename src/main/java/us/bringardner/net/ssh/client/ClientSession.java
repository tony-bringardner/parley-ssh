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
package us.bringardner.net.ssh.client;

import java.io.IOException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import us.bringardner.net.ssh.SshBuffer;
import us.bringardner.net.ssh.SshConstants;
import us.bringardner.net.ssh.SshException;
import us.bringardner.net.ssh.algorithms.ISignatureAlgorithm;
import us.bringardner.net.ssh.algorithms.SshAlgorithms;
import us.bringardner.net.ssh.algorithms.SshPublicKeys;
import us.bringardner.net.ssh.transport.SshTransport;

/**
 * The client end of an SSH connection, made by {@link SshClient#connect(String, int)}.
 * <p>
 * The key exchange checks the server's host key with the client's {@link IHostKeyVerifier};
 * {@link #getReadyFuture()} completes once it is done and the keys are in use.
 *
 * @author Tony Bringardner
 */
public class ClientSession extends SshTransport {

	private final String host;
	private final int port;
	private final IHostKeyVerifier verifier;
	private final CompletableFuture<ClientSession> ready = new CompletableFuture<ClientSession>();
	private volatile PublicKey hostKey;
	// One service request at a time (RFC 4253 10)
	private CompletableFuture<Void> serviceRequest;
	private String requestedService;

	protected ClientSession(String host, int port, IHostKeyVerifier verifier, SshAlgorithms algorithms, String version, SecureRandom random) {
		super(true, algorithms, version, random);
		this.host = host;
		this.port = port;
		this.verifier = verifier;
	}

	/**
	 * @return completes with this session when the first key exchange is done (the host
	 * key is trusted), or fails with the reason
	 */
	public CompletableFuture<ClientSession> getReadyFuture() {
		return ready;
	}

	public String getHost() {
		return host;
	}

	public int getPort() {
		return port;
	}

	/**
	 * @return the server's host key, null until the key exchange checked it
	 */
	public PublicKey getServerHostKey() {
		return hostKey;
	}

	/**
	 * Ask for a service, e.g. {@link SshConstants#SERVICE_USERAUTH}.
	 *
	 * @return completes when the server accepts it; fails if it refuses (it disconnects)
	 */
	public synchronized CompletableFuture<Void> requestService(String name) {
		CompletableFuture<Void> ret = new CompletableFuture<Void>();
		if( serviceRequest != null ) {
			ret.completeExceptionally(new IllegalStateException("A service request is already waiting for "+requestedService));
			return ret;
		}
		serviceRequest = ret;
		requestedService = name;
		try {
			send(SshBuffer.message(SshConstants.SSH_MSG_SERVICE_REQUEST).putString(name));
		} catch (IOException e) {
			serviceRequest = null;
			ret.completeExceptionally(e);
		}
		return ret;
	}

	@Override
	protected boolean handleMessage(int msg, SshBuffer message) throws Exception {
		if( msg == SshConstants.SSH_MSG_SERVICE_ACCEPT ) {
			String name = message.getStringUtf8();
			CompletableFuture<Void> f;
			synchronized (this) {
				if( serviceRequest == null || !name.equals(requestedService) ) {
					throw new SshException("Unexpected SERVICE_ACCEPT for "+name);
				}
				f = serviceRequest;
				serviceRequest = null;
				requestedService = null;
			}
			f.complete(null);
			return true;
		}
		return false;
	}

	@Override
	protected void onReady() {
		ready.complete(this);
	}

	@Override
	protected void onClosed(Throwable reason) {
		ready.completeExceptionally(reason);
		CompletableFuture<Void> f;
		synchronized (this) {
			f = serviceRequest;
			serviceRequest = null;
		}
		if( f != null ) {
			f.completeExceptionally(reason);
		}
	}

	/**
	 * Algorithms for key types already known for the host go first, so the server uses the
	 * key the verifier knows rather than one of another type (as OpenSSH does).
	 */
	@Override
	protected List<String> getHostKeyAlgorithmsToOffer() {
		List<String> all = super.getHostKeyAlgorithmsToOffer();
		List<String> known = verifier.getKnownKeyTypes(host, port);
		if( known.isEmpty() ) {
			return all;
		}
		List<String> first = new ArrayList<String>();
		List<String> rest = new ArrayList<String>();
		for (String name : all) {
			ISignatureAlgorithm s = getAlgorithms().findHostKeyAlgorithm(name);
			(s != null && known.contains(s.getKeyType()) ? first : rest).add(name);
		}
		first.addAll(rest);
		return first;
	}

	@Override
	protected void verifyHostKey(byte[] blob, byte[] signature, byte[] exchangeHash, String algorithm) throws IOException {
		ISignatureAlgorithm sig = getAlgorithms().findHostKeyAlgorithm(algorithm);
		if( sig == null ) {
			throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "No host key algorithm "+algorithm);
		}
		String type = SshPublicKeys.blobType(blob);
		if( !sig.getKeyType().equals(type) ) {
			throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Host key is "+type+", expected "+sig.getKeyType());
		}
		PublicKey key = SshPublicKeys.decode(blob);
		if( !sig.verify(key, exchangeHash, signature) ) {
			throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Bad host key signature");
		}
		PublicKey known = hostKey;
		if( known == null ) {
			if( !verifier.verify(host, port, key) ) {
				throw new SshException(SshConstants.SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE,
						"Host key "+type+" "+SshPublicKeys.fingerprint(key)+" for "+host+" is not trusted");
			}
			hostKey = key;
		} else if( !Arrays.equals(SshPublicKeys.encode(known), blob) ) {
			throw new SshException(SshConstants.SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, "The host key changed during re-keying");
		}
	}

	@Override
	public String toString() {
		return "ClientSession["+host+":"+port+(isReady() ? ", "+getNegotiated() : "")+"]";
	}
}
