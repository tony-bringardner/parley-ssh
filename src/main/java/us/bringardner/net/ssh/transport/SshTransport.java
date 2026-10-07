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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.locks.ReentrantLock;

import us.bringardner.core.BaseObject;
import us.bringardner.net.framework.nio.INioConnection;
import us.bringardner.net.framework.nio.INioHandler;
import us.bringardner.net.framework.nio.LineFrameDecoder;
import us.bringardner.net.framework.server.Server;
import us.bringardner.net.ssh.SshBuffer;
import us.bringardner.net.ssh.SshConstants;
import us.bringardner.net.ssh.SshException;
import us.bringardner.net.ssh.algorithms.IKexContext;
import us.bringardner.net.ssh.algorithms.IKeyExchange;
import us.bringardner.net.ssh.algorithms.ISshCipher;
import us.bringardner.net.ssh.algorithms.ISshMac;
import us.bringardner.net.ssh.algorithms.NamedFactory;
import us.bringardner.net.ssh.algorithms.SshAlgorithms;

/**
 * The SSH transport layer (RFC 4253), shared by the client and the server: identification
 * strings, binary packets, algorithm negotiation, key exchange, re-keying and disconnect.
 * It is the {@link INioHandler} of one connection; subclasses add the services on top
 * (user authentication, connections) through {@link #handleMessage(int, SshBuffer)}.
 * <p>
 * <b>Key exchange.</b> Each side sends SSH_MSG_KEXINIT, the key exchange runs, each side
 * sends SSH_MSG_NEWKEYS and from then on uses the new keys in that direction. While a key
 * exchange is running, messages other than key exchange messages are queued and sent with
 * the new keys. Re-keying starts after {@link #setRekeyBytes(long)} bytes or
 * {@link #setRekeyTime(long)} ms, or when either side asks.
 * <p>
 * <b>Strict key exchange</b> (kex-strict-*-v00@openssh.com, the Terrapin fix): when both sides
 * offer it, the first key exchange accepts nothing but key exchange messages, KEXINIT must be
 * the first packet, and the sequence numbers start again at 0 after each NEWKEYS.
 * <p>
 * <b>Threads.</b> Incoming messages are handled one at a time on the connection's handler
 * thread. {@link #send(SshBuffer)} may be called from any thread; packets are encoded and
 * queued under a lock, so they go out in order with the right sequence numbers.
 *
 * @author Tony Bringardner
 */
public abstract class SshTransport extends BaseObject implements INioHandler {

	public static final String DEFAULT_VERSION = "SSH-2.0-BjlSsh_1.0";
	/** Re-key after this much data in either direction (RFC 4253 9 suggests 1 GB) */
	public static final long DEFAULT_REKEY_BYTES = 1L << 30;
	/** Re-key after this long (RFC 4253 9 suggests an hour) */
	public static final long DEFAULT_REKEY_TIME = 60*60*1000L;
	/** A client accepts this many lines before the server's identification (RFC 4253 4.2) */
	private static final int MAX_PRE_VERSION_LINES = 100;
	/** Longest identification string, without CR LF (RFC 4253 4.2: 255 with CR LF) */
	private static final int MAX_VERSION_LENGTH = 253;

	protected final boolean client;
	private final SshAlgorithms algorithms;
	private final String localVersion;
	private final SecureRandom random;
	private final SshPacketDecoder decoder;
	private final SshPacketEncoder encoder;
	// Guards the key exchange state and the encoder
	private final ReentrantLock lock = new ReentrantLock();

	private volatile INioConnection connection;
	private volatile String peerVersion;
	private int preVersionLines;
	private volatile long rekeyBytes = DEFAULT_REKEY_BYTES;
	private volatile long rekeyTime = DEFAULT_REKEY_TIME;

	// ---- key exchange state, under lock
	private KexProposal localProposal;
	private KexProposal peerProposal;
	private NegotiatedAlgorithms pendingNegotiated;
	private volatile NegotiatedAlgorithms negotiated;
	private IKeyExchange kex;
	private boolean ignoreNextKexPacket;
	// Keys waiting for the peer's NEWKEYS
	private ISshCipher pendingInCipher;
	private ISshMac pendingInMac;
	private boolean pendingIn;
	// true from sending KEXINIT until sending NEWKEYS (and before the first KEXINIT): only key exchange messages go out
	private boolean outputBlocked = true;
	// true from sending or receiving KEXINIT until receiving NEWKEYS
	private boolean kexRunning;
	// A key exchange finished, finishKexIfDone() hasn't told anyone yet
	private boolean kexCompleted;
	private volatile boolean firstKexDone;
	private volatile int kexCount;
	private volatile boolean strictKex;
	private volatile byte[] sessionId;
	private long lastKexTime = System.currentTimeMillis();
	// Sequence number our last KEXINIT went out with, to recognize SSH_MSG_UNIMPLEMENTED for it
	private long kexInitSequence = -1;
	private final List<SshBuffer> queued = new ArrayList<SshBuffer>();
	private final List<CompletableFuture<Void>> kexWaiters = new ArrayList<CompletableFuture<Void>>();
	private volatile Map<String, byte[]> peerExtensions = Collections.emptyMap();

	private volatile boolean disconnecting;
	private volatile boolean closed;
	private volatile Throwable failure;

	/**
	 * @param client true for the client side
	 * @param algorithms what to offer (copied)
	 * @param localVersion this side's identification string, e.g. "SSH-2.0-BjlSsh_1.0"
	 * @param random for cookies, padding and keys
	 */
	protected SshTransport(boolean client, SshAlgorithms algorithms, String localVersion, SecureRandom random) {
		if( !localVersion.startsWith("SSH-2.0-") || localVersion.length() > MAX_VERSION_LENGTH ) {
			throw new IllegalArgumentException("Bad identification string "+localVersion);
		}
		this.client = client;
		this.algorithms = algorithms.copy();
		this.localVersion = localVersion;
		this.random = random;
		this.decoder = new SshPacketDecoder();
		this.encoder = new SshPacketEncoder(random);
		getLogger().setLevel(Server.getDefaultLogLevel());
	}

	// ------------------------------------------------------------------ for subclasses

	/**
	 * A service message (anything but the transport's own), on the handler thread.
	 *
	 * @param msg the message number
	 * @param message the message, read position after the number
	 * @return false if the message isn't known (SSH_MSG_UNIMPLEMENTED is sent)
	 */
	protected abstract boolean handleMessage(int msg, SshBuffer message) throws Exception;

	/**
	 * The first key exchange is done: services can start (a client requests ssh-userauth).
	 */
	protected abstract void onReady() throws Exception;

	/**
	 * The connection is gone, after a disconnect or a failure.
	 *
	 * @param reason why (an SshException with the disconnect reason, or the I/O error)
	 */
	protected abstract void onClosed(Throwable reason);

	/**
	 * Client side: check the server's host key and its signature of the exchange hash.
	 * @see IKexContext#verifyHostKey(byte[], byte[], byte[])
	 */
	protected void verifyHostKey(byte[] hostKey, byte[] signature, byte[] exchangeHash, String algorithm) throws IOException {
		throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Host keys are checked by clients");
	}

	/**
	 * Server side: the blob of the host key for the algorithm.
	 */
	protected byte[] getHostKey(String algorithm) throws IOException {
		throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Only servers have host keys");
	}

	/**
	 * Server side: sign the exchange hash with the host key for the algorithm.
	 */
	protected byte[] signExchangeHash(byte[] exchangeHash, String algorithm) throws IOException {
		throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Only servers have host keys");
	}

	/**
	 * @return the host key algorithms to offer: all the configured ones; a server offers only
	 * those it has a key for
	 */
	protected List<String> getHostKeyAlgorithmsToOffer() {
		return algorithms.getHostKeyAlgorithmNames();
	}

	/**
	 * The peer sent SSH_MSG_EXT_INFO (RFC 8308), e.g. the server's server-sig-algs.
	 */
	protected void onExtensions(Map<String, byte[]> extensions) {
	}

	// ------------------------------------------------------------------ INioHandler

	@Override
	public void onConnect(INioConnection connection) throws Exception {
		this.connection = connection;
		if( disconnecting ) {
			// Given up on (e.g. the connect timed out) before the connection was made
			connection.close();
			return;
		}
		logDebug(() -> "Connected "+connection.getRemoteAddress()+", sending "+localVersion);
		connection.writeLine(localVersion);
		// KEXINIT may follow the identification at once (RFC 4253 7.1)
		lock.lock();
		try {
			sendKexInit();
		} finally {
			lock.unlock();
		}
	}

	@Override
	public void onMessage(INioConnection connection, ByteBuffer frame) throws Exception {
		if( disconnecting || closed ) {
			return;
		}
		try {
			if( peerVersion == null ) {
				handleVersionLine(connection, LineFrameDecoder.toString(frame));
			} else {
				handlePacket(frame);
			}
		} catch (SshException e) {
			logDebug("SSH error, disconnecting", e);
			fail(e);
			disconnect(e.getReason(), e.getMessage());
		} catch (Exception e) {
			logError("Error handling a message, disconnecting", e);
			fail(e);
			disconnect(SshConstants.SSH_DISCONNECT_BY_APPLICATION, "Internal error");
		}
	}

	@Override
	public void onError(INioConnection connection, Throwable error) {
		logDebug("Connection error", error);
		fail(error);
	}

	@Override
	public void onClose(INioConnection connection) {
		closed = true;
		Throwable reason = failure;
		if( reason == null ) {
			reason = new SshException(SshConstants.SSH_DISCONNECT_CONNECTION_LOST, "Connection closed");
		}
		List<CompletableFuture<Void>> waiters;
		lock.lock();
		try {
			waiters = new ArrayList<CompletableFuture<Void>>(kexWaiters);
			kexWaiters.clear();
			queued.clear();
		} finally {
			lock.unlock();
		}
		for (CompletableFuture<Void> f : waiters) {
			f.completeExceptionally(reason);
		}
		onClosed(reason);
	}

	/**
	 * Remember the first failure, it is the reason given to waiters.
	 */
	protected void fail(Throwable error) {
		if( failure == null ) {
			failure = error;
		}
	}

	// ------------------------------------------------------------------ identification

	private void handleVersionLine(INioConnection connection, String line) throws SshException {
		if( !line.startsWith("SSH-") ) {
			// A server may send other lines first (RFC 4253 4.2); a client may not
			if( !client || ++preVersionLines > MAX_PRE_VERSION_LINES ) {
				throw new SshException(SshConstants.SSH_DISCONNECT_PROTOCOL_ERROR, "Expected an SSH identification string");
			}
			return;
		}
		if( line.length() > MAX_VERSION_LENGTH ) {
			throw new SshException("Identification string too long");
		}
		for (int i = 0; i < line.length(); i++) {
			char c = line.charAt(i);
			if( c < 0x20 || c > 0x7e ) {
				throw new SshException("Invalid character in the identification string");
			}
		}
		if( !line.startsWith("SSH-2.0-") && !line.startsWith("SSH-1.99-") ) {
			throw new SshException(SshConstants.SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED, "Unsupported protocol version: "+line);
		}
		peerVersion = line;
		logDebug(() -> "Peer is "+line);
		// Binary packets from here on; bytes already read move to the new decoder
		connection.setDecoder(decoder);
	}

	// ------------------------------------------------------------------ packets in

	private void handlePacket(ByteBuffer frame) throws Exception {
		SshBuffer message = SshBuffer.wrap(frame);
		int msg = message.getByte();
		if( isDebugEnabled() ) {
			logDebug("Received "+SshConstants.messageName(msg));
		}
		if( msg == SshConstants.SSH_MSG_KEXINIT || msg == SshConstants.SSH_MSG_NEWKEYS
				|| (msg >= SshConstants.SSH_MSG_KEX_FIRST && msg <= SshConstants.SSH_MSG_KEX_LAST) ) {
			lock.lock();
			try {
				if( msg == SshConstants.SSH_MSG_KEXINIT ) {
					receivedKexInit(frame);
				} else if( msg == SshConstants.SSH_MSG_NEWKEYS ) {
					receivedNewKeys();
				} else {
					receivedKexMessage(msg, message);
				}
			} finally {
				lock.unlock();
			}
			finishKexIfDone();
			return;
		}
		if( msg == SshConstants.SSH_MSG_DISCONNECT ) {
			int reason = message.getInt();
			String text = message.getStringUtf8();
			logDebug(() -> "Peer disconnected ("+reason+"): "+text);
			fail(new SshException(reason, "Disconnected by peer: "+text));
			disconnecting = true;
			connection.close();
			return;
		}
		if( !firstKexDone && strictKex ) {
			// Strict: nothing but key exchange messages until the first NEWKEYS
			throw new SshException("Unexpected "+SshConstants.messageName(msg)+" during the strict key exchange");
		}
		switch (msg) {
		case SshConstants.SSH_MSG_IGNORE:
		case SshConstants.SSH_MSG_DEBUG:
			return;
		case SshConstants.SSH_MSG_UNIMPLEMENTED:
			receivedUnimplemented(message.getUInt());
			return;
		case SshConstants.SSH_MSG_EXT_INFO:
			receivedExtInfo(message);
			return;
		default:
		}
		if( !firstKexDone ) {
			throw new SshException("Unexpected "+SshConstants.messageName(msg)+" before the key exchange");
		}
		checkRekey();
		if( !handleMessage(msg, message) ) {
			send(SshBuffer.message(SshConstants.SSH_MSG_UNIMPLEMENTED).putInt(decoder.getLastSequence()));
		}
	}

	/**
	 * Some servers refuse to re-key before the user is authenticated (OpenSSH 10 answers the 
	 * KEXINIT with SSH_MSG_UNIMPLEMENTED). Then the attempt is dropped: the current keys stay 
	 * in use, what was queued goes out, and rekey() callers get an error.
	 */
	private void receivedUnimplemented(long sequence) throws IOException {
		List<CompletableFuture<Void>> refused = null;
		lock.lock();
		try {
			if( firstKexDone && kexRunning && peerProposal == null && sequence == kexInitSequence ) {
				logDebug("Peer refused to re-key");
				localProposal = null;
				kexRunning = false;
				outputBlocked = false;
				// Don't try again at once
				lastKexTime = System.currentTimeMillis();
				refused = new ArrayList<CompletableFuture<Void>>(kexWaiters);
				kexWaiters.clear();
				List<SshBuffer> tmp = new ArrayList<SshBuffer>(queued);
				queued.clear();
				for (SshBuffer b : tmp) {
					writePacket(b);
				}
			} else {
				logDebug("Peer didn't understand packet "+sequence);
			}
		} finally {
			lock.unlock();
		}
		if( refused != null ) {
			for (CompletableFuture<Void> f : refused) {
				f.completeExceptionally(new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "The peer refused to re-key"));
			}
		}
	}

	private void receivedExtInfo(SshBuffer message) throws SshException {
		long count = message.getUInt();
		if( count > 100 ) {
			throw new SshException("Too many extensions");
		}
		Map<String, byte[]> ext = new LinkedHashMap<String, byte[]>();
		for (long i = 0; i < count; i++) {
			ext.put(message.getStringUtf8(), message.getString());
		}
		peerExtensions = Collections.unmodifiableMap(ext);
		onExtensions(peerExtensions);
	}

	// ------------------------------------------------------------------ key exchange (under lock)

	/**
	 * Send our KEXINIT and block other output until NEWKEYS.
	 */
	private void sendKexInit() throws IOException {
		if( localProposal != null || closed ) {
			return;
		}
		List<String> kexNames = new ArrayList<String>(algorithms.getKeyExchangeNames());
		if( !firstKexDone ) {
			// Markers, only meaningful in the first key exchange
			kexNames.add(client ? SshConstants.KEX_STRICT_CLIENT : SshConstants.KEX_STRICT_SERVER);
			if( client ) {
				kexNames.add(SshConstants.EXT_INFO_CLIENT);
			}
		}
		List<String> ciphers = algorithms.getCipherNames();
		List<String> macs = algorithms.getMacNames();
		List<String> comp = algorithms.getCompressions();
		List<String> none = Collections.emptyList();
		localProposal = KexProposal.create(random, Arrays.asList(kexNames, getHostKeyAlgorithmsToOffer(),
				ciphers, ciphers, macs, macs, comp, comp, none, none));
		outputBlocked = true;
		kexRunning = true;
		kexInitSequence = encoder.getSequence();
		writePacket(new SshBuffer(localProposal.getPayload()));
		logDebug("Sent KEXINIT");
	}

	private void receivedKexInit(ByteBuffer frame) throws IOException {
		if( peerProposal != null ) {
			throw new SshException("KEXINIT during a key exchange");
		}
		byte[] payload = new byte[frame.remaining()];
		frame.duplicate().get(payload);
		peerProposal = KexProposal.parse(payload);
		kexRunning = true;
		sendKexInit();
		KexProposal c = client ? localProposal : peerProposal;
		KexProposal s = client ? peerProposal : localProposal;
		if( !firstKexDone ) {
			strictKex = c.get(KexProposal.KEX).contains(SshConstants.KEX_STRICT_CLIENT)
					&& s.get(KexProposal.KEX).contains(SshConstants.KEX_STRICT_SERVER);
			if( strictKex && decoder.getLastSequence() != 0 ) {
				throw new SshException("Strict key exchange: KEXINIT was not the first packet");
			}
		}
		pendingNegotiated = NegotiatedAlgorithms.negotiate(c, s, algorithms);
		logDebug(() -> "Negotiated "+pendingNegotiated+(strictKex ? " (strict)" : ""));
		if( peerProposal.isFirstKexPacketFollows() ) {
			// The peer guessed; a wrong guess means its next key exchange packet is ignored (RFC 4253 7)
			List<String> pk = peerProposal.get(KexProposal.KEX);
			List<String> ph = peerProposal.get(KexProposal.HOST_KEY);
			ignoreNextKexPacket = pk.isEmpty() || ph.isEmpty() || !pk.get(0).equals(pendingNegotiated.getKeyExchange())
					|| !ph.get(0).equals(pendingNegotiated.getHostKey());
		}
		NamedFactory<IKeyExchange> f = algorithms.findKeyExchange(pendingNegotiated.getKeyExchange());
		kex = f.create();
		kex.start(new KexContext());
	}

	private void receivedKexMessage(int msg, SshBuffer message) throws IOException {
		if( kex == null ) {
			throw new SshException("Unexpected "+SshConstants.messageName(msg));
		}
		if( ignoreNextKexPacket ) {
			ignoreNextKexPacket = false;
			return;
		}
		if( kex.handle(msg, message) ) {
			keysReady();
		}
	}

	/**
	 * K and H are known: derive the keys, send NEWKEYS, switch the output.
	 */
	private void keysReady() throws IOException {
		byte[] h = kex.getExchangeHash();
		byte[] k = new SshBuffer().putMpint(kex.getSharedSecret()).toByteArray();
		String hash = kex.getHashAlgorithm();
		if( sessionId == null ) {
			sessionId = h;
		}
		NegotiatedAlgorithms n = pendingNegotiated;
		String outCipherName = client ? n.getCipherClientToServer() : n.getCipherServerToClient();
		String inCipherName = client ? n.getCipherServerToClient() : n.getCipherClientToServer();
		String outMacName = client ? n.getMacClientToServer() : n.getMacServerToClient();
		String inMacName = client ? n.getMacServerToClient() : n.getMacClientToServer();
		// RFC 4253 7.2: A/B IV, C/D key, E/F MAC; the first letter of each pair is client to server
		char ivOut = client ? 'A' : 'B', ivIn = client ? 'B' : 'A';
		char keyOut = client ? 'C' : 'D', keyIn = client ? 'D' : 'C';
		char macOut = client ? 'E' : 'F', macIn = client ? 'F' : 'E';
		try {
			ISshCipher outCipher = algorithms.findCipher(outCipherName).create();
			outCipher.init(true, derive(hash, k, h, keyOut, outCipher.getKeySize()), derive(hash, k, h, ivOut, outCipher.getIvSize()));
			ISshCipher inCipher = algorithms.findCipher(inCipherName).create();
			inCipher.init(false, derive(hash, k, h, keyIn, inCipher.getKeySize()), derive(hash, k, h, ivIn, inCipher.getIvSize()));
			ISshMac outMac = null;
			if( outMacName != null ) {
				outMac = algorithms.findMac(outMacName).create();
				outMac.init(derive(hash, k, h, macOut, outMac.getKeySize()));
			}
			ISshMac inMac = null;
			if( inMacName != null ) {
				inMac = algorithms.findMac(inMacName).create();
				inMac.init(derive(hash, k, h, macIn, inMac.getKeySize()));
			}
			writePacket(SshBuffer.message(SshConstants.SSH_MSG_NEWKEYS));
			encoder.setKeys(outCipher, outMac);
			if( strictKex ) {
				encoder.resetSequence();
			}
			pendingInCipher = inCipher;
			pendingInMac = inMac;
			pendingIn = true;
		} catch (GeneralSecurityException e) {
			throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Can't set up the keys: "+e.getMessage(), e);
		}
		kex = null;
		outputBlocked = false;
		logDebug("Sent NEWKEYS");
		// What waited for the key exchange goes out with the new keys
		List<SshBuffer> tmp = new ArrayList<SshBuffer>(queued);
		queued.clear();
		for (SshBuffer b : tmp) {
			writePacket(b);
		}
	}

	private void receivedNewKeys() throws SshException {
		if( !pendingIn ) {
			throw new SshException("NEWKEYS before the key exchange finished");
		}
		decoder.setKeys(pendingInCipher, pendingInMac);
		if( strictKex ) {
			decoder.resetSequence();
		}
		pendingIn = false;
		pendingInCipher = null;
		pendingInMac = null;
		negotiated = pendingNegotiated;
		peerProposal = null;
		localProposal = null;
		kexRunning = false;
		kexCompleted = true;
		lastKexTime = System.currentTimeMillis();
		logDebug("Received NEWKEYS, keys in use: "+negotiated);
	}

	/**
	 * After the lock is released: tell waiters and, the first time, the subclass.
	 */
	private void finishKexIfDone() throws Exception {
		List<CompletableFuture<Void>> done = null;
		boolean first = false;
		lock.lock();
		try {
			if( kexCompleted ) {
				kexCompleted = false;
				first = !firstKexDone;
				firstKexDone = true;
				kexCount++;
				done = new ArrayList<CompletableFuture<Void>>(kexWaiters);
				kexWaiters.clear();
			}
		} finally {
			lock.unlock();
		}
		if( done != null ) {
			for (CompletableFuture<Void> f : done) {
				f.complete(null);
			}
			if( first ) {
				onReady();
			}
		}
	}

	/**
	 * RFC 4253 7.2: K1 = HASH(K || H || X || session_id), Kn = HASH(K || H || K1 || ... || Kn-1).
	 *
	 * @param k K encoded as an mpint
	 */
	private byte[] derive(String hash, byte[] k, byte[] h, char letter, int len) throws GeneralSecurityException {
		MessageDigest md = MessageDigest.getInstance(hash);
		md.update(k);
		md.update(h);
		md.update((byte) letter);
		md.update(sessionId);
		byte[] out = md.digest();
		while( out.length < len ) {
			md.update(k);
			md.update(h);
			md.update(out);
			byte[] more = md.digest();
			byte[] tmp = Arrays.copyOf(out, out.length+more.length);
			System.arraycopy(more, 0, tmp, out.length, more.length);
			out = tmp;
		}
		return Arrays.copyOf(out, len);
	}

	/**
	 * Start a key exchange if enough data or time has gone by. Called as packets go in and out.
	 */
	private void checkRekey() throws IOException {
		if( !firstKexDone || kexRunning ) {
			return;
		}
		boolean due = encoder.getBytesSinceKeys() > rekeyBytes || decoder.getBytesSinceKeys() > rekeyBytes
				// well before the 2^32 sequence numbers wrap
				|| encoder.getPacketsSinceKeys() > (1L << 31) || decoder.getPacketsSinceKeys() > (1L << 31)
				|| System.currentTimeMillis()-lastKexTime > rekeyTime;
		if( due ) {
			lock.lock();
			try {
				if( !kexRunning ) {
					logDebug("Re-keying");
					sendKexInit();
				}
			} finally {
				lock.unlock();
			}
		}
	}

	private final class KexContext implements IKexContext {

		@Override
		public boolean isClient() {
			return client;
		}

		@Override
		public byte[] getClientVersion() {
			return (client ? localVersion : peerVersion).getBytes(StandardCharsets.UTF_8);
		}

		@Override
		public byte[] getServerVersion() {
			return (client ? peerVersion : localVersion).getBytes(StandardCharsets.UTF_8);
		}

		@Override
		public byte[] getClientKexInit() {
			return (client ? localProposal : peerProposal).getPayload();
		}

		@Override
		public byte[] getServerKexInit() {
			return (client ? peerProposal : localProposal).getPayload();
		}

		@Override
		public String getHostKeyAlgorithm() {
			return pendingNegotiated.getHostKey();
		}

		@Override
		public SecureRandom getRandom() {
			return random;
		}

		@Override
		public void send(SshBuffer message) throws IOException {
			writePacket(message);
		}

		@Override
		public void verifyHostKey(byte[] hostKey, byte[] signature, byte[] exchangeHash) throws IOException {
			SshTransport.this.verifyHostKey(hostKey, signature, exchangeHash, getHostKeyAlgorithm());
		}

		@Override
		public byte[] getHostKey() throws IOException {
			return SshTransport.this.getHostKey(getHostKeyAlgorithm());
		}

		@Override
		public byte[] signExchangeHash(byte[] exchangeHash) throws IOException {
			return SshTransport.this.signExchangeHash(exchangeHash, getHostKeyAlgorithm());
		}
	}

	// ------------------------------------------------------------------ packets out

	/**
	 * Send a message. During a key exchange, messages other than transport messages wait and
	 * go out with the new keys. Any thread.
	 *
	 * @param message the message, starting with its number
	 * @throws IOException if the connection is closed
	 */
	public void send(SshBuffer message) throws IOException {
		int msg = message.array()[message.readPosition()] & 0xff;
		lock.lock();
		try {
			if( closed || disconnecting ) {
				throw new ClosedChannelException();
			}
			boolean transport = (msg >= SshConstants.SSH_MSG_DISCONNECT && msg <= SshConstants.SSH_MSG_DEBUG)
					|| (msg >= SshConstants.SSH_MSG_KEXINIT && msg <= SshConstants.SSH_MSG_KEX_LAST);
			if( outputBlocked && !transport ) {
				queued.add(new SshBuffer(message.toByteArray()));
				return;
			}
			writePacket(message);
		} finally {
			lock.unlock();
		}
		checkRekey();
	}

	/**
	 * Encode and queue a packet now. Called with the lock held.
	 */
	private void writePacket(SshBuffer message) throws IOException {
		INioConnection c = connection;
		if( c == null ) {
			throw new ClosedChannelException();
		}
		if( isDebugEnabled() ) {
			logDebug("Sending "+SshConstants.messageName(message.array()[message.readPosition()] & 0xff));
		}
		try {
			c.write(encoder.encode(message));
		} catch (GeneralSecurityException e) {
			throw new SshException(SshConstants.SSH_DISCONNECT_PROTOCOL_ERROR, "Can't encrypt a packet: "+e.getMessage(), e);
		}
	}

	// ------------------------------------------------------------------ public API

	/**
	 * Start a key exchange now (if one isn't running).
	 *
	 * @return completes when the new keys are in use in both directions
	 */
	public CompletableFuture<Void> rekey() {
		CompletableFuture<Void> ret = new CompletableFuture<Void>();
		lock.lock();
		try {
			if( closed || disconnecting ) {
				ret.completeExceptionally(new ClosedChannelException());
				return ret;
			}
			kexWaiters.add(ret);
			if( firstKexDone && !kexRunning ) {
				sendKexInit();
			}
		} catch (IOException e) {
			kexWaiters.remove(ret);
			ret.completeExceptionally(e);
		} finally {
			lock.unlock();
		}
		return ret;
	}

	/**
	 * Send SSH_MSG_DISCONNECT and close once it is sent. Any thread; later calls do nothing.
	 *
	 * @param reason SshConstants.SSH_DISCONNECT_...
	 * @param description for the peer's logs
	 */
	public void disconnect(int reason, String description) {
		INioConnection c = connection;
		lock.lock();
		try {
			if( disconnecting || closed ) {
				return;
			}
			disconnecting = true;
			if( c != null && peerVersion != null ) {
				try {
					writePacket(SshBuffer.message(SshConstants.SSH_MSG_DISCONNECT).putInt(reason)
							.putString(description == null ? "" : description).putString(""));
				} catch (IOException e) {
					logDebug("Can't send DISCONNECT", e);
				}
			}
		} finally {
			lock.unlock();
		}
		fail(new SshException(reason, description == null ? "Disconnected" : description));
		if( c != null ) {
			c.closeAfterFlush();
		}
	}

	/**
	 * Disconnect "by application".
	 */
	public void close() {
		disconnect(SshConstants.SSH_DISCONNECT_BY_APPLICATION, "Closed");
	}

	public boolean isOpen() {
		return !closed && !disconnecting;
	}

	/**
	 * @return true once the first key exchange is done
	 */
	public boolean isReady() {
		return firstKexDone;
	}

	public INioConnection getConnection() {
		return connection;
	}

	public String getLocalVersion() {
		return localVersion;
	}

	/**
	 * @return the peer's identification string, null until received
	 */
	public String getPeerVersion() {
		return peerVersion;
	}

	/**
	 * @return the algorithms in use, null until the first key exchange is done
	 */
	public NegotiatedAlgorithms getNegotiated() {
		return negotiated;
	}

	/**
	 * @return H of the first key exchange (signed in public key authentication), null before
	 */
	public byte[] getSessionId() {
		byte[] s = sessionId;
		return s == null ? null : s.clone();
	}

	/**
	 * @return how many key exchanges have finished (1 after connecting, more after re-keying)
	 */
	public int getKexCount() {
		return kexCount;
	}

	public boolean isStrictKex() {
		return strictKex;
	}

	/**
	 * @return the peer's SSH_MSG_EXT_INFO extensions (RFC 8308), empty if none
	 */
	public Map<String, byte[]> getPeerExtensions() {
		return peerExtensions;
	}

	/**
	 * @return why the connection ended (or is ending), null while it is fine
	 */
	public Throwable getFailure() {
		return failure;
	}

	public SshAlgorithms getAlgorithms() {
		return algorithms;
	}

	public long getRekeyBytes() {
		return rekeyBytes;
	}

	public void setRekeyBytes(long rekeyBytes) {
		this.rekeyBytes = rekeyBytes;
	}

	public long getRekeyTime() {
		return rekeyTime;
	}

	public void setRekeyTime(long milliSeconds) {
		this.rekeyTime = milliSeconds;
	}
}
