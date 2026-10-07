package us.bringardner.net.ssh.transport;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import javax.crypto.interfaces.DHPublicKey;

import org.junit.jupiter.api.Test;

import us.bringardner.net.ssh.SshBuffer;
import us.bringardner.net.ssh.SshConstants;
import us.bringardner.net.ssh.SshException;
import us.bringardner.net.ssh.algorithms.DhAgreement;
import us.bringardner.net.ssh.algorithms.ISshCipher;
import us.bringardner.net.ssh.algorithms.ISshMac;
import us.bringardner.net.ssh.algorithms.SshAlgorithms;

/**
 * Encoder and decoder against each other, for every cipher and MAC layout, with input that
 * arrives a few bytes at a time.
 */
public class PacketCodecTest {

	private final SecureRandom random = new SecureRandom();

	private static final String[][] COMBOS = {
			{null, null},
			{"aes128-ctr", "hmac-sha2-256"},
			{"aes256-ctr", "hmac-sha2-512"},
			{"aes192-ctr", "hmac-sha2-256-etm@openssh.com"},
			{"aes256-ctr", "hmac-sha2-512-etm@openssh.com"},
			{"aes128-gcm@openssh.com", null},
			{"aes256-gcm@openssh.com", null},
	};

	private ISshCipher[] ciphers(String name) throws Exception {
		if( name == null ) {
			return new ISshCipher[2];
		}
		SshAlgorithms a = SshAlgorithms.defaults();
		ISshCipher enc = a.findCipher(name).create();
		ISshCipher dec = a.findCipher(name).create();
		byte[] key = new byte[enc.getKeySize()];
		byte[] iv = new byte[enc.getIvSize()];
		random.nextBytes(key);
		random.nextBytes(iv);
		enc.init(true, key, iv);
		dec.init(false, key, iv);
		return new ISshCipher[] {enc, dec};
	}

	private ISshMac[] macs(String name) throws Exception {
		if( name == null ) {
			return new ISshMac[2];
		}
		SshAlgorithms a = SshAlgorithms.defaults();
		ISshMac m1 = a.findMac(name).create();
		ISshMac m2 = a.findMac(name).create();
		byte[] key = new byte[m1.getKeySize()];
		random.nextBytes(key);
		m1.init(key);
		m2.init(key);
		return new ISshMac[] {m1, m2};
	}

	@Test
	public void roundTripEveryLayout() throws Exception {
		Random sizes = new Random(3);
		for (String[] combo : COMBOS) {
			ISshCipher[] c = ciphers(combo[0]);
			ISshMac[] m = macs(combo[1]);
			SshPacketEncoder enc = new SshPacketEncoder(random);
			SshPacketDecoder dec = new SshPacketDecoder();
			enc.setKeys(c[0], m[0]);
			dec.setKeys(c[1], m[1]);

			List<byte[]> sent = new ArrayList<byte[]>();
			ByteBuffer wire = ByteBuffer.allocate(4*1024*1024);
			for (int i = 0; i < 200; i++) {
				byte[] payload = new byte[1+sizes.nextInt(i % 10 == 0 ? 40000 : 300)];
				sizes.nextBytes(payload);
				sent.add(payload);
				wire.put(enc.encode(new SshBuffer(payload)));
			}
			wire.flip();

			// Feed the decoder a few bytes at a time, as reads from a socket would
			ByteBuffer in = ByteBuffer.allocate(wire.remaining());
			in.flip();
			List<byte[]> got = new ArrayList<byte[]>();
			while( wire.hasRemaining() || in.hasRemaining() ) {
				int n = Math.min(wire.remaining(), 1+sizes.nextInt(700));
				in.compact();
				for (int i = 0; i < n; i++) {
					in.put(wire.get());
				}
				in.flip();
				ByteBuffer frame;
				while( (frame = dec.decode(in)) != null ) {
					byte[] b = new byte[frame.remaining()];
					frame.get(b);
					got.add(b);
				}
				if( !wire.hasRemaining() ) {
					break;
				}
			}
			assertEquals(sent.size(), got.size(), "packets with "+combo[0]+"/"+combo[1]);
			for (int i = 0; i < sent.size(); i++) {
				assertArrayEquals(sent.get(i), got.get(i), "packet "+i+" with "+combo[0]+"/"+combo[1]);
			}
			assertEquals(200, dec.getSequence());
			assertEquals(200, enc.getSequence());
		}
	}

	@Test
	public void tamperedPacketIsRejected() throws Exception {
		for (String[] combo : COMBOS) {
			if( combo[0] == null ) {
				continue;
			}
			ISshCipher[] c = ciphers(combo[0]);
			ISshMac[] m = macs(combo[1]);
			SshPacketEncoder enc = new SshPacketEncoder(random);
			SshPacketDecoder dec = new SshPacketDecoder();
			enc.setKeys(c[0], m[0]);
			dec.setKeys(c[1], m[1]);
			ByteBuffer packet = enc.encode(new SshBuffer(new byte[100]));
			// Flip a bit in the last payload byte
			int at = packet.limit()-1-(combo[1] == null ? 16 : m[0].getMacSize())-1;
			packet.put(at, (byte) (packet.get(at) ^ 1));
			SshException e = assertThrows(SshException.class, () -> dec.decode(packet), combo[0]+"/"+combo[1]);
			assertEquals(SshConstants.SSH_DISCONNECT_MAC_ERROR, e.getReason());
		}
	}

	@Test
	public void incompletePacketWaits() throws Exception {
		SshPacketEncoder enc = new SshPacketEncoder(random);
		SshPacketDecoder dec = new SshPacketDecoder();
		ByteBuffer packet = enc.encode(new SshBuffer(new byte[] {1, 2, 3}));
		ByteBuffer part = ByteBuffer.wrap(packet.array(), 0, packet.limit()-1);
		assertNull(dec.decode(part));
		ByteBuffer frame = dec.decode(ByteBuffer.wrap(packet.array(), part.position(), packet.limit()-part.position()));
		assertNotNull(frame);
		assertEquals(3, frame.remaining());
	}

	@Test
	public void hugeLengthIsRejected() {
		SshPacketDecoder dec = new SshPacketDecoder();
		ByteBuffer evil = ByteBuffer.wrap(new byte[] {0x7f, 0, 0, 0, 4, 0, 0, 0});
		assertThrows(SshException.class, () -> dec.decode(evil));
	}

	/** The Diffie-Hellman groups are the JDK's own RFC 3526 groups */
	@Test
	public void dhGroupsMatchTheJdk() throws Exception {
		for (int bits : new int[] {2048, 4096}) {
			KeyPairGenerator g = KeyPairGenerator.getInstance("DH");
			g.initialize(bits);
			BigInteger p = ((DHPublicKey) g.generateKeyPair().getPublic()).getParams().getP();
			assertEquals(p, bits == 2048 ? DhAgreement.GROUP14 : DhAgreement.GROUP16, bits+" bit group");
		}
	}
}
