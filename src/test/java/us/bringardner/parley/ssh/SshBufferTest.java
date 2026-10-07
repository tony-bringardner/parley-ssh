package us.bringardner.parley.ssh;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.Test;

public class SshBufferTest {

	private static byte[] hex(String s) {
		s = s.replace(" ", "");
		byte[] ret = new byte[s.length()/2];
		for (int i = 0; i < ret.length; i++) {
			ret[i] = (byte) Integer.parseInt(s.substring(2*i, 2*i+2), 16);
		}
		return ret;
	}

	/** The mpint examples of RFC 4251 section 5 */
	@Test
	public void mpintRfcExamples() throws Exception {
		String[][] cases = {
				{"0", "00000000"},
				{"9a378f9b2e332a7", "00000008 09a378f9b2e332a7"},
				{"80", "00000002 0080"},
				{"-1234", "00000002 edcc"},
				{"-deadbeef", "00000005 ff21524111"},
		};
		for (String[] c : cases) {
			BigInteger v = new BigInteger(c[0], 16);
			byte[] enc = new SshBuffer().putMpint(v).toByteArray();
			assertArrayEquals(hex(c[1]), enc, "mpint "+c[0]);
			assertEquals(v, new SshBuffer(enc).getMpint(), "mpint "+c[0]+" read back");
		}
	}

	@Test
	public void typesRoundTrip() throws Exception {
		SshBuffer b = new SshBuffer(1);
		b.putByte(7).putBoolean(true).putInt(0xfedcba98L).putLong(-2).putString("héllo").putNameList(Arrays.asList("a", "b-c@x"))
				.putNameList(Collections.<String>emptyList());
		SshBuffer r = new SshBuffer(b.toByteArray());
		assertEquals(7, r.getByte());
		assertEquals(true, r.getBoolean());
		assertEquals(0xfedcba98L, r.getUInt());
		assertEquals(-2, r.getLong());
		assertEquals("héllo", r.getStringUtf8());
		assertEquals(Arrays.asList("a", "b-c@x"), r.getNameList());
		assertEquals(Collections.emptyList(), r.getNameList());
		assertEquals(0, r.available());
	}

	@Test
	public void malformedInputIsAProtocolError() {
		// A string claiming 2^32-1 bytes must not allocate them
		SshException e = assertThrows(SshException.class, () -> new SshBuffer(hex("ffffffff 01")).getString());
		assertEquals(SshConstants.SSH_DISCONNECT_PROTOCOL_ERROR, e.getReason());
		assertThrows(SshException.class, () -> new SshBuffer(hex("0000")).getUInt());
		assertThrows(SshException.class, () -> new SshBuffer(hex("80000000")).getInt());
		assertThrows(SshException.class, () -> new SshBuffer(hex("00000003 612c2c")).getNameList(), "empty name in a name-list");
	}
}
