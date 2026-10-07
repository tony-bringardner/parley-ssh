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
package us.bringardner.parley.ssh.keys;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.SshCertificate;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;

/**
 * Revoked keys, as OpenSSH's RevokedKeys and RevokedHostKeys files hold them: an OpenSSH
 * key revocation list (KRL, PROTOCOL.krl, made by ssh-keygen -k) or a plain list of public
 * keys, one per line.
 * <p>
 * A KRL revokes certificates by their CA and serial number (lists, ranges, bitmaps) or key
 * id, and keys by their blob or SHA-1 / SHA-256 fingerprint. A certificate is also revoked
 * when its key or its CA's key is. KRL signatures are not checked (as OpenSSH doesn't
 * require them); the file must be protected like any server configuration.
 * <p>
 * A list made with {@link #load(File)} reads its file again when it changes. Thread safe.
 *
 * @author Tony Bringardner
 */
public final class KeyRevocationList {

	private static final byte[] MAGIC = "SSHKRL\n\0".getBytes(StandardCharsets.US_ASCII);
	private static final int SECTION_CERTIFICATES = 1;
	private static final int SECTION_EXPLICIT_KEY = 2;
	private static final int SECTION_FINGERPRINT_SHA1 = 3;
	private static final int SECTION_SIGNATURE = 4;
	private static final int SECTION_FINGERPRINT_SHA256 = 5;
	private static final int CERT_SERIAL_LIST = 0x20;
	private static final int CERT_SERIAL_RANGE = 0x21;
	private static final int CERT_SERIAL_BITMAP = 0x22;
	private static final int CERT_KEY_ID = 0x23;
	/** Bitmaps bigger than this are refused (a 1 MB bitmap covers 8 million serials) */
	private static final int MAX_BITMAP = 1024*1024;

	/** The certificates of one CA (or any CA, for an empty ca) */
	private static final class CaSection {
		final byte[] ca;
		final List<long[]> ranges = new ArrayList<long[]>();
		final List<Object[]> bitmaps = new ArrayList<Object[]>();
		final Set<String> keyIds = new HashSet<String>();

		CaSection(byte[] ca) {
			this.ca = ca;
		}

		boolean revokes(SshCertificate c) {
			if( keyIds.contains(c.getKeyId()) ) {
				return true;
			}
			long serial = c.getSerial();
			for (long[] r : ranges) {
				if( Long.compareUnsigned(serial, r[0]) >= 0 && Long.compareUnsigned(serial, r[1]) <= 0 ) {
					return true;
				}
			}
			for (Object[] b : bitmaps) {
				long offset = (Long) b[0];
				BigInteger bits = (BigInteger) b[1];
				if( Long.compareUnsigned(serial, offset) >= 0 ) {
					long i = serial-offset;
					if( i >= 0 && i < bits.bitLength() && bits.testBit((int) i) ) {
						return true;
					}
				}
			}
			return false;
		}
	}

	private static final class State {
		final List<CaSection> certificates = new ArrayList<CaSection>();
		final Set<String> blobs = new HashSet<String>();
		final Set<String> sha1 = new HashSet<String>();
		final Set<String> sha256 = new HashSet<String>();
	}

	private final File file;
	private volatile State state;
	private volatile long modified;
	private volatile long size;

	private KeyRevocationList(File file, State state) {
		this.file = file;
		this.state = state;
		if( file != null ) {
			this.modified = file.lastModified();
			this.size = file.length();
		}
	}

	/**
	 * @param file a KRL or a list of public keys; read again when it changes
	 * @throws IOException if it can't be read or is malformed
	 */
	public static KeyRevocationList load(File file) throws IOException {
		return new KeyRevocationList(file, parse(Files.readAllBytes(file.toPath())));
	}

	/**
	 * @param data a KRL, or the text of a list of public keys
	 */
	public static KeyRevocationList of(byte[] data) throws IOException {
		return new KeyRevocationList(null, parse(data));
	}

	private State current() {
		File f = file;
		if( f != null && (f.lastModified() != modified || f.length() != size) ) {
			synchronized (this) {
				if( f.lastModified() != modified || f.length() != size ) {
					try {
						long m = f.lastModified();
						long s = f.length();
						state = parse(Files.readAllBytes(f.toPath()));
						modified = m;
						size = s;
					} catch (IOException e) {
						// A file that can't be read revokes everything (as OpenSSH refuses all keys then)
						State all = new State();
						all.certificates.add(null);
						state = all;
					}
				}
			}
		}
		return state;
	}

	/**
	 * @param blob a plain key's blob
	 * @return true if it is revoked
	 */
	public boolean isRevoked(byte[] blob) {
		State s = current();
		if( s.certificates.contains(null) ) {
			return true;
		}
		return s.blobs.contains(key(blob)) || s.sha1.contains(key(hash("SHA-1", blob))) || s.sha256.contains(key(hash("SHA-256", blob)));
	}

	/**
	 * @return true if the certificate, its key or its CA's key is revoked
	 */
	public boolean isRevoked(SshCertificate c) {
		if( isRevoked(c.getPublicKeyBlob()) || isRevoked(c.getCaKeyBlob()) ) {
			return true;
		}
		byte[] ca = c.getCaKeyBlob();
		for (CaSection sec : current().certificates) {
			if( sec != null && (sec.ca.length == 0 || Arrays.equals(sec.ca, ca)) && sec.revokes(c) ) {
				return true;
			}
		}
		return false;
	}

	private static String key(byte[] b) {
		return Base64.getEncoder().encodeToString(b);
	}

	private static byte[] hash(String alg, byte[] b) {
		try {
			return MessageDigest.getInstance(alg).digest(b);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	// ------------------------------------------------------------------ parsing

	private static State parse(byte[] data) throws IOException {
		if( data.length >= MAGIC.length && Arrays.equals(Arrays.copyOf(data, MAGIC.length), MAGIC) ) {
			return parseKrl(data);
		}
		State s = new State();
		int n = 0;
		for (String raw : new String(data, StandardCharsets.UTF_8).split("\r?\n")) {
			n++;
			String line = raw.trim();
			if( line.isEmpty() || line.startsWith("#") ) {
				continue;
			}
			try {
				s.blobs.add(key(SshPublicKeys.encode(SshPublicKeys.fromOpenSsh(line))));
			} catch (SshException e) {
				// An unsupported key type can't log in anyway; a malformed line is an error
				if( e.getMessage() == null || !e.getMessage().contains("Unsupported") ) {
					throw new SshException("Revoked keys line "+n+": "+e.getMessage());
				}
			}
		}
		return s;
	}

	private static State parseKrl(byte[] data) throws IOException {
		SshBuffer b = new SshBuffer(data);
		b.skip(MAGIC.length);
		long format = b.getUInt();
		if( format != 1 ) {
			throw new SshException("Unsupported KRL format "+format);
		}
		b.getLong(); // krl version
		b.getLong(); // generated
		b.getLong(); // flags
		b.getString(); // reserved
		b.getString(); // comment
		State s = new State();
		while( b.available() > 0 ) {
			int type = b.getByte();
			SshBuffer sec = new SshBuffer(b.getString());
			switch (type) {
			case SECTION_CERTIFICATES:
				s.certificates.add(certificates(sec));
				break;
			case SECTION_EXPLICIT_KEY:
				while( sec.available() > 0 ) {
					s.blobs.add(key(sec.getString()));
				}
				break;
			case SECTION_FINGERPRINT_SHA1:
				while( sec.available() > 0 ) {
					s.sha1.add(key(sec.getString()));
				}
				break;
			case SECTION_FINGERPRINT_SHA256:
				while( sec.available() > 0 ) {
					s.sha256.add(key(sec.getString()));
				}
				break;
			case SECTION_SIGNATURE:
				// Signatures come last and are not checked
				return s;
			default:
				throw new SshException("Unknown KRL section "+type);
			}
		}
		return s;
	}

	private static CaSection certificates(SshBuffer sec) throws IOException {
		CaSection c = new CaSection(sec.getString());
		sec.getString(); // reserved
		while( sec.available() > 0 ) {
			int type = sec.getByte();
			SshBuffer d = new SshBuffer(sec.getString());
			switch (type) {
			case CERT_SERIAL_LIST:
				while( d.available() > 0 ) {
					long serial = d.getLong();
					c.ranges.add(new long[] {serial, serial});
				}
				break;
			case CERT_SERIAL_RANGE:
				c.ranges.add(new long[] {d.getLong(), d.getLong()});
				break;
			case CERT_SERIAL_BITMAP: {
				long offset = d.getLong();
				byte[] bits = d.getString();
				if( bits.length > MAX_BITMAP ) {
					throw new SshException("KRL bitmap too big");
				}
				c.bitmaps.add(new Object[] {offset, new BigInteger(1, bits)});
				break;
			}
			case CERT_KEY_ID:
				while( d.available() > 0 ) {
					c.keyIds.add(d.getStringUtf8());
				}
				break;
			default:
				throw new SshException("Unknown KRL certificate section "+type);
			}
		}
		return c;
	}

	@Override
	public String toString() {
		State s = current();
		return "KeyRevocationList["+(file != null ? file+": " : "")+s.blobs.size()+" keys, "+(s.sha1.size()+s.sha256.size())
				+" fingerprints, "+s.certificates.size()+" CA sections]";
	}
}
