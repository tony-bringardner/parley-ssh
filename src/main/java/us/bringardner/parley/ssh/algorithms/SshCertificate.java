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
package us.bringardner.parley.ssh.algorithms;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshException;

/**
 * An OpenSSH certificate (PROTOCOL.certkeys): a public key, signed by a certificate authority
 * (CA) together with what it may be used for: user or host, the names (principals) it is
 * valid for, a validity period, critical options and extensions. A server that trusts the
 * CA accepts any user certificate it signed, and a client that trusts it accepts any host
 * certificate, without listing every key.
 * <p>
 * Made by {@code ssh-keygen -s ca_key ...} or {@link #sign}; read from the "-cert.pub" file
 * with {@link #load(File)} or from a key blob with {@link #decode(byte[])}.
 * <p>
 * {@link #check(int, String, long)} does the checks every use needs (signature, type,
 * validity, principal); who trusts which CA, and the critical options, are up to the user of
 * the certificate.
 *
 * @author Tony Bringardner
 */
public final class SshCertificate {

	/** The certificate type of a user certificate */
	public static final int USER = 1;
	/** The certificate type of a host certificate */
	public static final int HOST = 2;
	/** valid before: no end */
	public static final long FOREVER = -1L;

	public static final String SUFFIX = "-cert-v01@openssh.com";

	/** Critical option: the only command the user may run */
	public static final String FORCE_COMMAND = "force-command";
	/** Critical option: the addresses the user may connect from */
	public static final String SOURCE_ADDRESS = "source-address";
	/** Extensions ssh-keygen gives user certificates by default */
	public static final String PERMIT_PTY = "permit-pty";
	public static final String PERMIT_PORT_FORWARDING = "permit-port-forwarding";
	public static final String PERMIT_AGENT_FORWARDING = "permit-agent-forwarding";
	public static final String PERMIT_X11_FORWARDING = "permit-X11-forwarding";
	public static final String PERMIT_USER_RC = "permit-user-rc";

	private final byte[] blob;
	private final String type;
	private final PublicKey publicKey;
	private final byte[] publicKeyBlob;
	private final long serial;
	private final int certType;
	private final String keyId;
	private final List<String> principals;
	private final long validAfter;
	private final long validBefore;
	private final Map<String, String> criticalOptions;
	private final Map<String, String> extensions;
	private final byte[] caKeyBlob;
	private final byte[] signedData;
	private final byte[] signature;

	private SshCertificate(byte[] blob, String type, PublicKey publicKey, byte[] publicKeyBlob, long serial, int certType,
			String keyId, List<String> principals, long validAfter, long validBefore, Map<String, String> criticalOptions,
			Map<String, String> extensions, byte[] caKeyBlob, byte[] signedData, byte[] signature) {
		this.blob = blob;
		this.type = type;
		this.publicKey = publicKey;
		this.publicKeyBlob = publicKeyBlob;
		this.serial = serial;
		this.certType = certType;
		this.keyId = keyId;
		this.principals = principals;
		this.validAfter = validAfter;
		this.validBefore = validBefore;
		this.criticalOptions = criticalOptions;
		this.extensions = extensions;
		this.caKeyBlob = caKeyBlob;
		this.signedData = signedData;
		this.signature = signature;
	}

	/**
	 * @return true for a certificate key type, e.g. "ssh-ed25519-cert-v01@openssh.com"
	 */
	public static boolean isCertificateType(String keyType) {
		return keyType != null && keyType.endsWith(SUFFIX);
	}

	/**
	 * @return the plain key type of a certificate type ("ssh-ed25519-cert-v01@openssh.com" to "ssh-ed25519")
	 */
	public static String plainType(String certificateType) {
		return certificateType.substring(0, certificateType.length()-SUFFIX.length());
	}

	/**
	 * @return the certificate type of a plain key type ("ssh-ed25519" to "ssh-ed25519-cert-v01@openssh.com")
	 */
	public static String certificateType(String plainType) {
		return plainType+SUFFIX;
	}

	// ------------------------------------------------------------------ reading

	/**
	 * @param blob a certificate key blob (as sent in public key authentication or as a host key)
	 * @throws SshException if it is malformed or its key type isn't supported
	 */
	public static SshCertificate decode(byte[] blob) throws SshException {
		SshBuffer b = new SshBuffer(blob);
		String type = b.getStringUtf8();
		if( !isCertificateType(type) ) {
			throw new SshException("Not a certificate: "+type);
		}
		String plain = plainType(type);
		b.getString(); // nonce
		// The key's fields, as in its plain blob after the type
		int start = b.readPosition();
		if( SshPublicKeys.SSH_RSA.equals(plain) ) {
			b.getMpint();
			b.getMpint();
		} else if( plain.startsWith("ecdsa-sha2-") ) {
			b.getString();
			b.getString();
		} else if( Ed25519.SSH_ED25519.equals(plain) ) {
			b.getString();
		} else {
			throw new SshException("Unsupported certificate type "+type);
		}
		byte[] fields = Arrays.copyOfRange(blob, start, b.readPosition());
		byte[] keyBlob = new SshBuffer().putString(plain).putRaw(fields).toByteArray();
		PublicKey key = SshPublicKeys.decode(keyBlob);
		long serial = b.getLong();
		int certType = b.getInt();
		String keyId = b.getStringUtf8();
		List<String> principals = strings(b.getString());
		long after = b.getLong();
		long before = b.getLong();
		Map<String, String> critical = options(b.getString(), true);
		Map<String, String> extensions = options(b.getString(), false);
		b.getString(); // reserved
		byte[] ca = b.getString();
		if( isCertificateType(SshPublicKeys.blobType(ca)) ) {
			throw new SshException("A certificate's CA key can't be a certificate");
		}
		int signedEnd = b.readPosition();
		byte[] sig = b.getString();
		if( b.available() != 0 ) {
			throw new SshException("Extra data after the certificate");
		}
		return new SshCertificate(blob.clone(), type, key, keyBlob, serial, certType, keyId, principals, after, before,
				critical, extensions, ca, Arrays.copyOf(blob, signedEnd), sig);
	}

	/**
	 * @param text a "-cert.pub" line: "type base64 [comment]"
	 */
	public static SshCertificate fromOpenSsh(String text) throws SshException {
		String[] parts = text.trim().split("\\s+");
		if( parts.length < 2 || !isCertificateType(parts[0]) ) {
			throw new SshException("Not a certificate: '"+text+"'");
		}
		byte[] blob;
		try {
			blob = Base64.getDecoder().decode(parts[1]);
		} catch (IllegalArgumentException e) {
			throw new SshException("Not a certificate (bad base64)");
		}
		SshCertificate ret = decode(blob);
		if( !ret.type.equals(parts[0]) ) {
			throw new SshException("Certificate type "+ret.type+" listed as "+parts[0]);
		}
		return ret;
	}

	/**
	 * @param file a "-cert.pub" file, e.g. ~/.ssh/id_ed25519-cert.pub
	 */
	public static SshCertificate load(File file) throws IOException {
		return fromOpenSsh(new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8));
	}

	private static List<String> strings(byte[] packed) throws SshException {
		List<String> ret = new ArrayList<String>();
		SshBuffer b = new SshBuffer(packed);
		while( b.available() > 0 ) {
			ret.add(b.getStringUtf8());
		}
		return Collections.unmodifiableList(ret);
	}

	/**
	 * name, data pairs; the data of an option with a value is that value as a string
	 */
	private static Map<String, String> options(byte[] packed, boolean critical) throws SshException {
		Map<String, String> ret = new TreeMap<String, String>();
		SshBuffer b = new SshBuffer(packed);
		while( b.available() > 0 ) {
			String name = b.getStringUtf8();
			byte[] data = b.getString();
			String value = data.length == 0 ? "" : new SshBuffer(data).getStringUtf8();
			if( ret.put(name, value) != null ) {
				throw new SshException("Certificate "+(critical ? "option " : "extension ")+name+" given twice");
			}
		}
		return Collections.unmodifiableMap(ret);
	}

	// ------------------------------------------------------------------ checking

	/**
	 * @return true if the CA's signature is valid (who the CA is, is not checked here)
	 */
	public boolean isSignatureValid() {
		try {
			String alg = new SshBuffer(signature).getStringUtf8();
			ISignatureAlgorithm sig = SshAlgorithms.findSignature(alg);
			// The signature must be made with the CA key's own type (rsa-sha2-* for ssh-rsa), never SHA-1 ssh-rsa
			if( sig == null || isCertificateType(alg) || "ssh-rsa".equals(alg) || !sig.getKeyType().equals(SshPublicKeys.blobType(caKeyBlob)) ) {
				return false;
			}
			return sig.verify(SshPublicKeys.decode(caKeyBlob), signedData, signature);
		} catch (SshException e) {
			return false;
		}
	}

	/**
	 * The checks every use of a certificate needs: a valid signature, the type, the validity
	 * period and the principal.
	 *
	 * @param wantType {@link #USER} or {@link #HOST}
	 * @param principal the user name, or the host name; for a host certificate, principals may be
	 * patterns with * and ?, and no principals means any host
	 * @param now seconds since 1970
	 * @return null if the certificate passes, else why not
	 */
	public String check(int wantType, String principal, long now) {
		if( certType != wantType ) {
			return "a "+(certType == USER ? "user" : certType == HOST ? "host" : "type "+certType)+" certificate, not a "+(wantType == USER ? "user" : "host")+" certificate";
		}
		if( !isSignatureValid() ) {
			return "the CA's signature is not valid";
		}
		if( Long.compareUnsigned(now, validAfter) < 0 ) {
			return "not valid yet";
		}
		if( Long.compareUnsigned(now, validBefore) >= 0 ) {
			return "expired";
		}
		if( wantType == HOST ) {
			if( principals.isEmpty() ) {
				return null;
			}
			for (String p : principals) {
				if( glob(p.toLowerCase(java.util.Locale.ROOT), principal.toLowerCase(java.util.Locale.ROOT)) ) {
					return null;
				}
			}
			return "not valid for host "+principal;
		}
		if( !principals.contains(principal) ) {
			return principals.isEmpty() ? "it names no users" : "not valid for user "+principal;
		}
		return null;
	}

	private static boolean glob(String pattern, String name) {
		return glob(pattern, 0, name, 0);
	}

	private static boolean glob(String p, int pi, String n, int ni) {
		while( pi < p.length() ) {
			char c = p.charAt(pi);
			if( c == '*' ) {
				for (int k = ni; k <= n.length(); k++) {
					if( glob(p, pi+1, n, k) ) {
						return true;
					}
				}
				return false;
			}
			if( ni >= n.length() || (c != '?' && c != n.charAt(ni)) ) {
				return false;
			}
			pi++;
			ni++;
		}
		return ni == n.length();
	}

	// ------------------------------------------------------------------ getters

	/** @return the certificate key type, e.g. "ssh-ed25519-cert-v01@openssh.com" */
	public String getType() {
		return type;
	}

	/** @return the plain key type, e.g. "ssh-ed25519" */
	public String getKeyType() {
		return plainType(type);
	}

	/** @return the certificate's whole blob */
	public byte[] getBlob() {
		return blob.clone();
	}

	/** @return the certified key */
	public PublicKey getPublicKey() {
		return publicKey;
	}

	/** @return the certified key's plain blob */
	public byte[] getPublicKeyBlob() {
		return publicKeyBlob.clone();
	}

	public long getSerial() {
		return serial;
	}

	/** @return {@link #USER} or {@link #HOST} */
	public int getCertificateType() {
		return certType;
	}

	/** @return the key id the CA gave it (shown in logs) */
	public String getKeyId() {
		return keyId;
	}

	public List<String> getPrincipals() {
		return principals;
	}

	/** @return seconds since 1970 */
	public long getValidAfter() {
		return validAfter;
	}

	/** @return seconds since 1970 (unsigned), {@link #FOREVER} for no end */
	public long getValidBefore() {
		return validBefore;
	}

	public Map<String, String> getCriticalOptions() {
		return criticalOptions;
	}

	public Map<String, String> getExtensions() {
		return extensions;
	}

	public boolean hasExtension(String name) {
		return extensions.containsKey(name);
	}

	/** @return the CA's key blob */
	public byte[] getCaKeyBlob() {
		return caKeyBlob.clone();
	}

	public PublicKey getCaKey() throws SshException {
		return SshPublicKeys.decode(caKeyBlob);
	}

	/**
	 * @return the "-cert.pub" line
	 */
	public String toOpenSsh(String comment) {
		return type+" "+Base64.getEncoder().encodeToString(blob)+(comment == null || comment.isEmpty() ? "" : " "+comment);
	}

	@Override
	public String toString() {
		return type+" id \""+keyId+"\" serial "+serial+" for "+principals+" CA "+SshPublicKeys.fingerprint(caKeyBlob);
	}

	// ------------------------------------------------------------------ signing

	/**
	 * Make a certificate, as {@code ssh-keygen -s} does.
	 *
	 * @param key the key to certify
	 * @param certType {@link #USER} or {@link #HOST}
	 * @param keyId shown in the server's logs
	 * @param principals user or host names it is valid for
	 * @param validAfter seconds since 1970
	 * @param validBefore seconds since 1970, or {@link #FOREVER}
	 * @param criticalOptions e.g. {@link #FORCE_COMMAND}; null for none
	 * @param extensions e.g. {@link #PERMIT_PTY} with value ""; null for none
	 * @param ca the CA's key pair (RSA signs with rsa-sha2-512)
	 */
	public static SshCertificate sign(PublicKey key, int certType, String keyId, Collection<String> principals, long validAfter,
			long validBefore, Map<String, String> criticalOptions, Map<String, String> extensions, KeyPair ca)
			throws GeneralSecurityException {
		String plain = SshPublicKeys.keyType(key);
		byte[] keyBlob = SshPublicKeys.encode(key);
		SshBuffer kb;
		try {
			kb = new SshBuffer(keyBlob);
			kb.getString();
		} catch (SshException e) {
			throw new GeneralSecurityException(e);
		}
		byte[] nonce = new byte[32];
		new SecureRandom().nextBytes(nonce);
		SshBuffer p = new SshBuffer();
		for (String s : principals) {
			p.putString(s);
		}
		SshBuffer b = new SshBuffer();
		b.putString(certificateType(plain));
		b.putString(nonce);
		b.putRaw(Arrays.copyOfRange(keyBlob, kb.readPosition(), keyBlob.length));
		b.putLong(0);
		b.putInt(certType);
		b.putString(keyId == null ? "" : keyId);
		b.putString(p.toByteArray());
		b.putLong(validAfter);
		b.putLong(validBefore);
		b.putString(packOptions(criticalOptions));
		b.putString(packOptions(extensions));
		b.putString(new byte[0]);
		b.putString(SshPublicKeys.encode(ca.getPublic()));
		String caType = SshPublicKeys.keyType(ca.getPublic());
		ISignatureAlgorithm sig = SshAlgorithms.findSignature(SshPublicKeys.SSH_RSA.equals(caType) ? "rsa-sha2-512" : caType);
		b.putString(sig.sign(ca.getPrivate(), b.toByteArray()));
		try {
			return decode(b.toByteArray());
		} catch (SshException e) {
			throw new GeneralSecurityException(e);
		}
	}

	/** Sorted by name, as the format requires */
	private static byte[] packOptions(Map<String, String> options) {
		SshBuffer b = new SshBuffer();
		if( options != null ) {
			for (Map.Entry<String, String> e : new TreeMap<String, String>(options).entrySet()) {
				b.putString(e.getKey());
				String v = e.getValue();
				b.putString(v == null || v.isEmpty() ? new byte[0] : new SshBuffer().putString(v).toByteArray());
			}
		}
		return b.toByteArray();
	}
}
