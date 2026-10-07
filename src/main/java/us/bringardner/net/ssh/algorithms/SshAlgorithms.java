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
package us.bringardner.net.ssh.algorithms;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The algorithms a client or server offers, in order of preference. Each kind is a list of
 * {@link NamedFactory}s that can be reordered, trimmed or extended with new algorithms.
 * <p>
 * {@link #defaults()} offers only algorithms without known weaknesses. SHA-1 based ones
 * (ssh-rsa signatures, hmac-sha1, diffie-hellman-group14-sha1) are known, so
 * {@code setMacs("hmac-sha2-256", "hmac-sha1")} can turn them on for old peers, but not
 * offered by default.
 * <p>
 * An instance is configuration, not state: it is read when a connection starts. Changing it
 * from several threads needs outside synchronization.
 *
 * @author Tony Bringardner
 */
public class SshAlgorithms {

	private static final Map<String, NamedFactory<IKeyExchange>> KNOWN_KEX = new LinkedHashMap<String, NamedFactory<IKeyExchange>>();
	private static final Map<String, ISignatureAlgorithm> KNOWN_SIGNATURES = new LinkedHashMap<String, ISignatureAlgorithm>();
	private static final Map<String, NamedFactory<ISshCipher>> KNOWN_CIPHERS = new LinkedHashMap<String, NamedFactory<ISshCipher>>();
	private static final Map<String, NamedFactory<ISshMac>> KNOWN_MACS = new LinkedHashMap<String, NamedFactory<ISshMac>>();

	static {
		kex("curve25519-sha256", "SHA-256", X25519Agreement::new);
		kex("curve25519-sha256@libssh.org", "SHA-256", X25519Agreement::new);
		kex("ecdh-sha2-nistp256", "SHA-256", () -> new EcdhAgreement("nistp256"));
		kex("ecdh-sha2-nistp384", "SHA-384", () -> new EcdhAgreement("nistp384"));
		kex("ecdh-sha2-nistp521", "SHA-512", () -> new EcdhAgreement("nistp521"));
		kex("diffie-hellman-group16-sha512", "SHA-512", () -> new DhAgreement(DhAgreement.GROUP16, 1024));
		kex("diffie-hellman-group14-sha256", "SHA-256", () -> new DhAgreement(DhAgreement.GROUP14, 512));
		kex("diffie-hellman-group14-sha1", "SHA-1", () -> new DhAgreement(DhAgreement.GROUP14, 512));

		signature(new EcdsaSignature("nistp256", "SHA256withECDSA"));
		signature(new EcdsaSignature("nistp384", "SHA384withECDSA"));
		signature(new EcdsaSignature("nistp521", "SHA512withECDSA"));
		signature(new RsaSignature("rsa-sha2-512", "SHA512withRSA"));
		signature(new RsaSignature("rsa-sha2-256", "SHA256withRSA"));
		signature(new RsaSignature("ssh-rsa", "SHA1withRSA"));

		cipher("aes128-gcm@openssh.com", () -> new AesGcmCipher("aes128-gcm@openssh.com", 16));
		cipher("aes256-gcm@openssh.com", () -> new AesGcmCipher("aes256-gcm@openssh.com", 32));
		cipher("aes128-ctr", () -> new AesCtrCipher("aes128-ctr", 16));
		cipher("aes192-ctr", () -> new AesCtrCipher("aes192-ctr", 24));
		cipher("aes256-ctr", () -> new AesCtrCipher("aes256-ctr", 32));

		mac("hmac-sha2-256-etm@openssh.com", "HmacSHA256", 32, true);
		mac("hmac-sha2-512-etm@openssh.com", "HmacSHA512", 64, true);
		mac("hmac-sha2-256", "HmacSHA256", 32, false);
		mac("hmac-sha2-512", "HmacSHA512", 64, false);
		mac("hmac-sha1-etm@openssh.com", "HmacSHA1", 20, true);
		mac("hmac-sha1", "HmacSHA1", 20, false);
	}

	/** Known but not offered by default (SHA-1) */
	private static final List<String> WEAK = Arrays.asList("diffie-hellman-group14-sha1", "ssh-rsa", "hmac-sha1-etm@openssh.com", "hmac-sha1");

	private static void kex(String name, String hash, java.util.function.Supplier<IKeyAgreement> agreement) {
		KNOWN_KEX.put(name, NamedFactory.of(name, () -> new EphemeralKeyExchange(name, hash, agreement)));
	}

	private static void signature(ISignatureAlgorithm alg) {
		KNOWN_SIGNATURES.put(alg.getName(), alg);
	}

	private static void cipher(String name, java.util.function.Supplier<ISshCipher> supplier) {
		KNOWN_CIPHERS.put(name, NamedFactory.of(name, supplier));
	}

	private static void mac(String name, String jce, int size, boolean etm) {
		KNOWN_MACS.put(name, NamedFactory.of(name, () -> new HmacMac(name, jce, size, etm)));
	}

	/**
	 * Add an algorithm to the catalog, so {@code setKeyExchanges(...)} etc. can name it
	 * (e.g. a new key exchange). It is not offered until it is added to an instance's list.
	 */
	public static synchronized void registerKeyExchange(NamedFactory<IKeyExchange> factory) {
		KNOWN_KEX.put(factory.getName(), factory);
	}

	public static synchronized void registerSignature(ISignatureAlgorithm algorithm) {
		KNOWN_SIGNATURES.put(algorithm.getName(), algorithm);
	}

	public static synchronized void registerCipher(NamedFactory<ISshCipher> factory) {
		KNOWN_CIPHERS.put(factory.getName(), factory);
	}

	public static synchronized void registerMac(NamedFactory<ISshMac> factory) {
		KNOWN_MACS.put(factory.getName(), factory);
	}

	/**
	 * @return the signature algorithm with this name (known, not only offered), or null
	 */
	public static synchronized ISignatureAlgorithm findSignature(String name) {
		return KNOWN_SIGNATURES.get(name);
	}

	private final List<NamedFactory<IKeyExchange>> keyExchanges = new ArrayList<NamedFactory<IKeyExchange>>();
	private final List<ISignatureAlgorithm> hostKeyAlgorithms = new ArrayList<ISignatureAlgorithm>();
	private final List<NamedFactory<ISshCipher>> ciphers = new ArrayList<NamedFactory<ISshCipher>>();
	private final List<NamedFactory<ISshMac>> macs = new ArrayList<NamedFactory<ISshMac>>();
	private final List<String> compressions = new ArrayList<String>(Collections.singletonList("none"));

	/**
	 * Empty lists; see {@link #defaults()}.
	 */
	public SshAlgorithms() {
	}

	/**
	 * @return the default algorithms, strongest and fastest first
	 */
	public static synchronized SshAlgorithms defaults() {
		SshAlgorithms ret = new SshAlgorithms();
		for (NamedFactory<IKeyExchange> f : KNOWN_KEX.values()) {
			if( !WEAK.contains(f.getName()) && f.isSupported() ) {
				ret.keyExchanges.add(f);
			}
		}
		for (ISignatureAlgorithm s : KNOWN_SIGNATURES.values()) {
			if( !WEAK.contains(s.getName()) ) {
				ret.hostKeyAlgorithms.add(s);
			}
		}
		for (NamedFactory<ISshCipher> f : KNOWN_CIPHERS.values()) {
			if( !WEAK.contains(f.getName()) && f.isSupported() ) {
				ret.ciphers.add(f);
			}
		}
		for (NamedFactory<ISshMac> f : KNOWN_MACS.values()) {
			if( !WEAK.contains(f.getName()) && f.isSupported() ) {
				ret.macs.add(f);
			}
		}
		return ret;
	}

	/**
	 * @return a copy (the lists are copied, the factories shared)
	 */
	public SshAlgorithms copy() {
		SshAlgorithms ret = new SshAlgorithms();
		ret.keyExchanges.addAll(keyExchanges);
		ret.hostKeyAlgorithms.addAll(hostKeyAlgorithms);
		ret.ciphers.addAll(ciphers);
		ret.macs.addAll(macs);
		ret.compressions.clear();
		ret.compressions.addAll(compressions);
		return ret;
	}

	// ------------------------------------------------------------------ the lists (live, may be changed)

	public List<NamedFactory<IKeyExchange>> getKeyExchanges() {
		return keyExchanges;
	}

	public List<ISignatureAlgorithm> getHostKeyAlgorithms() {
		return hostKeyAlgorithms;
	}

	public List<NamedFactory<ISshCipher>> getCiphers() {
		return ciphers;
	}

	public List<NamedFactory<ISshMac>> getMacs() {
		return macs;
	}

	public List<String> getCompressions() {
		return compressions;
	}

	// ------------------------------------------------------------------ by name

	/**
	 * Offer these key exchanges, in this order.
	 * @throws IllegalArgumentException for a name that isn't known
	 */
	public SshAlgorithms setKeyExchanges(String... names) {
		replace(keyExchanges, KNOWN_KEX, names);
		return this;
	}

	public SshAlgorithms setHostKeyAlgorithms(String... names) {
		replace(hostKeyAlgorithms, KNOWN_SIGNATURES, names);
		return this;
	}

	public SshAlgorithms setCiphers(String... names) {
		replace(ciphers, KNOWN_CIPHERS, names);
		return this;
	}

	public SshAlgorithms setMacs(String... names) {
		replace(macs, KNOWN_MACS, names);
		return this;
	}

	private static synchronized <T> void replace(List<T> list, Map<String, T> known, String... names) {
		List<T> tmp = new ArrayList<T>();
		for (String name : names) {
			T t = known.get(name);
			if( t == null ) {
				throw new IllegalArgumentException("Unknown algorithm "+name+", known: "+known.keySet());
			}
			tmp.add(t);
		}
		list.clear();
		list.addAll(tmp);
	}

	public List<String> getKeyExchangeNames() {
		return names(keyExchanges);
	}

	public List<String> getHostKeyAlgorithmNames() {
		List<String> ret = new ArrayList<String>();
		for (ISignatureAlgorithm s : hostKeyAlgorithms) {
			ret.add(s.getName());
		}
		return ret;
	}

	public List<String> getCipherNames() {
		return names(ciphers);
	}

	public List<String> getMacNames() {
		return names(macs);
	}

	private static <T> List<String> names(List<NamedFactory<T>> list) {
		List<String> ret = new ArrayList<String>();
		for (NamedFactory<T> f : list) {
			ret.add(f.getName());
		}
		return ret;
	}

	/**
	 * @return the offered key exchange with this name, or null
	 */
	public NamedFactory<IKeyExchange> findKeyExchange(String name) {
		return find(keyExchanges, name);
	}

	public NamedFactory<ISshCipher> findCipher(String name) {
		return find(ciphers, name);
	}

	public NamedFactory<ISshMac> findMac(String name) {
		return find(macs, name);
	}

	/**
	 * @return the offered host key algorithm with this name, or null
	 */
	public ISignatureAlgorithm findHostKeyAlgorithm(String name) {
		for (ISignatureAlgorithm s : hostKeyAlgorithms) {
			if( s.getName().equals(name) ) {
				return s;
			}
		}
		return null;
	}

	private static <T> NamedFactory<T> find(List<NamedFactory<T>> list, String name) {
		for (NamedFactory<T> f : list) {
			if( f.getName().equals(name) ) {
				return f;
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return "kex="+getKeyExchangeNames()+" hostkey="+getHostKeyAlgorithmNames()+" ciphers="+getCipherNames()+" macs="+getMacNames();
	}
}
