package us.bringardner.parley.ssh.client;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

/**
 * Key helpers for the client tests.
 */
final class CertificateTestAccess {

	private CertificateTestAccess() {
	}

	/** @return a new P-256 key pair */
	static KeyPair ec() throws Exception {
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
		g.initialize(new ECGenParameterSpec("secp256r1"));
		return g.generateKeyPair();
	}
}
