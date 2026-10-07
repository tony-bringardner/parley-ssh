package us.bringardner.parley.ssh.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.ssh.algorithms.SshPublicKeys;
import us.bringardner.parley.ssh.client.KnownHosts.Result;

public class KnownHostsTest {

	@TempDir
	File dir;

	private static PublicKey ec() throws Exception {
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
		g.initialize(new ECGenParameterSpec("secp256r1"));
		return g.generateKeyPair().getPublic();
	}

	private static PublicKey rsa() throws Exception {
		KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
		g.initialize(2048);
		return g.generateKeyPair().getPublic();
	}

	@Test
	public void lookups() throws Exception {
		PublicKey a = ec();
		PublicKey b = ec();
		PublicKey r = rsa();
		PublicKey revoked = ec();
		List<String> lines = Arrays.asList(
				"# comment",
				"",
				"host1,10.0.0.1 "+SshPublicKeys.toOpenSsh(a)+" a comment",
				"[host2]:2222 "+SshPublicKeys.toOpenSsh(b),
				"*.example.com,!bad.example.com "+SshPublicKeys.toOpenSsh(r),
				"@revoked * "+SshPublicKeys.toOpenSsh(revoked),
				"host3 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
				"garbage");
		KnownHosts kh = new KnownHosts(lines);

		assertEquals(Result.TRUSTED, kh.check("host1", 22, a));
		assertEquals(Result.TRUSTED, kh.check("HOST1", 22, a), "host names ignore case");
		assertEquals(Result.TRUSTED, kh.check("10.0.0.1", 22, a));
		assertEquals(Result.CHANGED, kh.check("host1", 22, b));
		assertEquals(Result.UNKNOWN, kh.check("host1", 2222, a), "another port is another host");
		assertEquals(Result.TRUSTED, kh.check("host2", 2222, b));
		assertEquals(Result.OTHER_TYPES_KNOWN, kh.check("host2", 2222, r));
		assertEquals(Result.TRUSTED, kh.check("www.example.com", 22, r));
		assertEquals(Result.UNKNOWN, kh.check("bad.example.com", 22, r), "negated pattern");
		assertEquals(Result.REVOKED, kh.check("anything", 22, revoked));
		// Unsupported key types still count, a host known with Ed25519 isn't "unknown"
		assertEquals(Result.OTHER_TYPES_KNOWN, kh.check("host3", 22, a));
		assertEquals(Arrays.asList("ssh-ed25519"), kh.getKnownKeyTypes("host3", 22));

		assertTrue(kh.verify("host1", 22, a));
		assertFalse(kh.verify("host1", 22, b), "changed key");
		assertFalse(kh.verify("new", 22, a), "unknown, REJECT");
		kh.setPolicy(KnownHosts.Policy.ACCEPT);
		assertTrue(kh.verify("new", 22, a));
		assertFalse(kh.verify("host1", 22, b), "a changed key is refused whatever the policy");
		assertFalse(kh.verify("x", 22, revoked));
	}

	@Test
	public void acceptNewWritesHashedEntries() throws Exception {
		File f = new File(dir, "ssh/known_hosts");
		PublicKey a = ec();
		KnownHosts kh = new KnownHosts(f).setPolicy(KnownHosts.Policy.ACCEPT_NEW);
		assertTrue(kh.verify("myhost", 2200, a));
		String text = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
		assertTrue(text.startsWith("|1|"), "hashed: "+text);
		assertFalse(text.contains("myhost"));

		// A new reader of the file trusts the key, and only for that host and port
		KnownHosts again = new KnownHosts(f);
		assertEquals(Result.TRUSTED, again.check("myhost", 2200, a));
		assertEquals(Result.UNKNOWN, again.check("myhost", 22, a));
		assertEquals(Result.CHANGED, again.check("myhost", 2200, ec()));
	}
}
