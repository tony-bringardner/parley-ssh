package us.bringardner.net.ssh.server;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.net.ssh.algorithms.SshAlgorithms;

/**
 * The server with the real OpenSSH client (/usr/bin/ssh): exec, exit codes, stderr, stdin,
 * and each algorithm OpenSSH will use. Logs in with a key ssh-keygen makes. Skipped
 * without ssh and ssh-keygen. Runs in 'mvn verify' (failsafe).
 */
public class OpenSshClientIT {

	@TempDir
	static File dir;

	private static SshServer server;
	private static File key;
	private static File sftpRoot;

	private static boolean have(String program) {
		try {
			Process p = new ProcessBuilder(program, "-V").redirectErrorStream(true).start();
			p.getInputStream().readAllBytes();
			return p.waitFor(10, TimeUnit.SECONDS);
		} catch (Exception e) {
			return false;
		}
	}

	@BeforeAll
	public static void start() throws Exception {
		Assumptions.assumeTrue(have("ssh"), "no ssh client");
		key = new File(dir, "id_ecdsa");
		Process kg = new ProcessBuilder("ssh-keygen", "-q", "-t", "ecdsa", "-N", "", "-f", key.getPath()).redirectErrorStream(true).start();
		Assumptions.assumeTrue(kg.waitFor(30, TimeUnit.SECONDS) && kg.exitValue() == 0, "no ssh-keygen");
		server = new SshServer(0);
		server.setHostKeyProvider(HostKeyProviders.ephemeral());
		server.setPublicKeyAuthenticator(AuthorizedKeysAuthenticator.forFile(new File(key.getPath()+".pub")));
		server.setCommandFactory((line, env) -> ServerTest.command(line));
		sftpRoot = new File(dir, "sftp-root");
		sftpRoot.mkdirs();
		server.addSubsystem(us.bringardner.net.ssh.sftp.server.SftpSubsystemFactory.forRoot(
				new us.bringardner.io.filesource.fileproxy.FileProxyFactory().createFileSource(sftpRoot.getCanonicalPath())));
		server.startAndWait(5000);
	}

	@AfterAll
	public static void stop() throws Exception {
		if( server != null ) {
			server.stop(5000, false);
		}
	}

	private static final class Result {
		int exit;
		byte[] out;
		String err;
	}

	private static Result ssh(byte[] stdin, String command, String... options) throws Exception {
		List<String> cmd = new ArrayList<String>(Arrays.asList("ssh", "-F", "/dev/null", "-p", ""+server.getLocalPort(),
				"-i", key.getPath(), "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes",
				"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"));
		for (String o : options) {
			cmd.add("-o");
			cmd.add(o);
		}
		cmd.add("alice@127.0.0.1");
		cmd.add(command);
		Process p = new ProcessBuilder(cmd).start();
		Thread writer = new Thread(() -> {
			try (OutputStream o = p.getOutputStream()) {
				if( stdin != null ) {
					o.write(stdin);
				}
			} catch (Exception e) {
				// the result shows it
			}
		});
		writer.start();
		ByteArrayOutputStream err = new ByteArrayOutputStream();
		Thread errReader = new Thread(() -> {
			try {
				p.getErrorStream().transferTo(err);
			} catch (Exception e) {
				// done
			}
		});
		errReader.start();
		Result r = new Result();
		r.out = p.getInputStream().readAllBytes();
		assertTrue(p.waitFor(60, TimeUnit.SECONDS), "ssh finished");
		errReader.join();
		writer.join();
		r.exit = p.exitValue();
		r.err = err.toString("UTF-8");
		return r;
	}

	@Test
	public void execAndExitCodes() throws Exception {
		Result r = ssh(null, "echo hello from openssh");
		assertEquals(0, r.exit, r.err);
		assertEquals("hello from openssh\n", new String(r.out, StandardCharsets.UTF_8));

		r = ssh(null, "fail 3");
		assertEquals(3, r.exit, "ssh exits with the command's status");
		assertTrue(r.err.contains("failing"), r.err);

		assertEquals("alice", new String(ssh(null, "whoami").out, StandardCharsets.UTF_8));
	}

	@Test
	public void stdinThroughCat() throws Exception {
		byte[] data = new byte[5*1024*1024];
		new Random(11).nextBytes(data);
		Result r = ssh(data, "cat");
		assertEquals(0, r.exit, r.err);
		assertArrayEquals(data, r.out);
	}

	/** Each of the server's algorithms, as far as this OpenSSH client still offers them */
	@Test
	public void eachAlgorithm() throws Exception {
		SshAlgorithms d = SshAlgorithms.defaults();
		List<String> worked = new ArrayList<String>();
		List<String> refused = new ArrayList<String>();
		List<String[]> runs = new ArrayList<String[]>();
		for (String k : d.getKeyExchangeNames()) {
			runs.add(new String[] {"KexAlgorithms="+k});
		}
		for (String h : new String[] {"ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"}) {
			runs.add(new String[] {"HostKeyAlgorithms="+h});
		}
		for (String c : d.getCipherNames()) {
			runs.add(new String[] {"Ciphers="+c});
		}
		for (String m : d.getMacNames()) {
			runs.add(new String[] {"Ciphers=aes128-ctr", "MACs="+m});
		}
		for (String[] o : runs) {
			Result r = ssh(null, "echo ok", o);
			if( r.exit == 0 && "ok\n".equals(new String(r.out, StandardCharsets.UTF_8)) ) {
				worked.add(String.join(" ", o));
			} else if( r.err.contains("Bad SSH2") || r.err.contains("Unsupported") || r.err.contains("no matching") ) {
				// this OpenSSH client doesn't do it
				refused.add(String.join(" ", o)+": "+r.err.trim());
			} else {
				throw new AssertionError(String.join(" ", o)+" failed ("+r.exit+"): "+r.err);
			}
		}
		System.out.println("OpenSSH client: worked "+worked.size()+" "+worked+"; not supported by the client "+refused);
		assertTrue(worked.size() >= runs.size()-4, "worked: "+worked);
	}

	/** OpenSSH's sftp in batch mode: mkdir, put, ls, get, rename, chmod, rm, rmdir */
	@Test
	public void sftpBatch() throws Exception {
		Assumptions.assumeTrue(have("sftp"), "no sftp client");
		File local = new File(dir, "upload.bin");
		byte[] data = new byte[3*1024*1024+7];
		new Random(13).nextBytes(data);
		java.nio.file.Files.write(local.toPath(), data);
		File back = new File(dir, "download.bin");
		File batch = new File(dir, "batch.txt");
		java.nio.file.Files.write(batch.toPath(), String.join("\n",
				"mkdir docs",
				"cd docs",
				"put "+local.getPath()+" up.bin",
				"ls -l",
				"get up.bin "+back.getPath(),
				"rename up.bin renamed.bin",
				"chmod 600 renamed.bin",
				"ls -l",
				"").getBytes(StandardCharsets.UTF_8));
		List<String> cmd = new ArrayList<String>(Arrays.asList("sftp", "-F", "/dev/null", "-P", ""+server.getLocalPort(),
				"-i", key.getPath(), "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes",
				"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
				"-b", batch.getPath(), "alice@127.0.0.1"));
		Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
		String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		assertTrue(p.waitFor(60, TimeUnit.SECONDS));
		assertEquals(0, p.exitValue(), out);
		assertArrayEquals(data, java.nio.file.Files.readAllBytes(back.toPath()), "get");
		File onServer = new File(sftpRoot, "docs/renamed.bin");
		assertArrayEquals(data, java.nio.file.Files.readAllBytes(onServer.toPath()), "put and rename");
		assertEquals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"),
				java.nio.file.Files.getPosixFilePermissions(onServer.toPath()), "chmod");
		assertTrue(out.contains("renamed.bin"), out);

		java.nio.file.Files.write(batch.toPath(), "rm docs/renamed.bin\nrmdir docs\n".getBytes(StandardCharsets.UTF_8));
		p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
		out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		assertTrue(p.waitFor(60, TimeUnit.SECONDS));
		assertEquals(0, p.exitValue(), out);
		assertTrue(!new File(sftpRoot, "docs").exists(), "rm and rmdir");
	}
}
