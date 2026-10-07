package us.bringardner.parley.ssh.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Finding Pageant's named pipe and reading an OpenSSH config's IdentityAgent (what Pageant
 * --openssh-config writes). Connecting needs Windows and Pageant, so it isn't tested here.
 */
public class PageantTest {

	@TempDir
	File dir;

	@Test
	public void findsTheUsersPipe() {
		assertEquals("\\\\.\\pipe\\pageant.tony.0123abcd",
				SshAgent.pageantPipe(Arrays.asList("openssh-ssh-agent", "pageant.alice.ffff", "pageant.tony.0123abcd"), "Tony"));
		assertEquals("\\\\.\\pipe\\pageant.tony.99", SshAgent.pageantPipe(Arrays.asList("\\\\.\\pipe\\pageant.tony.99"), "tony"), "full names too");
		assertNull(SshAgent.pageantPipe(Arrays.asList("pageant.alice.ffff", "pageant.tony."), "tony"), "another user's, or no hash");
	}

	private String agentOf(String config) throws Exception {
		File f = new File(dir, "pageant.conf");
		Files.write(f.toPath(), config.getBytes(StandardCharsets.UTF_8));
		return SshAgent.identityAgent(f);
	}

	@Test
	public void readsIdentityAgent() throws Exception {
		assertEquals("\\\\.\\pipe\\pageant.tony.0123", agentOf("IdentityAgent \"\\\\.\\pipe\\pageant.tony.0123\"\n"));
		assertEquals("/tmp/agent.sock", agentOf("# comment\nHost *\n  identityagent=/tmp/agent.sock\n"));
		assertNull(agentOf("IdentityAgent none\n"));
		assertNull(agentOf("Host example\n  User tony\n"));
	}
}
