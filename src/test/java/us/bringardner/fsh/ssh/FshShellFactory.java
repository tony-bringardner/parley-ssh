package us.bringardner.fsh.ssh;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import us.bringardner.parley.ssh.server.AbstractCommand;
import us.bringardner.parley.ssh.server.CommandEnvironment;
import us.bringardner.parley.ssh.server.ICommand;
import us.bringardner.parley.ssh.server.IShellFactory;

/**
 * A stand-in for fsh's real shell factory (fsh isn't a dependency of parley-ssh): the tests
 * check that SshServer uses the class of this name by default.
 */
public class FshShellFactory implements IShellFactory {

	@Override
	public ICommand create(CommandEnvironment env) {
		return new AbstractCommand() {
			@Override
			protected int run(CommandEnvironment e, InputStream in, OutputStream out, OutputStream err) throws Exception {
				out.write("fsh stand-in\n".getBytes(StandardCharsets.UTF_8));
				return 0;
			}
		};
	}
}
