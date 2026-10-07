package us.bringardner.parley.ssh.server;

/**
 * The test commands of {@link ServerTest} for tests in other packages.
 */
public final class ServerTestAccess {

	private ServerTestAccess() {
	}

	public static ICommand command(String line) {
		return ServerTest.command(line);
	}
}
