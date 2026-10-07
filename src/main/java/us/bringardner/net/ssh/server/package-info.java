/**
 * The SSH server: {@link us.bringardner.net.ssh.server.SshServer} (a framework NioServer),
 * one {@link us.bringardner.net.ssh.server.ServerSession} per connection, host keys
 * ({@link us.bringardner.net.ssh.server.HostKeyProviders}), user authentication plug-ins
 * ({@link us.bringardner.net.ssh.server.IServerAuthMethod}: password and keyboard-interactive
 * through the access control list, publickey through authorized_keys), and what sessions
 * run: {@link us.bringardner.net.ssh.server.ICommandFactory} (exec),
 * {@link us.bringardner.net.ssh.server.IShellFactory} and
 * {@link us.bringardner.net.ssh.server.ISubsystemFactory} (e.g. SFTP). Nothing runs unless
 * a plug-in is set.
 */
package us.bringardner.net.ssh.server;
