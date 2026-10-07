/**
 * An SSH library, client and server (RFC 4251-4254), built on bjl_net_framework's
 * non-blocking {@link us.bringardner.net.framework.nio} package:
 * <ul>
 * <li>{@code algorithms}: key exchange, host key, cipher and MAC plug-ins</li>
 * <li>{@code transport}: packets, key exchange, re-keying (shared by client and server)</li>
 * <li>{@code connection}: channels with flow control (shared)</li>
 * <li>{@code client}: SshClient, ClientSession, known_hosts, login methods</li>
 * <li>{@code server}: SshServer, host keys, login methods, exec / shell / subsystem plug-ins</li>
 * <li>{@code sftp}: SFTP client; {@code sftp.server}: SFTP server on FileSource</li>
 * <li>{@code keys}: reading and writing key files</li>
 * </ul>
 */
package us.bringardner.net.ssh;
