/**
 * An SFTP version 3 server subsystem on BjlFileSystem: each user's root is any
 * {@link us.bringardner.io.filesource.FileSource} (local disk, memory, JDBC, another SFTP
 * server...), and nothing outside it can be reached. Needs bjl_file_system (an optional
 * dependency of bjl_net_ssh).
 */
package us.bringardner.net.ssh.sftp.server;
