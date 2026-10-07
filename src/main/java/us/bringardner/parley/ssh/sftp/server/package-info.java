/**
 * An SFTP version 3 server subsystem on parley-files: each user's root is any
 * {@link us.bringardner.parley.files.FileSource} (local disk, memory, JDBC, another SFTP
 * server...), and nothing outside it can be reached. Needs parley-files (an optional
 * dependency of parley-ssh).
 */
package us.bringardner.parley.ssh.sftp.server;
