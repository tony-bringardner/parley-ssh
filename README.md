# parley-ssh

SSH for **Parley**, a family of Java libraries for implementing internet protocols: an SSH client
and server (RFC 4251-4254) built on `parley-net`'s non-blocking `nio` package, with an SFTP
client and an SFTP version 3 server subsystem.

| Package | What it holds |
|---|---|
| `us.bringardner.parley.ssh.algorithms` | Key exchange, host key, cipher and MAC plug-ins |
| `us.bringardner.parley.ssh.transport` | Packets, key exchange, re-keying (shared by client and server) |
| `us.bringardner.parley.ssh.connection` | Channels with flow control (shared) |
| `us.bringardner.parley.ssh.client` | `SshClient`, `ClientSession`, `known_hosts`, login methods |
| `us.bringardner.parley.ssh.server` | `SshServer`, host keys, login methods, exec / shell / subsystem plug-ins |
| `us.bringardner.parley.ssh.sftp` | SFTP client |
| `us.bringardner.parley.ssh.sftp.server` | SFTP server: each user's root is any `FileSource` (local disk, memory, another SFTP server...) |
| `us.bringardner.parley.ssh.keys` | Reading and writing key files |

Supported algorithms include Ed25519, chacha20-poly1305, compression, bcrypt-protected keys and
port forwarding.

Requires Java 11 or later. Depends on `parley-net` (which brings in `parley-core` and `parley-io`).
The SFTP server also needs `parley-files`, an optional dependency: add it yourself if you use
`us.bringardner.parley.ssh.sftp.server`.

```xml
<dependency>
    <groupId>us.bringardner.parley</groupId>
    <artifactId>parley-ssh</artifactId>
    <version>1.0.0</version>
</dependency>
```

> parley-ssh was previously `us.bringardner:bjl_net_ssh` (BjlSsh), with packages under
> `us.bringardner.net.ssh`. Moving over means changing the dependency and replacing
> `us.bringardner.net.ssh` with `us.bringardner.parley.ssh` in imports and in property names that
> start with a class name.

## Shells

`SshServer` answers "shell" requests (an interactive `ssh host`) through an `IShellFactory`, named
with the `ShellFactory` property. fsh, the FileSource Shell, is one such shell.

## Build and test

```
mvn verify
```

The tests run the client and server against Apache MINA SSHD and JSch (test scope only).
`OpenSshIT` and `OpenSshClientIT` run against a real OpenSSH (`parley.ssh.it.host` /
`parley.ssh.it.port`, default localhost) and are skipped when nothing listens there.
