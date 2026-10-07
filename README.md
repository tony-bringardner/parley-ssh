# parley-ssh

SSH for **Parley**, a family of Java libraries for implementing internet protocols: an SSH client
and server (RFC 4251-4254) built on `parley-net`'s non-blocking `nio` package, with SFTP client and
server, and what OpenSSH users expect: certificates, agents, port forwarding and security keys.
It is tested against OpenSSH, Apache MINA SSHD and JSch.

| Package | What it holds |
|---|---|
| `us.bringardner.parley.ssh.algorithms` | Key exchange, host key, cipher and MAC plug-ins; certificates and security keys |
| `us.bringardner.parley.ssh.transport` | Packets, key exchange, re-keying (shared by client and server) |
| `us.bringardner.parley.ssh.connection` | Channels with flow control, port and agent forwarding channels (shared) |
| `us.bringardner.parley.ssh.client` | `SshClient`, `ClientSession`, `known_hosts`, login methods, SSH agent |
| `us.bringardner.parley.ssh.server` | `SshServer`, host keys, login methods, exec / shell / subsystem plug-ins |
| `us.bringardner.parley.ssh.sftp` | SFTP client |
| `us.bringardner.parley.ssh.sftp.server` | SFTP server: each user's root is any `FileSource` (local disk, memory, another SFTP server...) |
| `us.bringardner.parley.ssh.keys` | Reading and writing key files, key revocation lists |

## Features

**Algorithms** (strongest first): curve25519, ECDH and Diffie-Hellman group 14/16 key exchange;
Ed25519, ECDSA and RSA (SHA-2) keys; chacha20-poly1305, AES-GCM and AES-CTR ciphers; HMAC-SHA2
(encrypt-then-MAC); zlib compression; strict key exchange (the Terrapin fix); re-keying. SHA-1
algorithms are known but only used when turned on by name.

**Keys**: OpenSSH (including passphrase protected), PKCS#8, traditional PEM and key store files are
read; OpenSSH and PKCS#8 files are written.

**Client**
- Login with password, keyboard-interactive, public keys, OpenSSH certificates, or the keys of an
  SSH agent (`ssh-agent`, OpenSSH's Windows agent, PuTTY's Pageant)
- Host keys checked against `known_hosts` (hashed names, wildcards, `@revoked`, `@cert-authority`
  for host certificates) and key revocation lists
- exec, shells with a pseudo terminal, subsystems, local and remote port forwarding (`-L`, `-R`),
  agent forwarding (`-A`), keep-alives
- SFTP versions 3 to 6, with several reads and writes in flight

**Server**
- Login with password and keyboard-interactive through the access control list every Parley server
  uses, with `authorized_keys` files (including their options: `command=`, `from=`, `no-pty`,
  `permitopen=`, `restrict`, `cert-authority`...), with user certificates from trusted certificate
  authorities, and with FIDO security keys (`sk-ecdsa`, `sk-ed25519`; touch and PIN rules as in
  OpenSSH)
- Host keys made once and kept, from files or a key store, with host certificates
- Revoked keys and certificates refused (OpenSSH key revocation lists or key lists)
- The shared login limits: failures before the connection is closed, a delay after each, and a
  time limit for logging in
- What runs is up to plug-ins: commands, a shell, subsystems such as SFTP. `ProcessCommandFactory`
  and `ProcessShellFactory` run operating system commands, on a real pseudo terminal when pty4j is
  on the class path
- Port forwarding (refused unless a forwarding filter allows it) and agent forwarding
- SFTP versions 3 to 6 on any `FileSource`, which keeps each user inside their root

Requires Java 11 or later. Some features need more: Ed25519 needs Java 15, and SSH agents on Unix
(and agent forwarding) need Java 16 (Unix domain sockets).

```xml
<dependency>
    <groupId>us.bringardner.parley</groupId>
    <artifactId>parley-ssh</artifactId>
    <version>1.0.0</version>
</dependency>
```

Depends on `parley-net` (which brings in `parley-core` and `parley-io`). Optional dependencies, added
by you when you need them:

| Dependency | For |
|---|---|
| `us.bringardner.parley:parley-files` | The SFTP server (`us.bringardner.parley.ssh.sftp.server`) |
| `org.jetbrains.pty4j:pty4j` | Pseudo terminals for operating system commands and shells |

> parley-ssh was previously `us.bringardner:bjl_net_ssh` (BjlSsh), with packages under
> `us.bringardner.net.ssh`. Moving over means changing the dependency and replacing
> `us.bringardner.net.ssh` with `us.bringardner.parley.ssh` in imports and in property names that
> start with a class name.

## Client

```java
try (SshClient client = new SshClient()) {
    client.setHostKeyVerifier(KnownHosts.userFile());          // ~/.ssh/known_hosts
    ClientSession s = client.connectAndWait("example.com", 22);
    s.authenticateAndWait("tony", PublicKeyAuth.fromAgent(SshAgent.connect()));
    System.out.print(s.exec("uname -a", null, 30000).getStdoutText());

    try (SftpClient sftp = SftpClient.open(s)) {
        for (SftpDirEntry e : sftp.list(".")) {
            System.out.println(e.getLongName());
        }
    }
}
```

`new PublicKeyAuth(SshKeyLoader.load(file, passphrase))` logs in with a key file, and
`addCertificate(key, SshCertificate.load(certFile))` adds its certificate.

## Server

```java
SshServer server = new SshServer(2222);
server.setHostKeyProvider(HostKeyProviders.generated(new File("/var/myapp/ssh")));
server.setPublicKeyAuthenticator(AuthorizedKeysAuthenticator.forHomes(new File("/home")));
server.addSubsystem(SftpSubsystemFactory.forRoot(root));      // root: any FileSource
server.startAndWait(10000);
```

Without a password authenticator the server uses its access control list for passwords, as every
Parley server does.

### Properties

Settings can also be given as properties: system properties, or a properties file named after the
class on the class path, each named with the class name as prefix
(`us.bringardner.parley.ssh.server.SshServer.Port`) or without it (`Port`, then shared with other
Parley servers).

| Property | What it does | Default |
|---|---|---|
| `Port` | The port to listen on, when the server is made without one | 9200 (Parley's default: give 22 or another port) |
| `BindAddress` | The address to listen on | all addresses |
| `MaxConnections` | Connections at a time; more are refused | no limit |
| `Backlog` | Connections waiting to be accepted | the system's |
| `TcpNoDelay`, `KeepAlive` | TCP_NODELAY and SO_KEEPALIVE on connections | off |
| `AuthenticationProvider` | Class name of the access control list (users, passwords, permissions), e.g. `us.bringardner.parley.net.server.FileBasedAcl` | none |
| `HostKeyDir` | Where host keys are made and kept (with `*-cert.pub` host certificates) | the working directory |
| `KeyStoreName`, `KeyStorePassword`, `KeyStoreType` | Host keys from a key store's RSA and EC entries instead of `HostKeyDir` | not used |
| `ShellFactory` | Class name of the `IShellFactory` that answers "shell" requests, or `none` | fsh when it is on the class path, else none (shells refused) |
| `RevokedKeys` | A key revocation list or list of keys that can't log in | none |
| `MaxLoginAttempts` | Failed logins before the connection is closed | 6 |
| `LoginFailureDelay` | Milliseconds before a failed login is answered | 250 |
| `LoginTimeLimit` | Milliseconds a connection has to log in | 120000 |

Properties of other Parley servers that an SSH server ignores: `secure` (SSH encrypts itself and
never uses TLS), `SocketTimeout`, `AcceptTimeout`, `SoLinger` and `IsSoLinger` (they are for
servers that block a thread per connection).

### Settings in code

| `SshServer` method | What it does | Default |
|---|---|---|
| `setPasswordAuthenticator`, `setPublicKeyAuthenticator`, `setAuthMethods` | How users log in | the access control list for passwords |
| `setHostKeyProvider` | Where host keys (and host certificates) come from | `HostKeyDir` or the key store |
| `setCommandFactory`, `setShellFactory`, `addSubsystem` | What "exec", "shell" and subsystem requests run | refused, except shells: fsh when it is on the class path |
| `setForwardingFilter` | Which port forwardings are allowed (`ForwardingFilters.localOnly()`...) | none: refused |
| `setAgentForwardingAllowed` | Whether clients may forward their agent | yes, as OpenSSH |
| `setRevokedKeys` | Keys and certificates that can't log in | none |
| `setSecurityKeyTouchRequired`, `setSecurityKeyVerifyRequired` | Security keys must always be touched / verified with a PIN | no (the key's options decide) |
| `setAlgorithms` | The algorithms offered (`SshAlgorithms.defaults()`, then `setCiphers(...)`...) | the strongest, no SHA-1 |
| `setBanner` | Text shown before login | none |
| `setMaxChannelsPerSession` | Channels one connection may have open | 10 |
| `setMaxIdleTime` | Milliseconds without traffic before a connection is closed | 24 hours |
| `setMaxLoginAttempts`, `setLoginFailureDelay`, `setLoginTimeLimit` | The login limits (as the properties) | 6, 250 ms, 2 minutes |

| Client method | What it does | Default |
|---|---|---|
| `SshClient.setHostKeyVerifier` | How host keys are checked: `KnownHosts` (with `setPolicy`: reject, accept new, accept), `HostKeyVerifiers.only(...)` | `~/.ssh/known_hosts`, unknown hosts refused |
| `KnownHosts.setRevokedHostKeys` | Host keys and certificates to refuse | none |
| `SshClient.setAlgorithms` | The algorithms offered | the strongest, no SHA-1 |
| `SshClient.setKeepAliveInterval` | Milliseconds between keep-alives on idle sessions | off |
| `ClientSession.setAgentForwarding` | Lets the server use an SSH agent through the session | off |
| `SftpClient.setTimeout` | Milliseconds a request waits for its reply | 60000 |
| `SftpClient.setChunkSize`, `setOutstanding` | Bytes per read or write, and requests in flight | 32 KB, 16 |

**Running operating system commands is opt-in, and they run as the account the server runs as,
whoever logged in.** Give `ProcessCommandFactory` and `ProcessShellFactory` only to users who may do
anything that account can (with an access control list, they need the "exec" or "shell"
permission).

## Shells

`SshServer` answers "shell" requests (an interactive `ssh host`) through an `IShellFactory`, set in
code or named with the `ShellFactory` property.

**fsh, the FileSource Shell, is the default**: when no shell is configured and fsh
(`us.bringardner.fsh.ssh.FshShellFactory`) is on the class path, users who log in get fsh. It needs
Java 21; on older JVMs, or without fsh, shell requests are refused. `ShellFactory=none` turns the
default off, and setting another shell replaces it. `ProcessShellFactory` runs the operating
system's login shell instead.

**fsh works with the access of the account the server runs as**, whoever logged in. Adding fsh to a
server's class path gives every user who can log in a shell (with an access control list, only
users with the "shell" permission): set `ShellFactory=none` if they shouldn't have one.

## Not supported

Left out on purpose; none is a common need.

- **X11 forwarding** (`ssh -X` / `-Y`): showing graphical Unix programs from the server on the
  client's screen. The `no-X11-forwarding` option and the certificate extension are understood,
  but X11 requests are refused.
- **Tunnel devices** (`ssh -w`): a VPN through SSH. It needs root and native code to create network
  interfaces, which Java can't do.
- **Using a FIDO security key directly from the client**: talking to a USB key needs native
  libraries. The client can still log in with security keys held by an SSH agent, and the server
  accepts them.
- **WebAuthn security key signatures** (`webauthn-sk-ecdsa-sha2-nistp256@openssh.com`), used only by
  browser-based SSH clients.
- **SFTP version 4-6 extras**: text mode (line ending conversion), ACLs and byte-range locks
  (`BLOCK` / `UNBLOCK`). Text mode is ignored, ACLs are not set or sent, and lock requests are
  answered "unsupported". OpenSSH supports none of these either.

## Build and test

```
mvn verify
```

The tests run the client and server against Apache MINA SSHD, JSch and OpenSSH (test scope only):
OpenSSH's `ssh`, `ssh-keygen` and `ssh-agent` when installed, and private `sshd` instances started on
free ports as the current user. `OpenSshIT` also runs against an OpenSSH server
(`parley.ssh.it.host` / `parley.ssh.it.port`, default localhost) and is skipped when nothing listens
there. Tests that need OpenSSH, Unix or a newer Java are skipped where those are missing.

Not tested here: the Windows agent pipe, Pageant and pseudo terminals on Windows.
