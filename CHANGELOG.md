# Changelog

## parley-ssh 1.0.0 (unreleased)

BjlSsh (`us.bringardner:bjl_net_ssh` 1.0.0-SNAPSHOT, never released) is now **parley-ssh**, part of
the Parley library family. Besides the new names (below), it adds what OpenSSH users expect:
certificates, agents, key options and revocation, security keys, real terminals and SFTP up to
version 6.

### Added

- **OpenSSH certificates** (`SshCertificate`): user certificates (client `PublicKeyAuth.addCertificate`,
  server `UserCertificateAuthenticator` with trusted CA keys and optional principals) and host
  certificates (servers use `*-cert.pub` next to their keys; clients trust `@cert-authority` lines
  in `known_hosts`). `force-command`, `source-address` and the `permit-*` extensions are enforced;
  certificates with unknown critical options are refused.
- **authorized_keys options**: `command=`, `from=`, `expiry-time=`, `no-pty`, `no-port-forwarding`,
  `no-agent-forwarding`, `no-X11-forwarding`, `no-user-rc`, `restrict` and the options that allow
  things again, `permitopen=`, `permitlisten=`, `cert-authority` with `principals=`, and
  `no-touch-required` / `verify-required`. Lines with other options are still skipped.
- **Key revocation** (`KeyRevocationList`): OpenSSH KRLs and plain key lists, re-read when they
  change. Servers refuse revoked keys and certificates (`setRevokedKeys`, `RevokedKeys` property);
  clients refuse revoked host keys (`KnownHosts.setRevokedHostKeys`).
- **FIDO security keys** on the server: `sk-ecdsa-sha2-nistp256@openssh.com`,
  `sk-ssh-ed25519@openssh.com` and their certificates, with OpenSSH's touch and PIN rules
  (`setSecurityKeyTouchRequired`, `setSecurityKeyVerifyRequired`).
- **SSH agents** (`SshAgent`): log in with an agent's keys and certificates (`PublicKeyAuth.fromAgent`);
  `ssh-agent` (Unix, Java 16+), OpenSSH's Windows agent and PuTTY's Pageant.
- **Agent forwarding** (`ssh -A`): clients allow it with `ClientSession.setAgentForwarding` and ask
  with `SessionChannel.requestAgentForwarding`; servers give the session's commands `SSH_AUTH_SOCK`
  and Java code `ServerSession.openForwardedAgent`. Allowed by default, as in OpenSSH
  (`setAgentForwardingAllowed`).
- **Pseudo terminals** for operating system commands: with pty4j (a new optional dependency)
  `ProcessCommandFactory` runs commands on a real pty when the client asks for one, and the new
  `ProcessShellFactory` runs the login shell. The size follows the client's window.
- **SFTP versions 4 to 6**: the server speaks the client's version up to 6 (and `version-select`);
  the client asks for 3 by default, up to 6 with `SftpClient.open(session, version)`.
  `SftpAttrs` reads and writes every version (file type, owner names, nanosecond times).
- `ShellFactory` property: the shell is chosen by class name; a class that can't be made stops the
  server from starting.
- **fsh is the default shell**: with no shell configured, a server whose class path has fsh
  (`us.bringardner.fsh.ssh.FshShellFactory`, Java 21+) gives users fsh. `ShellFactory=none` turns
  it off.

### Changed (needs a code change)

- Maven coordinates: `us.bringardner:bjl_net_ssh` is now `us.bringardner.parley:parley-ssh`.
- Packages: `us.bringardner.net.ssh` (and `.algorithms`, `.client`, `.connection`, `.keys`,
  `.server`, `.sftp`, `.transport`) is now `us.bringardner.parley.ssh`.
- Module name (`Automatic-Module-Name`): `us.bringardner.net.ssh` is now `us.bringardner.parley.ssh`.
- Dependencies: `bjl_net_framework` and the optional `bjl_file_system` are now `parley-net` and the
  optional `parley-files`.

- Login limits are the shared ones of parley-core's `AbstractCoreServer`: `setMaxAuthTries`,
  `setLoginGraceTime` and `setAuthFailureDelay` are now `setMaxLoginAttempts`, `setLoginTimeLimit`
  and `setLoginFailureDelay` (also the `MaxLoginAttempts`, `LoginTimeLimit` and `LoginFailureDelay`
  properties), still with OpenSSH's defaults (6 tries, 2 minutes, 250 ms).
- PEM key loading moved to parley-core (`PrivateKeys`, `Pem`, `Der`); `SshKeyLoader` and
  `SshKeyWriter` keep their methods. `us.bringardner.parley.ssh.keys.Der` is gone.

### Changed (no code change needed)

- The SSH identification string is now `SSH-2.0-ParleySsh_1.0` (was `SSH-2.0-BjlSsh_1.0`).
- New host key files are commented `parley-ssh host key`.
- The OpenSSH integration tests read `parley.ssh.it.host` / `parley.ssh.it.port`
  (were `bjl.ssh.it.*`).
- authorized_keys lines with options were skipped; the supported options are now used (see Added).
- The default algorithm lists include the certificate and security key algorithms (after the
  plain ones; a client asks for certificates first for hosts whose CA it trusts).

### Fixed

- Port forwarding sometimes lost the end of the data (about half the time with several large
  transfers at once): when the far side closed the channel, the local socket was closed before
  the data already received had been written to it.
- The `secure` property (meant for TLS servers) is ignored by `SshServer` and `SshClient`: set,
  even without the class name prefix, it made them speak TLS so no SSH peer could connect.
  `SshServer.setSecure(true)` now throws `IllegalArgumentException`.
- Operating system commands no longer inherit the server's own `SSH_AUTH_SOCK`, which let any user
  use the server account's SSH agent.
- A version 4+ SFTP client that sent a file type without permissions made the server create files
  with mode 0.
