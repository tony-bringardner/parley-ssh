# Changelog

## parley-ssh 1.0.0 (unreleased)

BjlSsh (`us.bringardner:bjl_net_ssh` 1.0.0-SNAPSHOT, never released) is now **parley-ssh**, part of
the Parley library family. The code is the same; only names changed.

### Changed (needs a code change)

- Maven coordinates: `us.bringardner:bjl_net_ssh` is now `us.bringardner.parley:parley-ssh`.
- Packages: `us.bringardner.net.ssh` (and `.algorithms`, `.client`, `.connection`, `.keys`,
  `.server`, `.sftp`, `.transport`) is now `us.bringardner.parley.ssh`.
- Module name (`Automatic-Module-Name`): `us.bringardner.net.ssh` is now `us.bringardner.parley.ssh`.
- Dependencies: `bjl_net_framework` and the optional `bjl_file_system` are now `parley-net` and the
  optional `parley-files`.

### Changed (no code change needed)

- The SSH identification string is now `SSH-2.0-ParleySsh_1.0` (was `SSH-2.0-BjlSsh_1.0`).
- New host key files are commented `parley-ssh host key`.
- The OpenSSH integration tests read `parley.ssh.it.host` / `parley.ssh.it.port`
  (were `bjl.ssh.it.*`).
