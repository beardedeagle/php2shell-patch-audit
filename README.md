# PHP2Shell patch audit

Checks PHP installations for fixes for PHP2Shell (CVE-2026-109618 and
CVE-2026-109619). Supports running executables and modules on Linux and macOS,
process and DLL discovery on Windows, installed-file checks, SSH and container access,
HTTP/phpinfo checks, multipart-filter checks, and log/event inspection.
By default, it reads PHP files without executing them. `--probe-php` runs a
selected trusted binary; `--multipart-check` sends a small POST.

It does not patch, restart services, change configuration, or determine whether
a host has already been compromised.

Requirements: Python **3.9+**, with no third-party Python dependencies. Controllers
can run on Linux, macOS, or Windows. Windows discovery also uses the system's
Windows PowerShell. Unix SSH/container targets default to `/usr/bin/python3`;
`--remote-python` selects another absolute path. `--sudo` needs noninteractive
`/usr/bin/sudo`. SSH host keys must already be trusted.

## Platform scope

The tables below list expected platform compatibility, known fixed package versions,
and test coverage.

### Potential platform coverage

Linux discovery uses `/proc` and does not filter by distribution name. The systems
below are expected to work with Python 3.9+, readable `/proc`, a supported package
database format/location, and the required system utilities. Only the environments
listed under [Tested environments](#tested-environments) have been tested.
systemd is not required. Restricted procfs or namespaces can prevent inspection.
Custom installations can use inventory paths and build records tied to SHA-256 hashes.

| Family and example systems | Checks | Patch evidence required |
| --- | --- | --- |
| Debian, Ubuntu; dpkg derivatives such as Linux Mint, Pop!_OS, Kali and Raspberry Pi OS | Linux process/mapping identity, dpkg ownership and file checksums, native revision comparison. | Built-in rules only for the combinations below; other releases/derivatives need their own vendor rules or build evidence. |
| RHEL, Rocky Linux, AlmaLinux, CentOS/CentOS Stream, Fedora, Oracle Linux and Amazon Linux | Linux process/mapping identity, RPM ownership and file checksums, native revision comparison. | Selected RHEL rules below; other vendors/streams need explicit rules, scoped RPM updateinfo, or build evidence. |
| SUSE Linux Enterprise and openSUSE | The same generic RPM inspection path. | Vendor rules, scoped RPM updateinfo, or build evidence; no built-in SUSE/openSUSE thresholds. |
| Alpine and compatible APK-based Linux systems | Linux process/mapping identity, installed-file `Q1` SHA-1 checksums and native APK version comparison. | Rules for selected Alpine 3.23/3.24 packages below; other releases/derivatives need vendor or build evidence. Other APK checksum encodings remain unsupported. |
| Arch Linux, Manjaro and compatible pacman-based derivatives | Linux process/mapping identity, package ownership, mtree SHA-256 and native `vercmp`. | Rules for Arch rolling `php` and `php-legacy`; other packages and derivatives, including Manjaro, need vendor or build evidence. |
| Gentoo, NixOS, Slackware, other Linux, and custom/embedded builds | Linux process/mapping identity and explicit runtime inventory. | SHA-256-bound build evidence. No Portage, Nix or Slackware package adapter is implemented. |
| Windows desktop and Windows Server installations with Python and Windows PowerShell | Native process/DLL discovery, file hashes and PE version-resource hints; Windows OpenSSH transport. | Installed-file verdicts require build evidence. Running-image status remains `UNKNOWN`, with separate `file_status`. See the Windows versions tested below. |
| macOS on Apple Silicon or Intel, with readable native process information | Native executable/module discovery and mapped-file identity through libproc; Homebrew receipt and MacPorts registry ownership; local and SSH checks. | A trusted package archive with matching file bytes, or SHA-256-bound build evidence. Package ownership/version alone remains `UNKNOWN`. Intel and older macOS releases have not been tested. |
| FreeBSD, OpenBSD, NetBSD and other compatible Python hosts | Explicit installed-file assessment, HTTP and log observations. | SHA-256-bound build evidence for listed files. No native BSD process collector or package adapter is implemented. |

Linux containers and WSL use the backend for their guest distribution. Audit each
deployment namespace separately; a guest report does not cover its host or other
guests. Docker/Podman transport has the prerequisites described below. HTTP checks
can target any OS, but cannot verify the backend's patch status.

### Known fixed package versions

These are comparison thresholds, not patches applied by the script. It includes
vendor fix versions for these OS/PHP combinations. Rules apply
to recognized PHP runtime packages. File identity, checksums and inventory
requirements still apply.

| OS release | PHP branch covered |
| --- | --- |
| Ubuntu 14.04 | 5.5 |
| Ubuntu 16.04 | 7.0 |
| Ubuntu 18.04 | 7.2 |
| Ubuntu 20.04 | 7.4 |
| Ubuntu 22.04 | 8.1 |
| Ubuntu 24.04 | 8.3 |
| Ubuntu 26.04, 26.10 | 8.5 |
| Debian 12 | 8.2 |
| Debian 13 | 8.4 |
| RHEL 8.10 | Red Hat PHP 7.4 module stream |
| RHEL 9.8 | Red Hat PHP 8.0, non-modular |
| Alpine 3.23 and 3.24, including their point releases | PHP 8.3, 8.4 and 8.5: base, `-fpm`, `-cgi` and `-apache2` packages |
| Arch rolling | `php` (8.5) and `php-legacy` (8.3); separate split packages require their own evidence |

Full fixed-package revisions and evidence formats are documented under
[Package and build evidence](#package-and-build-evidence). Older-release update
availability may depend on vendor support entitlements. Derivatives do not inherit
their parent distribution's thresholds. Missing vendor/build evidence remains
`UNKNOWN`. Unsupported package databases are reported as inspection errors.

### Tested environments

The original native checks used system executables or compiled fixtures as
stand-ins for PHP. Real PHP 8.3.35 and 8.3.36 tests on 2026-10-23 used isolated
Docker containers, without installing PHP on a workstation or publishing ports.

| Environment | Tests run |
| --- | --- |
| Debian 13 container | dpkg file checksum, native version comparison, Linux process identity and replacement detection. |
| Alpine 3.24.2 container | APK file checksum, native version comparison, Linux process identity and replacement detection. |
| Rocky Linux 9.3 container | RPM metadata/checksum, native version comparison, Linux process identity and replacement detection. This does not validate the RHEL advisory thresholds. |
| Arch rolling container under amd64 emulation | pacman mtree checksum and native version comparison; procfs checks were not tested under emulation. |
| Windows build 26300, Python 3.13.15, Windows PowerShell 5.1 | Native file evidence, path casing, PE resources, process/DLL discovery, and key-authenticated Windows SSH. The report includes access errors and cannot verify loaded images. |
| macOS controller | Controller execution and offline/loopback regressions; Docker transport to a temporary Debian container. |
| macOS 27.0.1, arm64 | Native PID enumeration, executable/module discovery, mapped-file identity and replacement detection. Temporary Homebrew receipt/archive and MacPorts registry/archive fixtures; no PHP installation or live MacPorts deployment tested. |
| PHP 8.3.35 and 8.3.36, Debian Bookworm Docker Official Images, arm64 | Real PHP-FPM pools, Apache/mod_php, two CLI installations, affected/fixed verdicts, missing evidence/inventory, and stale workers after binary replacement. |
| Alpine 3.24.2 container with `php83` 8.3.36-r0 | Real installed PHP checksum and the new Alpine vendor rule, using native APK version comparison. |

All 113 regressions passed on macOS/Python 3.14.7, Windows/Python 3.13.15, and
disposable Linux containers with Python 3.9 and 3.15 on 2026-10-23.
The CI workflow covers Python 3.9 and 3.15 on Linux, Windows and Intel
macOS, plus real PHP fixtures on Linux, Windows and Apple Silicon macOS hosted
runners. Hosted CI jobs have not yet been executed for this change; their
configuration does not establish platform acceptance.
Other named derivatives, Windows Server releases, BSD hosts, WSL and Podman
transport have not been tested on those systems. Intel/older macOS, live macOS SSH,
Linux SSH/sudo policy, production PHP workloads and fleet-wide deployment coverage
are also untested. The macOS SSH command construction has a regression test.

## Patching guidance

Apply updates through the repository or vendor that supplies PHP. Use the
instructions for the installed OS release.

### Confirm that the update fixes both CVEs

Use the applicable advisory to identify a fixed package or build before updating:

- **Upstream PHP:** [CVE-2026-109618 advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [CVE-2026-109619 advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).
- **Ubuntu:** Canonical's [CVE-2026-109618](https://ubuntu.com/security/CVE-2026-109618) and [CVE-2026-109619](https://ubuntu.com/security/CVE-2026-109619) trackers list release/package status and associated notices.
- **Debian:** the [CVE-2026-109618](https://security-tracker.debian.org/tracker/CVE-2026-109618) and [CVE-2026-109619](https://security-tracker.debian.org/tracker/CVE-2026-109619) trackers identify affected and fixed package revisions.
- **RHEL:** [RHSA-2026:87080](https://access.redhat.com/errata/RHSA-2026:87080) covers the selected RHEL 8 PHP stream; [RHSA-2026:87151](https://access.redhat.com/errata/RHSA-2026:87151) covers the selected RHEL 9 package. Check product, release, architecture and module stream applicability.

For other vendors, obtain their own advisory or trusted build evidence covering
**both** CVEs. Backports may retain an older upstream version number. Neither a
successful package-manager run nor the absence of available updates proves a fix.
An end-of-life release may require extended support or migration to a supported
release. See [Package and build evidence](#package-and-build-evidence) for what
this audit can verify.

### OS and package-manager update procedures

Links checked on 2026-10-23. These guides explain how to apply updates; use the
advisories above to check whether an update fixes PHP2Shell. Version-specific
guides apply to the named releases. Derivatives need their own repositories and
advisories.

| System or PHP installation | Official guidance and scope |
| --- | --- |
| Ubuntu | [Install and manage packages](https://ubuntu.com/server/docs/how-to/software/package-management/) explains refreshing APT metadata and upgrading installed packages. |
| Debian | [Keeping a system up to date](https://www.debian.org/doc/manuals/debian-handbook/sect.regular-upgrades.en.html) covers regular and security updates. |
| RHEL | [Apply security errata with YUM/DNF](https://access.redhat.com/solutions/10021) covers security-, CVE- and advisory-selected updates, with release-specific instructions. |
| Rocky Linux | [DNF package manager](https://docs.rockylinux.org/guides/package_management/dnf_package_manager/) includes package updates and upgrades. |
| AlmaLinux | [Security errata](https://wiki.almalinux.org/documentation/errata.html) explains how to find advisories and fixed packages with DNF. It does not cover installation. |
| Fedora installations using DNF5 | The package manager's [upgrade command](https://dnf5.readthedocs.io/en/latest/commands/upgrade.8.html) documents package upgrades and security/advisory filters. |
| Oracle Linux | [Updating software](https://docs.oracle.com/en/operating-systems/oracle-linux/software-management/sfw-mgmt-UpdateSoftwareonEnterpriseLinux.html) and [tracking security updates and errata](https://docs.oracle.com/en/operating-systems/oracle-linux/software-management/sfw-mgmt-TrackSecurityUpdatesandErrataReleases.html). |
| Amazon Linux 2023 | [Manage package and OS updates](https://docs.aws.amazon.com/linux/al2023/ug/managing-repos-os-updates.html) and [apply security updates in place](https://docs.aws.amazon.com/linux/al2023/ug/security-inplace-update.html). Account for AL2023's versioned repositories; these instructions do not cover Amazon Linux 2. |
| SUSE Linux Enterprise Server 15 SP7 | [YaST online update](https://documentation.suse.com/sles/15-SP7/html/SLES-all/cha-onlineupdate-you.html) and [Zypper software management](https://documentation.suse.com/sles/15-SP7/html/SLES-all/cha-sw-cl.html) cover patches and package updates. |
| openSUSE Leap 15.6 | [YaST online update](https://doc.opensuse.org/documentation/leap/startup/html/book-startup/cha-onlineupdate-you.html). Use the matching release's procedure for other Leap releases or Tumbleweed. |
| Alpine Linux | [APK: upgrading packages](https://docs.alpinelinux.org/user-handbook/0.1a/Working/apk.html#_upgrading_packages) covers package-index refresh, upgrades and changed configuration files. |
| Arch Linux | [System maintenance](https://wiki.archlinux.org/title/System_maintenance) requires full system upgrades; partial upgrades are unsupported. Manjaro users need their own release/update guidance. |
| Gentoo | [Upgrading Gentoo](https://wiki.gentoo.org/wiki/Upgrading_Gentoo) describes repository synchronization, package updates and configuration handling. |
| NixOS | [Upgrading NixOS](https://nixos.org/manual/nixos/stable/#sec-upgrading) covers channel updates and rebuilding/activating the system. Separately pinned PHP inputs also need updating. |
| Slackware | [slackpkg documentation](https://slackpkg.org/documentation.html) covers refreshing package lists and upgrading packages from the selected Slackware mirror. |
| Windows desktop / Windows Server, standalone PHP | [Official PHP Windows downloads](https://www.php.net/downloads.php?os=windows) and [pre-built binary installation requirements](https://www.php.net/manual/en/install.windows.manual.php). Match architecture, TS/NTS build, web-server integration and extensions; Windows Update does not update a standalone PHP installation. |
| macOS, package-managed PHP | [Homebrew package updates](https://docs.brew.sh/FAQ#how-do-i-update-my-local-packages) or [MacPorts upgrade](https://guide.macports.org/#using.port.upgrade), according to how PHP was installed. |
| FreeBSD | [Packages and Ports handbook](https://docs.freebsd.org/en/books/handbook/ports/) includes upgrading installed packages with `pkg`; base-OS updates alone do not update PHP packages. |
| OpenBSD | [Package management: updating packages](https://www.openbsd.org/faq/faq15.html#PkgUpdate) covers `pkg_add -u`; base-system patches alone do not update PHP packages. |
| NetBSD / pkgsrc binary packages | [Updating packages with pkgin](https://www.netbsd.org/docs/pkgsrc/using.html#using.pkgin_update) covers package metadata and binary-package upgrades. |

### Bundled runtimes, containers and verification

For hosting panels, appliances, XAMPP/WampServer, LiteSpeed/LSAPI, FrankenPHP or
other embedded/custom PHP, follow the product or build maintainer's update process.
Updating the host's default PHP package may leave these runtimes unchanged. For
standalone source builds, use an applicable fixed [official PHP release](https://www.php.net/downloads.php)
or a verified backport and retain build evidence for the resulting artifacts.

For containers, follow [Docker's image rebuild guidance](https://docs.docker.com/build/building/best-practices/#rebuild-your-images-often),
update the PHP-containing base image or build inputs, and redeploy the resulting
image. Updating only the host or pulling an image does not replace running
containers. WSL distributions need their own Linux package updates separately
from Windows updates.

After updating, restart or replace every affected PHP worker/service/container
using its deployment procedure, verify application health, and re-run the audit
with current inventory and evidence. Refresh evidence from trusted vendor/build
records; do not relabel an unknown artifact as patched. Windows running-image
uncertainty and the other [audit limits](#limits-and-trust) still apply. Request
filtering or upload-progress configuration changes are partial mitigations, not
proof that both CVEs are fixed.

## Running it

```sh
# Initial discovery; normally UNKNOWN until coverage is explicitly confirmed.
sudo python3 php2shell-audit.py --json

# After preparing a host-specific inventory:
sudo python3 php2shell-audit.py --inventory inventory.json --json

# Audit one remote Linux host, transferring the script and supplied JSON in memory.
python3 php2shell-audit.py --ssh auditor@host --sudo --inventory inventory.json --json

# Optional vendor/custom-build evidence:
python3 php2shell-audit.py --ssh auditor@host --sudo --inventory inventory.json --evidence evidence.json --json

# HEAD, with GET fallback on 405/501; always UNKNOWN, never patch clearance.
python3 php2shell-audit.py --http https://example.com --json

# Run tests; HTTP tests use local loopback servers.
python3 -m unittest discover -q
```

Save JSON output for evidence. Exit codes:

| Exit | Meaning |
| --- | --- |
| `0` | Every observed runtime has verified patched evidence, expected inventory is accounted for, no inspection failures, and no replacement/restart flags. |
| `1` | At least one running artifact has evidence of an affected build/package. Other unknown results remain in the report. |
| `2` | Incomplete evidence, coverage, unsupported environment, remote failure, or a restart/re-audit requirement; do not clear the host. |

`--files` explicitly changes the assessment to **installed files only**. Its exit
`0` clears the listed artifacts, not running workers or an entire host. Both text
and JSON identify this scope. HTTP, probes, logs and process events always return
`UNKNOWN`/`2`, even when an advertised version is at a fixed upstream baseline.

`restart_needed` is separate from each runtime's patch status. A replaced file
alone does not prove vulnerability. A patched running image with a replacement
flag still requires investigation/restart and another audit before exit `0`.
An old image whose hash no longer matches installed-package metadata is UNKNOWN
unless a trusted build entry independently identifies that old image.

### Findings and saved reports

Runtime records and report-level coverage failures include a `diagnostics` list.
Each entry has a stable `code`, the original `detail`, a `next_step`, and relevant
update `guidance` links. The text report prints the same next steps. Existing
`status`, `file_status`, `restart_needed`, `issues` and exit-code meanings are
unchanged. Guidance is informational; no repair command is executed.

Common codes distinguish `ACCESS_DENIED`, `FILE_MISSING`, `FILE_CHANGED`,
`PROCESS_CHANGED`, `EVIDENCE_MISSING`, `EVIDENCE_MISMATCH`, `VENDOR_RULE_MISSING`,
`VERSION_UNSUPPORTED`, `LOADED_IMAGE_UNVERIFIED`, `RESTART_REQUIRED`, and
`AFFECTED`. Coverage codes distinguish an unconfirmed inventory, missing expected
runtimes, unexpected runtimes, incomplete discovery, and no observed runtime.
`TRANSPORT_FAILED` identifies remote setup/protocol errors; `OBSERVATION_ONLY`
identifies methods that cannot establish patch status. Other inspection errors
retain `INSPECTION_FAILED` and their original detail.

Each JSON report includes `metadata`: UTC report time, tool version and script
SHA-256, target platform/version/architecture, and SHA-256 fingerprints of parsed
inventory and evidence JSON. Fingerprints use sorted keys and compact JSON, so
formatting changes do not change them. Imported RPM advisory rows are included in
the evidence fingerprint. Raw input documents are not copied into metadata.
These hashes identify inputs; they do not authenticate their source.

Successful SSH/container audits retain metadata generated on the target.
`host_role` distinguishes `audit-target` from `controller`; failed transports and
HTTP/log/probe observations describe the controller, not an inspected backend.
An unavailable local script fingerprint is `null` and does not hide an affected
runtime. Diagnostic and metadata fields are additive within schema 1.

## Inventory and coverage

Copy `inventory.example.json` to `inventory.json`. Replace its example with the
runtime paths from your deployment, service or container inventory.
Set `coverage_confirmed` to `true` only after confirming that inventory covers the
stated scope. The unedited example will return `UNKNOWN`.

To start from discovered paths:

```sh
python3 php2shell-audit.py --draft-inventory > inventory.draft.json
python3 php2shell-audit.py --ssh auditor@host --draft-inventory > remote.draft.json
python3 php2shell-audit.py --container php-app --draft-inventory > container.draft.json
```

Draft export intentionally exits `2`. It prints inventory JSON directly, with
`coverage_confirmed: false`, deduplicated runtime paths, discovery errors and
target metadata. It assesses no patch status and writes no file itself.
Review the scope and paths, add inactive, renamed and hidden deployments, and
resolve discovery failures before confirming coverage. A draft is rejected as
audit input until reviewed and explicitly confirmed. Use one target per export;
draft mode cannot be combined with evidence, file assessment or observation modes.

Each entry has `label`, `kind`, and the absolute path seen for the running
executable or mapped PHP module. Supported kinds: `fpm`, `mod_php`, `cgi`, `lsphp`,
`frankenphp`, `php`, and `embedded`. For Apache use the PHP shared-library path,
not `/usr/sbin/apache2`. List every distinct runtime path. Pools sharing the same
runtime file can share an entry; every observed process is inspected.

Automatic discovery examines executable identity and mapped PHP libraries across
visible processes. It does not infer PHP versions from CLI binaries, process
names, or web headers. Inventory-specified paths also cover renamed/custom
executables and PHP libraries. Apache modules are inspected independently of FPM
and LiteSpeed. Caddy is reported as a possible embedded runtime; check whether
it contains PHP and provide build evidence if it does.

Missing expected runtimes, unexpected runtimes, unreadable processes, or absent
inventory prevent clearance. Inactive services and scaled-to-zero applications
cannot be cleared by examining running processes; retain them in the expected
inventory and assess their deployed artifacts separately. Custom statically
embedded PHP may not have a recognizable process name: list its executable.

The Linux host cannot safely translate container/chroot executable paths into
host paths. Detected PHP processes with another mount/root namespace cause an
UNKNOWN result; run the audit inside each deployment namespace with its own
inventory and retain those reports. This script does not merge separate container
reports into a host-wide clearance. PID namespaces can conceal entire workloads,
which is why a deployment inventory is required even when discovery succeeds.

## Windows, inactive deployments and containers

```powershell
# Windows file evidence, including the PHP engine DLL used by this installation.
python php2shell-audit.py --files --inventory inventory.json --evidence builds.json --json

# Discover PHP executables and loaded PHP DLLs on Windows.
python php2shell-audit.py --inventory inventory.json --evidence builds.json --json
```

Start with `inventory.windows.example.json` and confirm its scope and paths.
Windows drive paths are accepted and compared without case sensitivity; UNC paths,
drive-relative paths and alternate data streams are rejected. Windows needs enough
privileges to enumerate the relevant processes/modules; permission failures remain
in the report. Version resources are observations, not authenticated build provenance.

Windows process/module paths do **not** prove that the current disk file is the
image still loaded in memory. Process records therefore retain `status=UNKNOWN`
and expose the separate `file_status`. Use `--files` for an explicit installed-file
assessment. Include the engine DLL (for example `php8.dll` or `php8ts.dll`) as well
as executables and Apache modules; checking a launcher alone does not cover its DLLs.

```sh
# Windows over OpenSSH; specify the installed Python executable.
python3 php2shell-audit.py --ssh auditor@windows-host --remote-os windows \
  --remote-python 'C:\Python313\python.exe' --files \
  --inventory inventory.json --evidence builds.json --json

# Inactive deployments and custom files on any supported host use the same file mode.
python3 php2shell-audit.py --files --inventory inventory.json --evidence builds.json --json

# Inspect one existing Linux container via the current Docker/Podman context.
python3 php2shell-audit.py --container php-app --inventory inventory.json --evidence builds.json --json
python3 php2shell-audit.py --engine podman --container php-app --remote-python /usr/local/bin/python3 --json
```

Container transport requires a Unix controller and Python already present in the
container. It sends this script through stdin and runs it in that container's
namespace; it does not install packages, pull images, execute PHP, or change services.
Use a separate invocation and inventory for each remote host/container. The script
does not enumerate Kubernetes/Swarm workloads or inspect image contents from tags.

## macOS

```sh
# Discover running PHP executables and mapped PHP libraries on this Mac.
python3 php2shell-audit.py --inventory inventory.json --evidence evidence.json --json

# Audit a Mac over SSH; select its installed Python 3.9+ interpreter.
python3 php2shell-audit.py --ssh auditor@mac-host --remote-os macos \
  --remote-python /opt/homebrew/bin/python3 \
  --inventory inventory.json --evidence evidence.json --json

# Native fixture checks; requires Apple Command Line Tools and runs no PHP.
python3 verify_macos.py
```

Use the same inventory format as Linux. Homebrew `opt`/`bin` symlinks resolve on
the audited Mac, so inventory can use a stable path such as
`/opt/homebrew/opt/php/sbin/php-fpm`. List Apache's PHP module separately as
`mod_php`; discovery recognizes `libphp*.so`, `libphp*.dylib` and `mod_php*`
libraries. Explicit paths also cover renamed or embedded runtimes. List each
runtime once; aliases of the same path and kind are rejected.

The collector uses macOS libproc to read process start times, executable paths
and mapped-file device/inode identities. A file is hashed only when its identity
matches the mapping; process identity, mappings and file stability are checked
again afterward. A deleted or replaced mapping that cannot be read remains
`UNKNOWN`, with a restart flag when detected. This checks the mapped backing
file, not private changes to memory pages.

The current user must be allowed to inspect the relevant processes. Permissions,
System Integrity Protection and other macOS restrictions can prevent inspection,
even with elevated privileges. Such errors remain coverage issues and prevent
host clearance. Use `--files` to assess only the explicitly listed installed files.

Homebrew ownership is read from the resolved Cellar path and its installation
receipt. MacPorts ownership is read from the registry under the installation
prefix, requiring exactly one active owner. Neither source supplies the file
checksum needed for a patched verdict. Provide a trusted archive as described
below, or use existing SHA-256 build evidence for custom or relocated files.

## Package and build evidence

On Linux, running executables are read through `/proc/PID/exe`. PHP shared libraries are
read through `map_files`, or through a pathname only if device/inode identity
matches the process mapping. macOS uses the native mapping checks described above.
PID identity and file stability are checked. The script never executes those files,
loads their configuration, or imports extensions.

For supported Linux distribution packages, the running-file digest must match the installed
package database. The full package revision is then compared with a vendor fix
using the distribution's native version comparison. A package update on disk
does not automatically identify the old process still in memory.

Built-in rules cover the documented Ubuntu PHP runtime packages for 14.04,
16.04, 18.04, 20.04, 22.04, 24.04, 26.04, and 26.10, based on the two Canonical
advisories checked on 2026-10-22. Availability of older-release updates depends on
the relevant Ubuntu support entitlement. Rules do not apply to other distributions
or unrelated package names. A PPA/private repository using the same names and
versions cannot be authenticated from its version string. Verify the package's
origin before relying on the result.

Debian/other dpkg distributions and RPM distributions need operator-supplied,
vendor-verified rules outside the built-in cases. Debian 12 `php8.2` is fixed at
`8.2.35-1~deb12u1`; Debian 13 `php8.4` at `8.4.27-1~deb13u1`. RHEL 8.10 PHP 7.4
uses `0:7.4.33-8.module+el8.10.0+25117+30337cca` (RHSA-2026:87080); RHEL 9.8 PHP
8.0 uses `0:8.0.30-8.el9_8.1` (RHSA-2026:87151). The RHEL rules require the
Red Hat vendor, matching release/branch, and the appropriate module identity.
Other streams remain UNKNOWN without evidence. No advisory data is downloaded
automatically. Use this JSON structure, replacing every placeholder:

```json
{
  "schema": 1,
  "vendor_fixes": [
    {
      "os_id": "REPLACE_OS_ID",
      "os_version": "REPLACE_VERSION_ID",
      "manager": "rpm",
      "package": "REPLACE_EXACT_BINARY_PACKAGE",
      "fixed_version": "REPLACE_VENDOR_FIXED_VERSION",
      "cves": ["CVE-2026-109618", "CVE-2026-109619"],
      "sources": ["https://REPLACE-WITH-VENDOR-ADVISORY"]
    }
  ],
  "builds": []
}
```

`os_id` and `os_version` must exactly match `/etc/os-release` (or
`/usr/lib/os-release`). Without `VERSION_ID`, the version is `VERSION_CODENAME`
or `rolling`. `manager` is `rpm`, `dpkg`, `apk`, or `pacman`.
Use RPM epoch:version-release, including epoch `0:` when appropriate;
use the full dpkg revision for Debian-family packages. Each rule must establish
that its baseline fixes **both** CVEs. Operator-supplied rules take precedence for
that exact OS/release/manager/package tuple and are trusted configuration.

For a custom PHP/FrankenPHP/LSAPI build, add a `builds` entry with `sha256`,
`php_version`, and `source`. Obtain the digest and the embedded PHP version from
trusted build or release records. Do not execute an untrusted file or use its
banner as evidence. `source` should identify the build record or signed manifest.
The SHA-256 must identify the actual executable or mapped module being audited.
For a verified custom backport, the build entry may additionally specify
`"fixed_cves": ["CVE-2026-109618", "CVE-2026-109619"]`. This asserts that the file
with that hash contains both fixes. The script trusts this supplied record; it
cannot infer a backport from the version number.

### Alpine and Arch rules

Rules verified on 2026-10-23 use the publishers' own records for both CVEs:

| Vendor scope | Fixed package revisions | Source |
| --- | --- | --- |
| Alpine 3.23/3.24 community: `php83`, `php84`, `php85` and their `-fpm`, `-cgi`, `-apache2` subpackages | `8.3.36-r0`, `8.4.27-r0`, `8.5.12-r0`, respectively | Alpine [3.23 secdb](https://secdb.alpinelinux.org/v3.23/community.json) and [3.24 secdb](https://secdb.alpinelinux.org/v3.24/community.json) |
| Arch rolling: `php` | `8.5.12-1` | [AVG-2909](https://security.archlinux.org/AVG-2909) |
| Arch rolling: `php-legacy` | `8.3.36-1` | [AVG-2910](https://security.archlinux.org/AVG-2910) |

Alpine's release branch covers its point releases; `edge`, other branches and
other OS IDs do not match. Arch rules require OS ID `arch`, release `rolling`
and the exact listed binary package name. Separate Arch packages such as
`php-fpm` are not inferred from the `php` advisory. Manjaro and other derivatives
need their own evidence. Package checksums and native version comparison still
apply before any patched verdict.

To review a rule, check the exact release/source package in Alpine's `secfixes`,
or the exact package, `status`, `fixed` and `issues` in Arch's
[AVG-2909 JSON](https://security.archlinux.org/AVG-2909.json) and
[AVG-2910 JSON](https://security.archlinux.org/AVG-2910.json). Confirm that the fixed
revision covers both CVE IDs. Update the rule, its boundary/scope tests and the
verification date together. Built-in rule dates appear as `rule_verified_at` in
artifact reports; a date records review, not an automatic freshness guarantee.

### Homebrew and MacPorts archives

Add `package_archives` to the same evidence JSON. This Homebrew example is a
template; replace the package/version, path, checksum and source with trusted
records for the installed build:

```json
{
  "schema": 1,
  "package_archives": [
    {
      "manager": "homebrew",
      "package": "homebrew/core/php",
      "version": "8.3.36_1",
      "path": "/absolute/path/on/audited/mac/php.bottle.tar.gz",
      "sha256": "REPLACE_WITH_TRUSTED_ARCHIVE_SHA256",
      "php_version": "8.3.36",
      "source": "REPLACE_WITH_TRUSTED_RELEASE_AND_CHECKSUM_RECORD"
    }
  ]
}
```

`manager`, `package` and `version` must match the reported installed package
exactly. Homebrew package names include the tap, such as `homebrew/core/php@8.3`;
versions use the Cellar directory name, including any `_revision`. For MacPorts,
use `manager: "macports"`, the port name (for example `php83`), and
`epoch:version_revision` followed by installed variants, such as
`0:8.3.36_1+openssl`. These identifiers describe package ownership, not a built-in
list of fixed macOS packages.

Obtain both the archive SHA-256 and embedded `php_version` from trusted release or
build records. The script trusts that association; a checksum calculated only
from an untrusted local archive does not authenticate it. `source` records where
that evidence came from. As with `builds`, a verified backport may supply
`fixed_cves` containing both CVEs; otherwise the existing upstream version rules
apply. Package version strings and PHP banners are not used as proof.

The archive must already exist on the audited host; SSH transfers the evidence
JSON, not the archive. The script verifies its SHA-256, finds the runtime's exact
package member, and compares that member's SHA-256 with the audited file. It reads
tar archives, optionally compressed with gzip, bzip2 or xz, without extracting
files. Limits are 512 MiB compressed/uncompressed, 100,000 members and 1 MiB per
extended header. Missing or duplicate members, non-regular runtime members,
unsafe paths, changed archives and mismatched file bytes remain `UNKNOWN`.

Homebrew relocation or code signing can change installed bytes relative to a
bottle. Such files require a separate `builds` record for the installed artifact;
the tool does not reverse relocation or assume a mismatch is safe. No archive is
downloaded and no package manager, installation, update or restart is performed.

Repeated checks of the same archive/member within one audit reuse its verified
digest only while device, inode, size, modification time and change time still
match. Open handles recheck the current pathname. Changed or replaced archives
are reverified; cache entries never survive an audit invocation. Every process
still receives its own runtime-identity checks and file hashing. A five-worker
fixture reduced archive verification from five full reads to one, about 0.24 s
to 0.05 s locally; this is not a general performance guarantee.

### RPM repository advisories

```sh
python3 php2shell-audit.py --inventory inventory.json \
  --updateinfo verified-updateinfo.xml.gz --updateinfo-os rocky:9.6 --json
```

Supply `updateinfo.xml` or gzip metadata from the target's trusted package
repository and bind it to the **exact** target OS ID/version. Obtain and verify
the repository metadata through your normal trusted repository process first;
this tool does not authenticate the XML or its source.
It matches binary package name, architecture, PHP major/minor branch and module
stream/context, and requires fixes covering both CVEs. Separate advisories for
the two CVEs are combined using native RPM version ordering. Metadata for another
vendor, release, architecture or stream cannot establish the target's patch status.

## Additional checking methods

```sh
python3 php2shell-audit.py --targets-file websites.txt --json
python3 php2shell-audit.py --http-details https://example.com/index.php --json
python3 php2shell-audit.py --phpinfo https://example.com/operator-selected-info.php --json
python3 php2shell-audit.py --multipart-check 'https://example.com/testblock.php?probe=1' --json
python3 php2shell-audit.py --probe-php /absolute/trusted/php --json
python3 php2shell-audit.py --log php-error.log --process-events events.jsonl --json
```

- `--targets-file`: explicit URLs/hostnames, one per line; blank lines and `#`
  comments are ignored. Checks run sequentially, with no subdomain/origin expansion.
- `--http-details`/`--phpinfo`: one bounded GET of the exact supplied URL. Collects
  explicit PHP version clues, PHP session-cookie presence (not its value), simple
  CMS clues, and selected phpinfo settings with local/master values. It retains no
  raw response body or environment variables. It does not infer PHP versions from
  CMS versions, guess a SAPI from nginx, or treat a banner as build evidence.
- `--multipart-check`: a GET control followed by **one small multipart POST** with
  an ordinary field. Use a dedicated harmless test endpoint, such as Syhunt's
  `testblock.php?probe=1`. POSTs to application routes can cause application writes.
  `MULTIPART_REACHED_PHP` or `PHP_EXECUTED` identifies the test response. A 403 is
  called blocked for this request only when the successful control had a marker.
  Filtering is partial mitigation; it does not prove patching or rule completeness.
- `--probe-php`: explicitly executes a trusted local binary with `-n -v` (or
  FrankenPHP `php-cli -n -v`). `-n` skips PHP ini files; it is **not a sandbox**.
  The digest must remain stable, and the resulting version is still only a hint.
- `--log`: counts memory-exhaustion, heap-corruption and worker-crash messages,
  retaining line numbers rather than potentially sensitive log text.
- `--process-events`: reads exported process-watcher schema-1 JSONL, deduplicates
  events, notes observation/sequence gaps, and lists PHP/Apache descendant execs.
  Shell/interpreter/network-tool children are flagged for review. Arguments are
  omitted; legitimate applications may launch such children. No collector is
  installed and no process is killed. A quiet log never proves no compromise.

Responses are capped at 256 KiB, logs at 64 MiB/one million lines (1 MiB per
line), and displayed log observations at 100; counts continue beyond that display
limit. Truncation/parse failures retain UNKNOWN.

The upstream baselines are 8.2.35, 8.3.36, 8.4.27, and 8.5.12. Only exact stable
`major.minor.patch` versions in these branches are classified from build evidence.
Prereleases, suffixed versions, older unsupported upstream branches, future
branches, and unknown/custom version formats remain UNKNOWN. Distribution
backports use vendor rules instead of these upstream-number comparisons.

## Audit behavior

| Area | Behavior |
| --- | --- |
| Verdicts | Any unresolved runtime or coverage issue prevents exit `0`. |
| Runtime identity | Running-file identity and matching evidence are required. Apache modules are inspected independently of other servers. |
| Discovery | Visible processes and modules are inspected; CGI, FrankenPHP, LSAPI, and custom inventory paths are recognized. Inspection failures and coverage gaps remain UNKNOWN. |
| Restart status | Every matching process is inspected; replacement markers are retained, with patch and restart states reported separately. |
| HTTP | HEAD with GET fallback on 405/501; explicit detail/multipart modes. No redirects or ambient proxies. Observations cannot establish patch status. |
| Backports | Full package revisions and vendor rules are used; package digests tie installed metadata to the running artifact. |
| Release versions | Stable-release parsing and explicit supported branches prevent assumptions about prereleases or future versions. |
| SSH | Noninteractive sudo, a complete result with a per-run token and matching exit status, timeouts, and host validation are required. |
| Execution | Default checks only read PHP files. Trusted system utilities perform queries/transport; only explicit `--probe-php` executes a selected PHP binary. |

## Limits and trust

The regression suite covers verdicts, discovery, runtime identity, package evidence,
version handling, HTTP checks, and remote failures. `verify_native.py` checks
package digests, version comparison and procfs identity/replacement in disposable
Linux containers, using a copy of `sleep` as a test process. `verify_windows.py`
checks file evidence, version resources and process/DLL discovery using the current
Python interpreter and DLL. Neither test script runs PHP. Results and untested
platforms are listed under [Tested environments](#tested-environments).
`verify_macos.py` compiles a temporary executable and PHP-named shared library,
checks native mapping/replacement behavior, and exercises synthetic package
archives and receipts. It runs no PHP or package manager and cleans up its fixtures.

### Real PHP tests

```sh
# Requires Docker. PHP and Python test dependencies stay inside disposable images.
python3 verify_php_containers.py
# Optional single case:
python3 verify_php_containers.py --case 8.3.36-fpm
```

The runner pins Docker Official Image digests for affected/fixed PHP-FPM and
Apache builds. It sends only the audit script and fixture verifier into the build
context, mounts no host directories, publishes no ports, and disables networking
while fixtures run. `SYS_PTRACE` is confined to the test container for procfs
inspection. Tests use ordinary sleeping CLI workers and idle servers, with no
exploit payloads. A fixed binary replaces a running copy to check that the old
worker cannot inherit the installed file's verdict.

Test containers and derived images are removed afterward; downloaded base images
and Docker build cache may remain. These commands never install PHP on the host.
`verify_php.py` refuses direct workstation/self-hosted CI use. Windows and macOS
PHP installation steps exist only in the GitHub-hosted CI jobs and reject
self-hosted runners. The Windows ZIP is checksum-pinned; the macOS job uses a
Homebrew installation on its disposable runner. Windows running-image uncertainty
remains part of the expected result.

### Trust boundaries

This is a point-in-time patch audit, not an exploitation or compromise test.
Package databases, system tools, kernel/procfs, and supplied inventory/evidence
must be trustworthy. Hashes detect disagreement with that baseline; they do not
establish the authenticity of a compromised package database or build manifest.
In-memory tampering and arbitrary live patching are outside this audit.

Insufficient permissions and inaccessible mappings result in UNKNOWN; run with
appropriate read access and recheck. Large process fleets may exceed the 120-second
SSH audit timeout and require separate runs within smaller deployment namespaces.
No service restart or remediation happens automatically.

HTTP uses certificate validation and does not follow redirects. HTTP responses,
including proxy/WAF responses, cannot establish the backend's patch status.
URLs and target lists are trusted operator input; requests may reach loopback,
private, and link-local destinations.
