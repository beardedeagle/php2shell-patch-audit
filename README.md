# PHP2Shell patch audit

Patch auditing and supplementary observations for PHP2Shell (CVE-2026-109618 and
CVE-2026-109619). Checks include Linux running artifacts, Windows process/module
discovery, installed files on any Python-supported platform, SSH and container
transport, HTTP/phpinfo observations, multipart-filter checks, and log/event review.
Default inspection reads files without executing PHP. `--probe-php` explicitly
executes a selected trusted binary; `--multipart-check` explicitly sends a small POST.

It does not patch, restart services, change configuration, or determine whether
a host has already been compromised.

Requirements: Python **3.9+**, with no third-party Python dependencies. Controllers
can run on Linux, macOS, or Windows. Windows discovery also uses the system's
Windows PowerShell. Unix SSH/container targets default to `/usr/bin/python3`;
`--remote-python` selects another absolute path. `--sudo` needs noninteractive
`/usr/bin/sudo`. SSH host keys must already be trusted.

| Platform/family | Evidence available |
| --- | --- |
| Debian, Ubuntu and dpkg derivatives | Linux process identity, package ownership/digests, native revision comparison. Built-in baselines for Debian 12/13 and the Ubuntu releases below. |
| RHEL, Rocky, AlmaLinux, CentOS, Fedora, Oracle, Amazon Linux; SUSE/openSUSE | Linux process identity, RPM ownership/digests, native revision comparison. Built-in rules for the verified RHEL streams below; other streams/vendors use their own rules or updateinfo. |
| Alpine | Linux process identity, APK installed-file SHA-1 checksums, native `apk version` comparison. Vendor rules required. |
| Arch/Manjaro | Linux process identity, pacman ownership/mtree SHA-256, native `vercmp`. Vendor rules required. |
| Other Linux, Gentoo, Nix, Slackware, custom/embedded builds | Linux process identity plus SHA-256-bound build evidence. An unsupported package database is explicit, not silently treated as RPM. |
| Windows | Native process/module discovery, file hashes and PE version-resource hints; installed-file verdicts using build evidence. See the loaded-image limitation below. |
| macOS/BSD and other Python platforms | Explicit installed-file checks using build evidence; HTTP and log methods. No native process collector. |

Platform support does not imply that every release has a built-in advisory.
Missing vendor/build evidence remains UNKNOWN. Derivatives do not inherit their
parent distribution's patch thresholds automatically.

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

# Additional method regressions include loopback HTTP servers, never external targets.
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

## Inventory and coverage

Copy `inventory.example.json` to `inventory.json`. Replace its example with the
runtime paths actually expected from your deployment/service/container inventory.
Set `coverage_confirmed` to `true` only after confirming that inventory covers the
stated scope. The example intentionally cannot clear anything without editing.

Each entry has `label`, `kind`, and the absolute path seen for the running
executable or mapped PHP module. Supported kinds: `fpm`, `mod_php`, `cgi`, `lsphp`,
`frankenphp`, `php`, and `embedded`. For Apache use the PHP shared-library path,
not `/usr/sbin/apache2`. List every distinct runtime path. Pools sharing the same
runtime file can share an entry; every observed process is inspected.

Automatic discovery examines executable identity and mapped PHP libraries across
visible processes. It does not infer PHP versions from CLI binaries, process
names, or web headers. Inventory-specified paths also cover renamed/custom
executables and PHP libraries. Apache modules are inspected independently of FPM
and LiteSpeed. Bare Caddy is treated conservatively as a possible embedded runtime
and needs evidence or investigation; its name cannot establish its PHP contents.

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

# Inactive Linux deployments or custom files on macOS/BSD use the same file mode.
python3 php2shell-audit.py --files --inventory inventory.json --evidence builds.json --json

# Inspect one existing Linux container via the current Docker/Podman context.
python3 php2shell-audit.py --container php-app --inventory inventory.json --evidence builds.json --json
python3 php2shell-audit.py --engine podman --container php-app --remote-python /usr/local/bin/python3 --json
```

Container transport requires a Unix controller and Python already present in the
container. It sends this script through stdin and runs it in that container's
namespace; it does not install packages, pull images, execute PHP, or change services.
Use a separate invocation and inventory for each remote host/container. The audit
does not claim Kubernetes/Swarm fleet coverage or infer deployed contents from tags.

## Package and build evidence

Running executables are read through `/proc/PID/exe`. PHP shared libraries are
read through `map_files`, or through a pathname only if device/inode identity
matches the process mapping. PID identity and file stability are checked. The
script never executes those files, loads their configuration, or imports extensions.

For distribution packages, the running-file digest must match the installed
package database. The full package revision is then compared with a vendor fix
using the distribution's native version comparison. A package update on disk
does not automatically identify the old process still in memory.

Built-in rules cover the documented Ubuntu PHP runtime packages for 14.04,
16.04, 18.04, 20.04, 22.04, 24.04, 26.04, and 26.10, based on the two Canonical
advisories checked on 2026-10-22. Availability of older-release updates depends on
the relevant Ubuntu support entitlement. Rules do not apply to other distributions
or unrelated package names. A PPA/private repository using the same names and
versions is not independently authenticated by this audit: package provenance is
an administrative prerequisite, not something a version string can prove.

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
trusted build/release provenance, not by executing an untrusted file or copying
its banner. `source` should identify the build record or signed manifest.
The SHA-256 must identify the actual executable or mapped module being audited.
For a verified custom backport, the build entry may additionally specify
`"fixed_cves": ["CVE-2026-109618", "CVE-2026-109619"]`. This is an explicit trusted
build-provenance assertion bound to that hash, not an inference from an old version.

### RPM repository advisories

```sh
python3 php2shell-audit.py --inventory inventory.json \
  --updateinfo verified-updateinfo.xml.gz --updateinfo-os rocky:9.6 --json
```

Supply `updateinfo.xml` or gzip metadata from the target's trusted package
repository and bind it to the **exact** target OS ID/version. Obtain and verify
the repository metadata through your normal trusted repository process first;
this tool does not authenticate arbitrary XML or its claimed provenance.
It matches binary package name, architecture, PHP major/minor branch and module
stream/context, and requires fixes covering both CVEs. Separate advisories for
the two CVEs are combined using native RPM version ordering. Metadata for another
vendor, release, architecture or stream cannot silently clear the target.

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
limit. Truncation/parse failures retain UNKNOWN. See [source-methods.md](source-methods.md)
for the review of all eleven supplied reference repositories and what was adopted.

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

The included offline regression suite covers verdicts, discovery, runtime identity,
package evidence, version handling, HTTP observations, and remote failure handling.
`verify_native.py` exercises native package digests/version comparison and procfs
identity/replacement using a synthetic system-sleep fixture in disposable Linux
containers. `verify_windows.py` checks native file evidence, version resources,
and process/DLL discovery using the current Python interpreter as a synthetic
fixture. These checks and key-authenticated Windows SSH transport passed on a
live Windows host; loaded-image uncertainty and protected-process coverage errors
remain explicit. Linux SSH/sudo policy and production PHP deployments remain
untested. See the source-methods document for the current validation record.

This is a point-in-time patch audit, not an exploitation or compromise test.
Package databases, system tools, kernel/procfs, and supplied inventory/evidence
must be trustworthy. Hashes detect disagreement with that baseline; they do not
establish the authenticity of a compromised package database or build manifest.
In-memory tampering and arbitrary live patching are outside this audit.

Insufficient permissions and inaccessible mappings result in UNKNOWN; run with
appropriate read access and recheck. Large process fleets may exceed the 120-second
SSH audit timeout and require separate runs within smaller deployment namespaces.
No service restart or remediation happens automatically.

HTTP uses certificate validation and does not follow redirects. A proxy/WAF
response, rejected request, or missing header remains only
an observation. It cannot certify any backend.

Sources:

- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://ubuntu.com/security/CVE-2026-109618
- https://ubuntu.com/security/CVE-2026-109619
- https://security-tracker.debian.org/tracker/CVE-2026-109618
- https://security-tracker.debian.org/tracker/CVE-2026-109619
- https://access.redhat.com/errata/RHSA-2026:87080
- https://access.redhat.com/errata/RHSA-2026:87151
