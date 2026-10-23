# PHP2Shell patch audit

Read-only patch auditing for PHP2Shell (CVE-2026-109618 and CVE-2026-109619), with
local and SSH inspection of Linux PHP runtimes and informational HTTP header
checks. The audit verifies running-file identity against package or build evidence
without executing PHP binaries or sending exploit requests.

It does not patch, restart services, change configuration, or determine whether
a host has already been compromised.

Requirements: Python **3.9+**. Local/SSH runtime inspection supports **Linux** with
procfs. The controller can run on macOS. There are no third-party Python
dependencies. SSH targets need `/usr/bin/python3`; `--sudo`
also needs noninteractive `/usr/bin/sudo`. Host keys must already be trusted.

Windows-hosted PHP is also within the scope of the PHP2Shell security advisories,
but Windows runtime inspection is not implemented in this tool. HTTP checks can
observe Windows-hosted websites; they cannot establish that those hosts are patched.

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

# Informational HEAD request only; always UNKNOWN, never patch clearance.
python3 php2shell-audit.py --http https://example.com --json

# Offline regression tests: no network connections or PHP execution.
python3 test_php2shell_audit.py
```

Save JSON output for evidence. Exit codes:

| Exit | Meaning |
| --- | --- |
| `0` | Every observed runtime has verified patched evidence, expected inventory is accounted for, no inspection failures, and no replacement/restart flags. |
| `1` | At least one running artifact has evidence of an affected build/package. Other unknown results remain in the report. |
| `2` | Incomplete evidence, coverage, unsupported environment, remote failure, or a restart/re-audit requirement; do not clear the host. |

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
vendor-verified rules. They remain UNKNOWN without them. No advisory data is
downloaded automatically. Use this JSON structure, replacing every placeholder:

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

`os_id` and `os_version` must exactly match `/etc/os-release`. `manager` is `rpm`
or `dpkg`. Use RPM epoch:version-release, including epoch `0:` when appropriate;
use the full dpkg revision for Debian-family packages. Each rule must establish
that its baseline fixes **both** CVEs. Operator-supplied rules take precedence for
that exact OS/release/manager/package tuple and are trusted configuration.

For a custom PHP/FrankenPHP/LSAPI build, add a `builds` entry with `sha256`,
`php_version`, and `source`. Obtain the digest and the embedded PHP version from
trusted build/release provenance, not by executing an untrusted file or copying
its banner. `source` should identify the build record or signed manifest.
The SHA-256 must identify the actual executable or mapped module being audited.

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
| HTTP | HEAD-only observations, without redirects or ambient proxies. Banners cannot establish patch status. |
| Backports | Full package revisions and vendor rules are used; package digests tie installed metadata to the running artifact. |
| Release versions | Stable-release parsing and explicit supported branches prevent assumptions about prereleases or future versions. |
| SSH | Noninteractive sudo, a complete result with a per-run token and matching exit status, timeouts, and host validation are required. |
| Execution | PHP executables and modules are only read; subprocesses are restricted to fixed system package utilities and SSH. |

## Limits and trust

The included offline regression suite covers verdicts, discovery, runtime identity,
package evidence, version handling, HTTP observations, and remote failure handling.
Additional isolated Linux checks exercise real procfs discovery, dpkg ownership,
checksums and version comparison, replaced executable detection, and mapped-module
identity using synthetic fixtures. The generated remote program is exercised over
a local subprocess transport. Production deployments, real SSH/sudo policy, and a live
RPM distribution have not been tested. RPM handling has mocked regression coverage.

This is a point-in-time patch audit, not an exploitation or compromise test.
Package databases, system tools, kernel/procfs, and supplied inventory/evidence
must be trustworthy. Hashes detect disagreement with that baseline; they do not
establish the authenticity of a compromised package database or build manifest.
In-memory tampering and arbitrary live patching are outside this audit.

Insufficient permissions and inaccessible mappings result in UNKNOWN; run with
appropriate read access and recheck. Large process fleets may exceed the 120-second
SSH audit timeout and require separate runs within smaller deployment namespaces.
No service restart or remediation happens automatically.

HTTP uses certificate validation, does not follow redirects, and does not retry
HEAD as GET. A proxy/WAF response, 405 response, or missing header remains only
an observation. It cannot certify any backend.

Sources:

- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://ubuntu.com/security/CVE-2026-109618
- https://ubuntu.com/security/CVE-2026-109619
