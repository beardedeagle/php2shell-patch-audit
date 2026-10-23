# Reference methods and validation

Reviewed on 2026-10-22. The eleven unique repositories supplied for this work are
pinned below; duplicate links to NCSC-NL and Syhunt refer to the same reviews.
Their methods informed this project's implementation. None is a runtime dependency,
and none of their scanners, mitigation scripts, or exploit programs was executed.

The original portability restriction had two causes: process inspection depended
on Linux `/proc`, and automatic vendor fix thresholds covered Ubuntu only. RPM
queries existed, but did not supply other vendors' release-specific fix evidence.
Those are separate concerns: discovering an artifact does not establish its patch
status, and a parent distribution's advisory does not authenticate a derivative.

## Source comparison

| Source at reviewed commit | Methods adopted or retained | Methods outside this audit |
| --- | --- | --- |
| [MakFly/php2shell-check](https://github.com/MakFly/php2shell-check/tree/f053cdd9688e9c690e507eb3fc8bf69a28dec3c2) | Broader package/binary discovery, explicit container execution, replacement/restart observations. Existing per-process Linux file identity remains required. | Swarm convergence, package remediation, image rebuilds/pulls, and treating changelog keywords as fix proof. |
| [Masriyan/php2shell](https://github.com/Masriyan/php2shell/tree/13091fae0d53a5b19ce59574c33abc365d6de75c) | Bounded HTTP response inspection and simple CMS/PHP presence hints. | KEV/EPSS services, legacy PHP egg probes, and deriving a PHP version from a CMS version. |
| [JoasASantos/php2shell-scanner](https://github.com/JoasASantos/php2shell-scanner/tree/5394f449ec574f2519deeaefe7c50ee0890367a7) | Selected phpinfo settings with local/master values, explicit version and PHP-presence observations from the chosen endpoint. | Automatic origin/endpoint reconnaissance, guessed SAPI from a proxy banner, and memory-exhaustion probes. |
| [0xrsydn/php2shell-scan](https://github.com/0xrsydn/php2shell-scan/tree/2e23e082dd63e559c70588fec5ed9fd5fd8aaacb) | Explicit target lists and a small opt-in multipart observation with a control request. | Large multipart corpora, burst/concurrent probes, and conclusions of vulnerability from response differences alone. |
| [openai/php2shell-checker](https://github.com/openai/php2shell-checker/tree/ffcd3fc82e5b404f2a04a95b2805ca7639d530fa) | HEAD-to-GET fallback on 405/501, version hints, serving-package vendor revisions and worker restart evidence. Debian/RHEL thresholds were checked against official advisories. | Header-only patch clearance or assuming that an updated disk package identifies every running worker. |
| [NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell/tree/ecad8f7dbcc8197b825ae3ca3d790fa4069235d3) | Explicit inventories accommodate hosting panels, custom paths, downstream software and embedded runtimes; build evidence can identify non-distribution artifacts. | Treating its software/SPDX inventory as proof of local deployment, or automatically applying hosting-panel mitigations. |
| [syhunt/php2shell-protection](https://github.com/syhunt/php2shell-protection/tree/f1857a5a2d30543b112450e0d7e35458710f2e64) | Recognize `MULTIPART_REACHED_PHP` / `PHP_EXECUTED` test markers, compare an ordinary multipart request with a GET control, and inspect selected session settings. | Configuration writes, assuming session hardening patches PHP, or interpreting one blocked request as universal protection. |
| [Neo23x0/process-watcher](https://github.com/Neo23x0/process-watcher/tree/472bccbd301b7fa25f5773a0a7cfbc024fc70325) | Offline consumption of schema-1 JSONL: event deduplication, sequence/collection gaps and PHP/Apache descendant executions. Arguments are omitted. | Installing an eBPF collector, maintaining a daemon, applying kill policies, or calling a suspicious child process proof of compromise. |
| [devploit/php2shell](https://github.com/devploit/php2shell/tree/a3aa44168803cb16e6af055ec21c1009c41816c1) | Explicit PHP body fingerprints and review signals for memory exhaustion, heap corruption and worker crashes. | OOM/leak/RCE stages, build/architecture calibration, worker pinning and exploit profiles. |
| [godylockz/cve-2026-109618-php2shell](https://github.com/godylockz/cve-2026-109618-php2shell/tree/a4f91107f8425a835147e27da06954023066300a) | GET-based explicit PHP clues and preservation of uncertainty when the patch level is missing. | The Linux mod_php RCE chain and lab profiles. Its exploit's platform restrictions do not define the audit's platform support. |
| [murrez/php2shell](https://github.com/murrez/php2shell/tree/e62535936b5fb1d013f8f52832df8c740c88e672) | Explicit `PHP/x.y[.z]` header/body markers; branch-only and suffixed versions stay uncertain. | Active primitive tests, stalled requests, memory manipulation and RCE. |

These general methods were implemented within this project's existing evidence
model; reference code was not incorporated. At review time, JoasASantos and
godylockz had no license file; Masriyan's README claimed proprietary licensing
while its LICENSE was MIT. NCSC-NL used EUPL-1.2, process-watcher GPL-3.0, and
OpenAI Apache-2.0. The other listed projects had MIT licenses, with upstream
licensing boundaries noted in devploit. Recheck licensing before any future code
reuse; this table is not a license grant.

## Platform and evidence changes

- Linux keeps process identity, mapping identity, stable file hashing, namespace
  checks, and explicit deployment coverage. dpkg, RPM, APK and pacman each use
  their own file metadata and native package-version ordering.
- Built-in vendor rules cover the documented Ubuntu releases, Debian 12/13, and
  the selected RHEL streams in the README. Other vendors/releases can use explicit
  rules. RPM `updateinfo` import is bounded and scoped to the declared OS/release,
  architecture, package, PHP branch and module stream/context, covering both CVEs.
- Windows uses native PowerShell process/module discovery, PE version-resource
  observations and stable file hashes. Explicit inventories accept drive paths
  with case-insensitive matching. Windows SSH uses an encoded PowerShell wrapper.
- `--files` supplies an explicitly limited installed-artifact assessment on
  Windows, inactive Linux deployments, macOS/BSD and other Python platforms.
  SHA-256-bound build evidence also supports custom builds/backports and package
  systems without a native adapter.
- Docker/Podman transport enters an existing container's namespace and transmits
  the audit to its installed Python interpreter. It reuses the complete-result,
  per-run-token and exit-status checks of SSH transport.

Official baseline sources:

- [Debian CVE-2026-109618](https://security-tracker.debian.org/tracker/CVE-2026-109618)
  and [CVE-2026-109619](https://security-tracker.debian.org/tracker/CVE-2026-109619):
  Debian 12 `php8.2` at `8.2.35-1~deb12u1`, Debian 13 `php8.4` at `8.4.27-1~deb13u1`.
- [RHSA-2026:87080](https://access.redhat.com/errata/RHSA-2026:87080): RHEL 8.10
  PHP 7.4 at `0:7.4.33-8.module+el8.10.0+25117+30337cca`.
- [RHSA-2026:87151](https://access.redhat.com/errata/RHSA-2026:87151): RHEL 9.8
  PHP 8.0 at `0:8.0.30-8.el9_8.1`.
- [Ubuntu CVE-2026-109618](https://ubuntu.com/security/CVE-2026-109618) and
  [CVE-2026-109619](https://ubuntu.com/security/CVE-2026-109619) for the retained
  Ubuntu table. No derivative inherits these thresholds automatically.

## Validation record

The ordinary regression suite uses synthetic evidence and loopback HTTP fixtures:

```sh
python3 -m unittest discover -q
```

It covers 75 tests, including package adapters, advisory scope, separate fixes for
the two CVEs, unsupported RPM module metadata, malformed compressed input,
Windows paths, file-versus-process verdicts, HTTP/multipart controls, log/event
limits, and serialized transport results. No external HTTP target was probed.

Native checks during this change:

| Environment | Observed proof | Boundary |
| --- | --- | --- |
| Debian 13 container | Real dpkg file checksum and native revision comparison; procfs executable identity and replacement detection. | Synthetic copied system-sleep process, not a PHP service. |
| Alpine 3.24.2 container | Real APK file checksum and native revision comparison; procfs identity and replacement detection. | Synthetic process; no Alpine advisory baseline claimed. |
| Rocky Linux 9.3 container | Real RPM checksum, epoch/release, architecture/vendor/module queries and native comparison; procfs identity/replacement. | Exercises the RPM adapter, not a RHEL advisory or an actual PHP workload. |
| Arch rolling container, amd64 emulation | Real pacman mtree SHA-256 and native `vercmp`. | Procfs acceptance was not claimed under emulation. Package-install sandboxing was disabled only inside this disposable test container because the emulator rejected it. |
| Docker transport | Actual source/inventory/build-evidence transfer to a temporary Debian container, complete validated result and installed-file scope. | Synthetic artifact; container removed. Podman transport has command-construction coverage only. |
| User-provided Windows host, build 26300, Python 3.13.15, Windows PowerShell 5.1 | Actual key-authenticated SSH discovery and installed-file transport; native file hashes, case-insensitive paths, PE resource hints, process and loaded-DLL enumeration. | The interpreter and its DLL served as explicitly synthetic fixtures, not PHP builds. Protected-process coverage errors were retained. Temporary test files were removed. |

`verify_native.py` reproduces the Linux package/procfs checks in a disposable Linux
environment with Python installed. `verify_windows.py` reproduces the native
Windows checks beside the audit script; it uses the current interpreter and its
DLL without executing PHP or changing system configuration.

Live Windows testing found and fixed two issues that mocks missed: `stat` and
`fstat` exposed different change-time semantics, and PowerShell 5.1 wrapped the
JSON inventory array when another array wrapper was added. File stability now
compares open-handle metadata; inventory-specified DLLs are actually discovered.

## Remaining limits

Windows module paths identify disk files, not the immutable bytes of an already
loaded image. Running Windows records therefore remain `UNKNOWN`, with separate
`file_status`. Native testing confirms this distinction; it does not remove it.
Installed-file success is not host-wide clearance on any OS.

No production PHP deployment, actual vulnerable/patched PHP binary pair, Linux
SSH/sudo policy, WinRM, Kubernetes/Swarm fleet, or exploit behavior was validated.
The supplied repositories were read, not run. Non-Debian/RHEL/Ubuntu releases
still need their own trusted advisory/build evidence. HTTP, configuration,
multipart and log/event observations cannot establish patching or compromise.
