# Components and forwarding architecture decision

Assessment date: 2026-11-11. Public GitHub repository metadata was read for the
three existing research references; no source code or user data was uploaded.
A push timestamp demonstrates activity, not a security audit or maintenance SLA.

| Candidate | Observed metadata | Fit / security tradeoffs |
| --- | --- | --- |
| [NetGuard](https://github.com/M66B/NetGuard) | GPL-3.0, not archived; pushed 2026-08-01 | Closest Android rootless per-UID forwarding/firewall reference. Adopting its engine requires review of its exact native revision, build inputs, UID mapping, IPv6/fragments, forwarding sockets and lifecycle. License/feature gates must be reviewed; no paid feature/service dependency may be imported. |
| [TrackerControl](https://github.com/TrackerControl/tracker-control-android) | GPL-3.0, not archived; pushed 2026-11-09 | Relevant local traffic analysis/filtering architecture; larger policy/database surface and inherited engine need a pinned review. Domain attribution is not reliable decryption of arbitrary DoH/ECH traffic. |
| [AFWall+](https://github.com/ukanth/afwall) | GPL-3.0, not archived; pushed 2026-10-17 | Kernel-rule approach depends on root and changes the trust/compatibility model; unsuitable as a drop-in for this unprivileged app. |

Apache-2.0 and GPL-3.0 code can be combined under appropriate GPL-3.0 distribution
terms while retaining required notices. This is not a claim of blanket license
incompatibility. No candidate was copied, integrated or relicensed in this change.
Current source remains Apache-2.0. Repository-level GitHub license labels do not
replace a file-by-file license review of any future pinned import.

The existing sink has no TCP/IP forwarding stack. Adding parser decisions to it
cannot allow selected packets safely: a forwarder must own TCP state, UDP mappings,
fragment reassembly, checksums, retransmissions, MTU/PMTU, memory/time budgets and
UID attribution. Forwarding sockets must be protected from VPN recursion. Native
code introduces memory-safety and NDK/ABI review requirements. Importing a large
engine without those tests would reduce the confidence of this patch.

Decision: harden the existing sink, expose the platform Lockdown boundary, and
build real traffic regression infrastructure now. Do not invent a new TCP stack
or label IP/port/domain filtering as complete. A subsequent pinned NetGuard-engine
assessment is the closest practical path to useful selective forwarding with
Lockdown. It must preserve the no-telemetry/no-paid-service requirement and pass
the complete device matrix before replacing the sink.

Runtime dependencies are AndroidX/Compose/Lifecycle, Kotlin/coroutines and their
resolved transitives. `app/gradle.lockfile` records versions and
`gradle/verification-metadata.xml` records artifact hashes, including plugins and
test inputs. Only official configured Maven repositories are used; versions are
not floating. The wrapper distribution already has a pinned SHA-256.

Lint reports six newer-version warnings for Compose BOM, Activity, Lifecycle
(two declarations), AndroidX JUnit and runner. They remain visible. No broad
transitive override was applied to AGP's tool dependencies: compatibility and
actual call-path review are required before changing those inputs.

## Offline license and advisory inventory

`scripts/audit-dependency-licenses.py` inventories cached POMs and inherited
parent declarations: **373 component records, 85 release-runtime graph records,
zero missing release-runtime declarations**. These declarations are not a legal
or full upstream-source audit. See [CSV](DEPENDENCY_LICENSES.csv).

The public OSV Maven snapshot was downloaded as generic advisory data, then
matched locally using Apache Maven 3.9.9 `ComparableVersion`. No project code,
package list or user data was sent to a scanning service. Snapshot Last-Modified:
2026-11-10T19:48:24Z; SHA-256:
`f779994d544de75b9a303de907d2bbe91dc7936f7ca060208f92828e207577a3`.
See [machine-readable candidates](DEPENDENCY_ADVISORIES.json).

**7,257 advisory records; 373 components; 62 version/advisory candidates;
zero release-runtime version candidates; zero unsupported range types.**
Aliases may duplicate vulnerabilities. Zero runtime matches is not proof of
absence: native code, Android/JDK, incomplete metadata and reachability are outside
this comparison. Build/plugin/test artifacts still execute on developer machines.

Candidates include AGP/tool inputs Guava, protobuf, Commons IO/Compress, Netty,
HttpClient, jose4j, Bouncy Castle and JDOM, plus Kotlin Gradle plugin 2.0.21.
Upstream severities include HIGH and CRITICAL; those are upstream labels, not a
validated exploit severity in this repository. Netty server/TLS/JWT/X.509 paths
are not application runtime paths here; exact build-task reachability remains
unproven. Do not treat them as fixed or harmless merely because APK runtime has
zero matches. Review a compatible AGP/Gradle/Kotlin upgrade before production.

Kotlin candidate GHSA-r937-wjx7-w2jp / CVE-2026-53914 describes unsafe build-cache
metadata deserialization before 2.4.20 (OSV range fixes at 2.4.20-Beta1). This
project configures no shared/remote build cache, and Gradle build caching is off
by default; this reduces exposure but does not remediate the upstream defect.
Do not enable or import untrusted caches. No claim is made that a beta upgrade
would be a safe production fix. Toolchain advisory triage/upgrade is an open
release gate; builds should run in isolated, trusted workspaces without secrets
from unrelated projects.

Reproduction (development-only comparator jar, never bundled in the APK):

```sh
python3 scripts/audit-dependency-licenses.py
python3 scripts/audit-maven-advisories.py \
  --database /path/to/Maven-all.zip \
  --maven-jar /path/to/maven-artifact-3.9.9.jar \
  --java-home /path/to/jdk \
  --snapshot-date 2026-11-10T19:48:24Z
```

The comparator's SHA-256 is enforced by the script. The upstream ZIP digest is
recorded in the output; use an intentionally reviewed snapshot when refreshing.
