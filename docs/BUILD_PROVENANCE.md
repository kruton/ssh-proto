# Verifying Maven build provenance

The attested publication pipeline targets **SLSA v1.0 Build Level 3** for both
`org.connectbot.sshlib:sshlib` and `org.connectbot.sshlib:protocol`, including
snapshots. Verify the publication job and attestation evidence for the version
you consume. The guarantees apply to artifacts whose provenance matches the
expected source and builder policy and whose published bytes pass verification.

## Published evidence

Each Maven publication includes the following evidence files:

| Classifier | Extension | Contents |
| --- | --- | --- |
| `provenance` | `json` | Sigstore bundle containing an in-toto SLSA provenance v1 statement |
| `sbom-attestation` | `json` | Sigstore bundle binding the binary JAR to its CycloneDX SBOM |
| `cyclonedx` | `json` | The CycloneDX SBOM itself |

Provenance covers the exact binary, sources and Javadoc JARs, POM, Gradle module
metadata and CycloneDX file by SHA-256. Bundles and GPG signatures are sidecars;
they are not embedded in JARs, avoiding circular digests.

Tagged versions also have a GitHub Release with the same Maven files, bundles,
GPG signatures and `SHA256SUMS`. Attestations for releases and snapshots are
discoverable through GitHub's attestation API. Workflow artifacts retain the
attested files for 30 days. Snapshots do not create GitHub Releases; Sonatype may
expire snapshot files according to its retention policy.

## Verify a downloaded release

Use a GitHub CLI version supporting `gh attestation verify` and the policy flags
below. Choose the version you consume and an independently trusted source commit
for that version. Obtain that commit through your normal review/trust process;
accepting a digest from unverified metadata would weaken the policy.

```bash
version=VERSION
commit=EXPECTED_40_CHARACTER_COMMIT
builder=REVIEWED_SHARED_BUILDER_COMMIT
base="https://repo.maven.apache.org/maven2/org/connectbot/sshlib/sshlib/$version"
curl --fail --remote-name "$base/sshlib-$version.jar"
curl --fail --remote-name "$base/sshlib-$version-provenance.json"

gh attestation verify "sshlib-$version.jar" \
  --bundle "sshlib-$version-provenance.json" \
  --repo connectbot/cbssh \
  --signer-workflow connectbot/actions/.github/workflows/publish-maven.yml \
  --signer-digest "$builder" \
  --source-digest "$commit" \
  --source-ref "refs/tags/v$version" \
  --deny-self-hosted-runners
```

The shared reusable workflow is pinned in this repository's CI configuration.
Its signer revision is the reviewed commit in `connectbot/actions`, separate from
the library's source revision. The command verifies the artifact
digest, SLSA predicate type, Sigstore signature and certificate identity, expected
source, and trusted builder workflow. For online lookup, omit `--bundle`.
For disconnected verification, also provision an independently trusted Sigstore
root with `gh attestation trusted-root` and pass `--custom-trusted-root`.

Repeat verification for `protocol` and any sources, documentation, POM, module
metadata or SBOM files your process consumes. A valid signature or matching
`SHA256SUMS` alone does not enforce the expected builder and source policy.

To verify the SBOM attestation, download the `sbom-attestation` classifier and
run the same command against the binary JAR with:

```bash
--bundle "sshlib-$version-sbom-attestation.json" \
--predicate-type https://cyclonedx.org/bom
```

The pipeline also verifies that the signed SBOM predicate equals the published
`cyclonedx` file. Consumers can inspect verified statements with `--format json`.
Always validate signatures and certificate policy before consuming predicate data.

## Resolve bundles with Maven or Gradle

Maven can download a bundle without adding it to your application classpath:

```bash
mvn org.apache.maven.plugins:maven-dependency-plugin:3.8.1:get \
  -Dartifact=org.connectbot.sshlib:sshlib:VERSION:json:provenance \
  -Dtransitive=false
```

For Gradle, use a separate resolvable configuration:

```kotlin
val libraryProvenance by configurations.creating {
    isCanBeConsumed = false
    isTransitive = false
}
dependencies {
    libraryProvenance("org.connectbot.sshlib:sshlib:VERSION:provenance@json")
}
```

Resolve and verify the bundle and the actual JAR selected by dependency resolution
before running the build steps that consume the library. Ordinary Maven/Gradle
dependency resolution does not automatically verify these attestations.

## Snapshots

Snapshot versions are mutable. Resolve the version-level `maven-metadata.xml`
from `https://central.sonatype.com/repository/maven-snapshots/`, then select the
same timestamp/build number for the JAR, provenance and SBOM attestation.
For example, the base version directory `0.5.2-SNAPSHOT` might contain:

```text
sshlib-0.5.2-20261015.123456-7.jar
sshlib-0.5.2-20261015.123456-7-provenance.json
sshlib-0.5.2-20261015.123456-7-sbom-attestation.json
```

Verify these files with the snapshot's expected source commit and branch ref
(`refs/heads/main` or `refs/heads/release/X.Y`), rather than a release tag.
Attestation subjects use the original `*-SNAPSHOT` filenames; verification binds
the downloaded file by digest even when the repository timestamps its filename.
Retain the resolved timestamp, exact SHA-256 digest, source commit and bundles
with your build evidence. Independently resolving `latest` twice can select
different publications.

## Extend this evidence in downstream builds

1. Enforce the repository, builder, source and digest policy in a trusted
   dependency-verification step, before consuming either published module.
2. Retain the verified Sigstore bundles and verification results with your own
   build evidence. Use `--format json` for additional policy checks.
3. Record the resolved Maven coordinates and artifact digest in your build's
   provenance `resolvedDependencies`, along with other dependencies you use.
4. Generate provenance for your own outputs using your chosen trusted builder.

This evidence establishes how this dependency was built. Your application's SLSA
level still depends on your own build platform, provenance and distribution.
The SBOM describes dependencies; it does not certify their security or confer a
SLSA level on third-party components.

## Builder security model and operations

- The trusted builder is `connectbot/actions/.github/workflows/publish-maven.yml`,
  pinned to an immutable shared-builder commit in this repository's CI workflow.
  It checks out its helpers using GitHub's platform-reported `job.workflow_sha`,
  separately from the source commit. Consumers should approve both revisions
  as part of their source and builder policy. External actions are commit-pinned.
- Publication follows successful source verification, workflow checks and the
  Java 17/21/25 test matrix. Only upstream CI push runs on permitted branches or
  matching annotated release tags may publish. No caller-supplied build commands,
  revisions or artifact selectors are accepted.
- The publication build runs on a fresh GitHub-hosted runner with no secrets or
  OIDC permission. Gradle caches are not restored or uploaded, and build caching
  is disabled. Network dependency downloads remain permitted and use strict
  Gradle dependency verification; SLSA v1 Build L3 does not require hermeticity.
- The attestation job runs separately on another fresh hosted runner. It computes
  digests from this run's immutable artifact and uses GitHub-generated provenance.
  It does not run the staged project. Sigstore signing uses short-lived OIDC
  credentials; build steps cannot access the attestation job or signing identity.
- The publisher verifies every payload and its certificate identity before
  receiving any upload effect. It then GPG-signs those same bytes and bundles,
  without executing the library build. Maven GPG signing is independent of
  provenance authentication. Maven and GPG credentials are supplied through
  GitHub Actions secrets.
- Releases use the Central Portal bundle API. Snapshots use the pinned Maven GPG
  plugin's `sign-and-deploy-file` goal from an empty directory, with explicit
  prebuilt files and POM. This preserves `.jar.asc`, `.pom.asc` and other signature
  extensions in a single deployment. Snapshot timestamp allocation is delegated
  to Maven; attested file contents stay intact.
- Downloads from the destination are compared with the attested local bytes.
  A GitHub Release stays in draft until all assets are uploaded. Attestation
  generation/verification failures stop publication; there is no unsigned fallback.
- Publication is serialized across branches and never cancelled mid-upload.
  Workflow summaries include attestation links and Central deployment records.

Every snapshot and tagged release publication checks that both modules' bundles
resolve from Sonatype and that the downloaded files match the verified
publication. Assess each artifact using its own provenance and verification
results; the repository's workflow configuration alone does not establish an
artifact's SLSA level.

For failures, rerun the failed publisher job so it reuses the original attested
artifact. Rerunning attestation creates new bundle bytes, which may conflict with
an already immutable release. Central deployment IDs and uploaded bundles are
preserved in the publication-records workflow artifact for 30 days. Inspect a
recorded deployment before retrying an interrupted upload to avoid duplicate
deployments. Partially visible CDN files are retried during normal publication;
if a later retry sees an incomplete release, wait for propagation and retry.

References: [SLSA v1.0 requirements](https://slsa.dev/spec/v1.0/requirements),
[GitHub's Level 3 workflow guidance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating),
[GitHub CLI verification policy](https://cli.github.com/manual/gh_attestation_verify).
