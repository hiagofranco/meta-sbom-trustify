# meta-sbom-trustify

A Yocto layer that turns a built RPM feed into **Trustify-ready security
artifacts**: a package-level CycloneDX SBOM and a matching CSAF VEX advisory.

## What it produces

Running the report recipe writes the following under `SBOM_TRUSTIFY_DEPLOY`
(default `${DEPLOY_DIR}/sbom-trustify`, i.e. `tmp/deploy/sbom-trustify`):

| File | Format | Contents |
|------|--------|----------|
| `cyclonedx-feed.json` | CycloneDX 1.6 SBOM | Target RPM feed (runtime / device risk) |
| `cyclonedx-native.json` | CycloneDX 1.6 SBOM | `-native` recipes (build integrity) |
| `csaf-vex-feed.json` | CSAF 2.0 VEX | Advisory for the feed SBOM |
| `csaf-vex-native.json` | CSAF 2.0 VEX | Advisory for the native SBOM |

Key properties of the output:

- **Package-level purls** in `pkg:rpm` form, with arch, e.g.
  `pkg:rpm/poky-altcfg/libssl3@3.5.6?arch=x86_64_v3`. The namespace is
  `SBOM_TRUSTIFY_DISTRO` (default `${DISTRO}`).
- Each SBOM component carries a `yocto:recipe` property; the CSAF generator
  joins CVEs (which are recipe-level) onto **every RPM that recipe produced**.

## Dependencies

| Requirement | Why |
|-------------|-----|
| OpenEmbedded-Core (`core`), branch `scarthgap` | Base layer |
| `PACKAGE_CLASSES = "package_rpm"` | The SBOM is built from `deploy/rpm` + `pkgdata` |
| `INHERIT += "cve-check"` | Enables CVE analysis (CSAF only) |

The CSAF generator reads the per-recipe `<PN>_cve.json` files that `cve-check`
writes under `CVE_CHECK_DIR` (`${DEPLOY_DIR}/cve`). `cve-check` wires
`do_cve_check` before `do_build`, so a plain `bitbake world` produces one file per
recipe — no image required. The first run downloads the NVD database via
`cve-update-nvd2-native`. **If no cve-check report is found, the CSAF step fails
with a clear message; the SBOM itself is still generated.**

## Usage

1. Add the layer:
   ```sh
   bitbake-layers add-layer meta-sbom-trustify
   ```
2. Build the feed and the per-recipe CVE reports (everything you want
   inventoried; `do_cve_check` runs as part of the build):
   ```sh
   bitbake world
   ```
3. Generate the artifacts (on-demand; the recipe is excluded from `world`):
   ```sh
   bitbake sbom-trustify-report
   ```
4. Find the four JSON files under `tmp/deploy/sbom-trustify/`.
5. Ingest into Trustify (web UI or API):
   - upload `cyclonedx-*.json` as **SBOMs**
   - upload `csaf-vex-*.json` as **Advisories**

   Trustify correlates them by purl: the feed SBOM links its feed advisory, and
   the native SBOM links its native advisory.

## Configuration

All variables can be set in `local.conf`.

| Variable | Default | Description |
|----------|---------|-------------|
| `SBOM_TRUSTIFY_DISTRO` | `${DISTRO}` | purl namespace |
| `SBOM_TRUSTIFY_SCOPES` | `feed native` | Which SBOMs to emit |
| `SBOM_TRUSTIFY_DEPLOY` | `${DEPLOY_DIR}/sbom-trustify` | Output directory |
| `SBOM_TRUSTIFY_AFFECTED_ONLY` | `1` | `1` = only Unpatched CVEs in the CSAF; `0` = also fixed / not_affected |
| `SBOM_TRUSTIFY_COLLAPSE` | `linux-yocto` | Recipes whose many packages collapse to one component (the kernel would otherwise add hundreds of module packages) |
| `SBOM_TRUSTIFY_INCLUDE_NONCODE` | `0` | `1` keeps `-dev`/`-dbg`/`-doc`/`-locale`/… packages |
| `SBOM_TRUSTIFY_NONCODE` | `-dev -dbg -doc -src -staticdev -locale -conf -ptest` | Suffixes treated as non-code |
| `SBOM_TRUSTIFY_CVE_DIR` | `${DEPLOY_DIR}/cve` | Where cve-check drops per-recipe reports |
| `SBOM_TRUSTIFY_CVE_GLOB` | `*_cve.json` | Per-recipe cve-check report glob |

## Notes

- **Scopes**: `feed` is the target RPM feed (runtime / device risk); `native` is
  the build-time `-native` recipes (build integrity), with each native's CVEs
  projected from its target recipe.
- **CVSS**: the CSAF carries CVSS v3 and v2 objects parsed from cve-check.
  Trustify ingests and surfaces **CVSS v3** (`cvss3_scores`); CVSS v4 vectors and
  CVEs with no score in the source are listed without a score.
- The SBOM is recipe/feed-wide and **independent of any image**: `bitbake world`
  is enough; you do not need to build an image first. `cve-check` runs per recipe
  during the world build, so the CSAF covers the whole feed (not just an image).

## AI Assistance Disclosure

Claude Code (Opus 4.8 model) was used to generate this README.md file and to
generated parts of the function `generate_trustify_csaf_vex()` and parts of the
function `generate_guac_cyclonedx()`.
