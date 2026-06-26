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
| OpenEmbedded-Core (`core`), branch `wrynose` | Base layer |
| `PACKAGE_CLASSES = "package_rpm"` | The SBOM is built from `deploy/rpm` + `pkgdata` |
| `OE_FRAGMENTS += "core/yocto/sbom-cve-check"` | Enables CVE analysis (CSAF only) |
| `SBOM_CVE_CHECK_RECIPE_AUTO = "1"` | Runs cve-check per recipe (CSAF only) |

The CSAF generator reads the per-recipe `*.sbom-cve-check.yocto.json` files from
`DEPLOY_DIR_IMAGE`. `SBOM_CVE_CHECK_RECIPE_AUTO` requires the OE-core change that
wires `do_sbom_cve_check_recipe` before `do_build`; without it, build an image so
the image-scoped report is produced instead. **If no cve-check report is found,
the SBOM is still generated and the CSAF step is skipped with a warning.**

## Usage

1. Add the layer:
   ```sh
   bitbake-layers add-layer meta-sbom-trustify
   ```
2. Build the feed (everything you want inventoried):
   ```sh
   bitbake world
   ```
3. Generate `world-recipe-sbom.sbom-cve-check.yocto.json`:
   ```sh
   bitbake meta-world-recipe-sbom -R conf/distro/include/cve-extra-exclusions.inc -c sbom_cve_check_recipe
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
| `SBOM_TRUSTIFY_CVE_REPORT` | `world-recipe-sbom.sbom-cve-check.yocto.json` | Input file |

## Notes

- **Scopes**: `feed` is the target RPM feed (runtime / device risk); `native` is
  the build-time `-native` recipes (build integrity), with each native's CVEs
  projected from its target recipe.
- **CVSS**: the CSAF carries CVSS v3 and v2 objects parsed from cve-check.
  Trustify ingests and surfaces **CVSS v3** (`cvss3_scores`); CVSS v4 vectors and
  CVEs with no score in the source are listed without a score.
- The SBOM is recipe/feed-wide and **independent of any image**: `bitbake world`
  is enough; you do not need to build an image first (except for the image-scoped
  CVE fallback noted above).

## AI Assistance Disclosure

Claude Code (Opus 4.8 model) was used to generate this README.md file and to
generated parts of the function `generate_trustify_csaf_vex()`.
