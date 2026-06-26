SUMMARY = "Generate Trustify SBOM from the built RPM feed"
DESCRIPTION = "Scans the feed already produced by the build \
and emits CycloneDX SBOMs under SBOM_TRUSTIFY_DEPLOY."
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

inherit sbom-trustify nospdx

INHIBIT_DEFAULT_DEPS = "1"

# Exclude from 'bitbake world', this recipe will actually run after 'world' or
# 'image' build.
EXCLUDE_FROM_WORLD = "1"

# cve-check (inherited globally) wires do_cve_check before do_build on every
# recipe; this aggregator has no sources to scan, so drop it to avoid pulling
# in cve-update-nvd2-native.
deltask do_cve_check

addtask do_generate_trustify_sbom before do_build
do_generate_trustify_sbom[nostamp] = "1"
