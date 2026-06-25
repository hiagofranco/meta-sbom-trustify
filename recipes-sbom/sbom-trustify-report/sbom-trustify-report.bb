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

addtask do_generate_trustify_sbom before do_build
do_generate_trustify_sbom[nostamp] = "1"
