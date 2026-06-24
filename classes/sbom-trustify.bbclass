SBOM_TRUSTIFY_DISTRO ?= "${DISTRO}"
SBOM_TRUSTIFY_AFFECTED_ONLY ?= "1"
SBOM_TRUSTIFY_COLLAPSE ?= "linux-yocto"
SBOM_TRUSTIFY_DEPLOY ?= "${DEPLOY_DIR}/sbom-trustify"
SBOM_TRUSTIFY_INCLUDE_NONCODE ?= "0"
SBOM_TRUSTIFY_NONCODE ?= "-dev -dbg -doc -src -staticdev -locale -conf -ptest"
SBOM_TRUSTIFY_SCOPES ?= "feed native"

def generate_trustify_sbom(d):
    import json
    import os
    import uuid
    from datetime import datetime, timezone
    from pathlib import Path 

    def is_code_package(name):
        if "-locale-" in name:
            return False
        noncode_suffixes = tuple(d.getVar("SBOM_TRUSTIFY_NONCODE").split())
        return not name.endswith(noncode_suffixes)

    # returns PN, PV and PKGV from the runtime-reverse informations
    # from a package. Example for openssl:
    # >>> out
    # {'PN': 'openssl', 'PV': '3.5.6', 'PKGV': '3.5.6'}
    def read_pkgdata(pkg):
        # Split on ': ' so 'PKG:foo: bar' keys do not fool us
        out = {}
        for line in pkg.read_text().splitlines():
            k, sep, v = line.partition(": ")
            if sep and k in ("PN", "PV", "PKGV"):
                out[k] = v
        return out

    def enumerate_rpms():
        tmp_path = d.getVar("TMPDIR")
        machine = d.getVar("MACHINE")
        # tmp/pkgdata/<machine>/runtime-reverse
        runtime_r_path = Path(tmp_path) / "pkgdata" / machine / "runtime-reverse"
        if not runtime_r_path.is_dir():
            bb.fatal(f"runtime-reverse not found for machine {machine}")

        # RPM packages live in rpm/deploy/rpm/<arch>
        rpm_root_path = Path(tmp_path) / "deploy" / "rpm"
        if not rpm_root_path.is_dir():
            bb.fatal(f"deploy/rpm not found it {tmp_path}")
       
        collapse_recipes = (d.getVar("SBOM_TRUSTIFY_COLLAPSE") or "").split()
        # Iterate over arch directories inside rpm folder to get all rpm packages
        seen = {}
        unmatched = 0
        for arch_dir in rpm_root_path.iterdir():
            # Skip if, for some reason, this isn't a folder
            if not arch_dir.is_dir():
                continue
            arch = arch_dir.name
            for rpm in arch_dir.glob("*.rpm"):
                # RPM comes with the following format: NAME-VERSION-RELEASE.ARCH
                # "stem" - > without the .rpm extension
                pkg_name = rpm.stem.rsplit("-", 2)[0] # get NAME
                # On runtime-reverse folder, there is a file inside with the
                # package name, like "runtime-reverse/openssl/". This file contains
                # the informations about the pakcage, like PN, PB, PR, PKGV...
                rr = runtime_r_path / pkg_name
                # If for some reason there is no info about the package
                if not rr.is_file():
                    unmatched += 1
                    continue
                f = read_pkgdata(rr)
                pn, pv, pkgv = f.get("PN"), f.get("PV"), f.get("PKGV")
                # For recipes like linux-yocto that produces too many packages with
                # no real value for the analisys (like a bunch of different kernel
                # modules packages), aggregate them into one single "linux-yocto"
                # name.
                name = pn if pn in collapse_recipes else pkg_name
                seen[(name, pv, arch)] = (name, arch, pv, pkgv, pn)

        if unmatched:
            bb.warn(f"{unmatched} rpm(s) had no runtime-reverse entry.")
        return list(seen.values())

    def enumerate_natives():
        build_arch = d.getVar("BUILD_SYS")
        work_path = Path(d.getVar("TMPDIR")) / "work" / build_arch
        if not work_path.is_dir():
            bb.fatal(f"native work dir not found: {work_path}")

        natives = []
        for recipe in work_path.iterdir():
            if not recipe.is_dir() or not recipe.name.endswith("-native"):
                continue
            target = recipe.name.removesuffix("-native")
            # Usually there is only one version, but let's iterate anyway
            for ver in recipe.iterdir():
                if ver.is_dir():
                    # Duplicate version to match the non-native pkgs to be used
                    # to build the sbom
                    natives.append((recipe.name, build_arch, ver.name, ver.name, target))
        return natives 

    def make_purl(distro, name, version, arch):
        return f"pkg:rpm/{distro}/{name}@{version}?arch={arch}"

    def build_bom(rows, bom_name):
        include_noncode = d.getVar("SBOM_TRUSTIFY_INCLUDE_NONCODE") == "1"
        distro = d.getVar("SBOM_TRUSTIFY_DISTRO")

        components, skipped = [], []
        for name, arch, pv, pkgv, pn in rows:
            if not include_noncode and not is_code_package(name):
                skipped.append(name)
                continue
            
            components.append(
                {
                    "type": "library",
                    "bom-ref": str(uuid.uuid4()),
                    "name": name,
                    "version": pv,
                    "purl": make_purl(distro, name, pv, arch),
                    "properties": [
                        {"name": "yocto:package_arch", "value": arch},
                        {"name": "yocto:pkgv", "value": pkgv or pv},
                        {"name": "yocto:recipe", "value": pn},
                    ],
                }
            )

        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "component": {
                    "type": "operating-system",
                    "bom-ref": str(uuid.uuid4()),
                    "name": bom_name,
                    "version": distro
                },
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "feed-to-cyclonedx",
                            "version": "0.1",
                        },
                    ]    
                },
            },
            "components": components,
        }
        return bom, skipped
    
    scopes = (d.getVar("SBOM_TRUSTIFY_SCOPES") or '').split()
    if not scopes:
        bb.fatal("SBOM_TRUSTIFY_SCOPES not set, please set as 'feed' or 'native'")

    deploy = d.getVar("SBOM_TRUSTIFY_DEPLOY")
    bb.utils.mkdirhier(deploy)

    machine = d.getVar("MACHINE")
    for scope in scopes:
        if scope == "feed":
            rows = enumerate_rpms()
        elif scope == "native":
            rows = enumerate_natives()
        else:
            bb.fatal("SBOM_TRUSTIFY_SCOPES not set to 'feed' or 'native'")

        bom, skipped = build_bom(rows, f"{machine}-{scope}")
        if skipped: 
            bb.plain(f"Skipped recipes: {len(skipped)}")

        with open(os.path.join(deploy, f"cyclonedx-{scope}.json"), "w") as file:
            json.dump(bom, file, indent=2)

# Run once at the end of any build (world or image), like buildhistory.bbclass.
# At BuildCompleted all tasks have run, so pkgdata/runtime-reverse and deploy/rpm
# are fully populated. Enable with INHERIT += "sbom-trustify" in local.conf.
addhandler sbom_trustify_eventhandler
sbom_trustify_eventhandler[eventmask] = "bb.event.BuildCompleted"

python sbom_trustify_eventhandler() {
    if e.getFailures() == 0:
        generate_trustify_sbom(d)
}
