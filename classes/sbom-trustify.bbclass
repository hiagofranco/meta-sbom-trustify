SBOM_TRUSTIFY_DISTRO ?= "${DISTRO}"
SBOM_TRUSTIFY_COLLAPSE ?= "linux-yocto"
SBOM_TRUSTIFY_DEPLOY ?= "${DEPLOY_DIR}/sbom-trustify"
SBOM_TRUSTIFY_INCLUDE_NONCODE ?= "0"
SBOM_TRUSTIFY_NONCODE ?= "-dev -dbg -doc -src -staticdev -locale -conf -ptest"
SBOM_TRUSTIFY_SCOPES ?= "feed native"
SBOM_TRUSTIFY_AFFECTED_ONLY ?= "1"

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
                # the informations about the package, like PN, PB, PR, PKGV...
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
            bb.note(f"Skipped recipes: {len(skipped)}")

        with open(os.path.join(deploy, f"cyclonedx-{scope}.json"), "w") as file:
            json.dump(bom, file, indent=2)
        bb.note(f"Saved cyclonedx-{scope}.json on {deploy}")

def generate_trustify_csaf_vex(d):
    import json
    import uuid
    from datetime import datetime, timezone
    from pathlib import Path
    from collections import defaultdict
    # CVSS v3 base-metric abbreviation -> (CSAF field name, value map).
    _CVSS3 = {
        "AV": ("attackVector", {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}),
        "AC": ("attackComplexity", {"L": "LOW", "H": "HIGH"}),
        "PR": ("privilegesRequired", {"N": "NONE", "L": "LOW", "H": "HIGH"}),
        "UI": ("userInteraction", {"N": "NONE", "R": "REQUIRED"}),
        "S": ("scope", {"U": "UNCHANGED", "C": "CHANGED"}),
        "C": ("confidentialityImpact", {"N": "NONE", "L": "LOW", "H": "HIGH"}),
        "I": ("integrityImpact", {"N": "NONE", "L": "LOW", "H": "HIGH"}),
        "A": ("availabilityImpact", {"N": "NONE", "L": "LOW", "H": "HIGH"}),
    }

    # CVSS v2 base-metric abbreviation -> (CSAF field name, value map). NOT the same
    # as v3: v2 has Au (authentication) with no v3 equivalent, AC has a MEDIUM level,
    # and the C/I/A impacts are NONE/PARTIAL/COMPLETE instead of NONE/LOW/HIGH.
    _CVSS2 = {
        "AV": ("accessVector", {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL"}),
        "AC": ("accessComplexity", {"L": "LOW", "M": "MEDIUM", "H": "HIGH"}),
        "Au": ("authentication", {"M": "MULTIPLE", "S": "SINGLE", "N": "NONE"}),
        "C": ("confidentialityImpact", {"N": "NONE", "P": "PARTIAL", "C": "COMPLETE"}),
        "I": ("integrityImpact", {"N": "NONE", "P": "PARTIAL", "C": "COMPLETE"}),
        "A": ("availabilityImpact", {"N": "NONE", "P": "PARTIAL", "C": "COMPLETE"}),
    }

    distro = d.getVar("SBOM_TRUSTIFY_DISTRO")
    deploy = d.getVar("SBOM_TRUSTIFY_DEPLOY")
    scopes = (d.getVar("SBOM_TRUSTIFY_SCOPES") or "").split()
    affected_only = d.getVar("SBOM_TRUSTIFY_AFFECTED_ONLY") == "1"

    # Yocto cve-check status -> CSAF product_status bucket.
    BUCKET = {
        "Unpatched": "known_affected",
        "Patched": "fixed",
        "Ignored": "known_not_affected",
    }
    # When the same (recipe, cve) shows up in several per-recipe reports (the
    # dependency closure overlaps), keep the most severe status.
    _STATUS_RANK = {"Ignored": 0, "Patched": 1, "Unpatched": 2}

    def severity(score):
        if score <= 0:
            return "NONE"
        elif score < 4:
            return "LOW"
        elif score < 7:
            return "MEDIUM"
        elif score < 9:
            return "HIGH"
        return "CRITICAL"

    def cvss3_object(vector, score_str):
        """Full CSAF cvss_v3 object parsed from a CVSS:3.x vectorString."""
        if not vector or not vector.startswith("CVSS:3"):
            return None
        parts = vector.split("/")
        obj = {"version": parts[0].split(":")[1], "vectorString": vector}
        for part in parts[1:]:
            k, _, v = part.partition(":")
            if k in _CVSS3:
                field, vmap = _CVSS3[k]
                obj[field] = vmap.get(v, v)
        score = float(score_str or 0)
        obj["baseScore"] = score
        obj["baseSeverity"] = severity(score)
        return obj

    def cvss2_object(vector, score_str):
        """Full CSAF cvss_v2 object. A v2 vector has no 'CVSS:' prefix
        (e.g. AV:N/AC:L/Au:N/C:C/I:C/A:C)."""
        if not vector or vector.startswith("CVSS:"):
            return None
        obj = {"version": "2.0", "vectorString": vector}
        for part in vector.split("/"):
            k, _, v = part.partition(":")
            if k in _CVSS2:
                field, vmap = _CVSS2[k]
                obj[field] = vmap.get(v, v)
        obj["baseScore"] = float(score_str or 0)
        return obj

    def make_cvss(issue):
        """Pick the right CVSS object from an issue's primary vectorString.
        Returns (csaf_field, object) or None. Trustify's CSAF ingest reads
        cvss_v2 and cvss_v3 but NOT cvss_v4, so v4 vectors are dropped."""
        vector = issue.get("vectorString") or ""
        if vector.startswith("CVSS:3"):
            obj = cvss3_object(vector, issue.get("scorev3"))
            return ("cvss_v3", obj) if obj else None
        if vector.startswith("CVSS:4"):
            return None
        obj = cvss2_object(vector, issue.get("scorev2"))
        return ("cvss_v2", obj) if obj else None

    def load_sbom(path):
        doc = json.loads(Path(path).read_text())
        comps = []
        for c in doc.get("components", []):
            props = {p["name"]: p["value"] for p in c.get("properties", [])}
            comps.append(
                {"purl": c["purl"], "name": c["name"], "recipe": props.get("yocto:recipe")}
            )
        return comps

    def load_cve_check(paths):
        """Merge the N per-recipe *.sbom-cve-check.yocto.json reports, deduping
        each (recipe, cve) and keeping the highest-ranked status."""
        merged = {}
        for path in paths:
            report = json.loads(Path(path).read_text())
            for entry in report.get("package", []):
                recipe = merged.setdefault(
                    entry["name"], {"version": entry.get("version", ""), "issues": {}}
                )
                for issue in entry.get("issue", []):
                    kept = recipe["issues"].get(issue["id"])
                    if kept is None or (
                        _STATUS_RANK.get(issue.get("status"), -1)
                        > _STATUS_RANK.get(kept.get("status"), -1)
                    ):
                        recipe["issues"][issue["id"]] = issue
        return {
            "package": [
                {"name": name, "version": rec["version"], "issue": list(rec["issues"].values())}
                for name, rec in merged.items()
            ]
        }

    def build_csaf_vex(sbom_path, cc):
        comps = load_sbom(sbom_path)
        recipe_to_idx = defaultdict(list)
        for i, c in enumerate(comps):
            if c["recipe"]:
                recipe_to_idx[c["recipe"]].append(i)

        # cve id -> {buckets: {bucket: set(idx)}, cvss: (field,obj)|None, note, link}
        cves = {}
        for entry in cc.get("package", []):
            idxs = recipe_to_idx.get(entry["name"])
            if not idxs:
                continue
            for issue in entry.get("issue", []):
                status = issue.get("status")
                if affected_only and status != "Unpatched":
                    continue
                bucket = BUCKET.get(status)
                if not bucket:
                    continue
                rec = cves.setdefault(
                    issue["id"],
                    {
                        "buckets": defaultdict(set),
                        "cvss": None,
                        "note": issue.get("summary", ""),
                        "link": issue.get("link", ""),
                    },
                )
                rec["buckets"][bucket].update(idxs)
                if rec["cvss"] is None:
                    rec["cvss"] = make_cvss(issue)

        referenced = sorted(
            {i for r in cves.values() for s in r["buckets"].values() for i in s}
        )
        # product_status / scores reference the COMBINED product id created by the
        # relationship (distro:comp-N), never the bare leaf comp-N, or Trustify
        # won't correlate.
        pid = lambda i: f"distro:comp-{i}"

        leaves = [
            {
                "category": "product_name",
                "name": distro,
                "product": {
                    "name": distro,
                    "product_id": "distro",
                    "product_identification_helper": {"cpe": f"cpe:/o:{distro}:{distro}"},
                },
            }
        ]
        rels = []
        for i in referenced:
            c = comps[i]
            leaves.append(
                {
                    "category": "product_version",
                    "name": c["purl"],
                    "product": {
                        "name": c["purl"],
                        "product_id": f"comp-{i}",
                        # purl taken verbatim from the SBOM so it can't desync.
                        "product_identification_helper": {"purl": c["purl"]},
                    },
                }
            )
            rels.append(
                {
                    "category": "default_component_of",
                    "product_reference": f"comp-{i}",
                    "relates_to_product_reference": "distro",
                    "full_product_name": {
                        "name": f"{c['name']} as a component of {distro}",
                        "product_id": pid(i),
                    },
                }
            )

        vulns = []
        for cid in sorted(cves):
            rec = cves[cid]
            ps = {b: sorted(pid(i) for i in idxs) for b, idxs in rec["buckets"].items()}
            v = {"cve": cid, "product_status": ps}
            if rec["cvss"]:
                field, obj = rec["cvss"]
                all_ids = sorted({p for ids in ps.values() for p in ids})
                v["scores"] = [{field: obj, "products": all_ids}]
            v["notes"] = [{"category": "description", "text": rec["note"] or cid, "title": cid}]
            if rec["link"]:
                v["references"] = [{"summary": cid, "url": rec["link"]}]
            vulns.append(v)

        now = datetime.now(timezone.utc).isoformat()
        return {
            "document": {
                "category": "csaf_vex",
                "csaf_version": "2.0",
                "title": f"Yocto distro VEX for {distro} (sbom-cve-check)",
                "publisher": {
                    "category": "vendor",
                    "name": distro,
                    "namespace": f"https://example.invalid/{distro}",
                },
                "tracking": {
                    "id": f"YOCTO-VEX-{distro}-{uuid.uuid4().hex[:8]}",
                    "status": "final",
                    "version": "1",
                    "initial_release_date": now,
                    "current_release_date": now,
                    "revision_history": [
                        {"number": "1", "date": now, "summary": "Generated from sbom-cve-check"}
                    ],
                    "generator": {"engine": {"name": "sbom-trustify", "version": "0.1"}},
                },
            },
            "product_tree": {
                "branches": [{"category": "vendor", "name": distro, "branches": leaves}],
                "relationships": rels,
            },
            "vulnerabilities": vulns,
        }

    # The recipe-scoped cve-check (SBOM_CVE_CHECK_RECIPE_AUTO=1) drops one
    # <recipe>-recipe-sbom.sbom-cve-check.yocto.json per recipe here.
    img = Path(d.getVar("DEPLOY_DIR_IMAGE"))
    cve_files = sorted(img.glob("*.sbom-cve-check.yocto.json"))
    if not cve_files:
        bb.warn(
            "sbom-trustify: no *.sbom-cve-check.yocto.json in %s; skipping CSAF "
            "(needs SBOM_CVE_CHECK_RECIPE_AUTO=1)" % img
        )
        return

    cc = load_cve_check(cve_files)
    for scope in scopes:
        sbom_path = Path(deploy) / f"cyclonedx-{scope}.json"
        if not sbom_path.is_file():
            bb.warn(f"sbom-trustify: {sbom_path} missing; skipping CSAF for {scope}")
            continue
        csaf = build_csaf_vex(str(sbom_path), cc)
        out = Path(deploy) / f"csaf-vex-{scope}.json"
        out.write_text(json.dumps(csaf, indent=2))
        bb.note(f"Saved {out.name} ({len(csaf['vulnerabilities'])} CVEs) on {deploy}")

python do_generate_trustify_sbom() {
    generate_trustify_sbom(d)
    generate_trustify_csaf_vex(d)
}
