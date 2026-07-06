SBOM_TRUSTIFY_DISTRO ?= "${DISTRO}"
SBOM_TRUSTIFY_COLLAPSE ?= "linux-yocto"
SBOM_TRUSTIFY_DEPLOY ?= "${DEPLOY_DIR}/sbom-trustify"
SBOM_TRUSTIFY_INCLUDE_NONCODE ?= "0"
SBOM_TRUSTIFY_NONCODE ?= "-dev -dbg -doc -src -staticdev -locale -conf -ptest"
SBOM_TRUSTIFY_SCOPES ?= "feed native"
SBOM_TRUSTIFY_AFFECTED_ONLY ?= "1"
# Scarthgap cve-check writes one <PN>_cve.json per recipe under CVE_CHECK_DIR
# (${DEPLOY_DIR}/cve). We glob+merge them all (the report recipe does not
# inherit cve-check, so default to the path instead of ${CVE_CHECK_DIR}).
SBOM_TRUSTIFY_CVE_DIR ?= "${DEPLOY_DIR}/cve"
SBOM_TRUSTIFY_CVE_GLOB ?= "*_cve.json"

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

    # Scarthgap cve-check (INHERIT += "cve-check") drops one <PN>_cve.json per
    # recipe under CVE_CHECK_DIR. do_cve_check is wired before do_build, so a
    # normal world build produces the whole feed:
    #   bitbake world          (or, to force: bitbake world -k -c cve_check)
    cve_dir = Path(d.getVar("SBOM_TRUSTIFY_CVE_DIR"))
    cve_glob = d.getVar("SBOM_TRUSTIFY_CVE_GLOB")
    cve_files = sorted(cve_dir.glob(cve_glob))
    if not cve_files:
        bb.fatal(
            f"sbom-trustify: no {cve_glob} under {cve_dir}; run the cve-check "
            "first (INHERIT += \"cve-check\"; bitbake world)."
        )

    # Each per-recipe report covers only its own recipe (no dependency-closure
    # overlap), so a plain union of the package lists is enough.
    cc = {"package": []}
    for f in cve_files:
        cc["package"].extend(json.loads(f.read_text()).get("package", []))
    for scope in scopes:
        sbom_path = Path(deploy) / f"cyclonedx-{scope}.json"
        if not sbom_path.is_file():
            bb.warn(f"sbom-trustify: {sbom_path} missing; skipping CSAF for {scope}")
            continue
        csaf = build_csaf_vex(str(sbom_path), cc)
        out = Path(deploy) / f"csaf-vex-{scope}.json"
        out.write_text(json.dumps(csaf, indent=2))
        bb.note(f"Saved {out.name} ({len(csaf['vulnerabilities'])} CVEs) on {deploy}")

def generate_guac_cyclonedx(d):
    import json
    from pathlib import Path

    deploy = Path(d.getVar("SBOM_TRUSTIFY_DEPLOY"))
    scopes = (d.getVar("SBOM_TRUSTIFY_SCOPES") or "").split()

    STATE = {
        "known_affected": "exploitable",
        "fixed": "resolved",
        "known_not_affected": "not_affected",
    }

    def cdx_rating(score):
        for field, method in (("cvss_v3", "CVSSv3"), ("cvss_v2", "CVSSv2")):
            obj = score.get(field)
            if obj:
                r = {"method": method, "score": obj.get("baseScore"),
                     "vector": obj.get("vectorString")}
                if obj.get("baseSeverity"):
                    r["severity"] = obj["baseSeverity"].lower()
                return r
        return None

    def build_guac_bom(sbom, csaf):
        # purl -> bom-ref for every SBOM component; the GUAC doc keeps the full
        # component list so the dependency graph rides along with the vulns.
        purl_to_ref = {c["purl"]: c["bom-ref"] for c in sbom.get("components", [])}

        leaf_ref = {}
        for vendor in csaf["product_tree"]["branches"]:
            for leaf in vendor.get("branches", []):
                if leaf["category"] != "product_version":
                    continue
                helper = leaf["product"].get("product_identification_helper", {})
                ref = purl_to_ref.get(helper.get("purl"))
                if ref:
                    leaf_ref[leaf["product"]["product_id"]] = ref
        pid_to_ref = {
            rel["full_product_name"]["product_id"]: leaf_ref[rel["product_reference"]]
            for rel in csaf["product_tree"].get("relationships", [])
            if rel["product_reference"] in leaf_ref
        }

        vulns = []
        for v in csaf.get("vulnerabilities", []):
            cid = v["cve"]
            # Returns and empty dict in case of fail (= returns None)
            rating = cdx_rating((v.get("scores") or [{}])[0])
            link = (v.get("references") or [{}])[0].get("url")
            for bucket, pids in v.get("product_status", {}).items():
                state = STATE.get(bucket)
                if not state:
                    continue
                refs = [{"ref": pid_to_ref[pid]} for pid in pids if pid in pid_to_ref]
                if not refs:
                    continue
                vuln = {
                    "bom-ref": f"{cid}-{bucket}",
                    "id": cid,
                    "source": {"name": "NVD", "url": link} if link else {"name": "NVD"},
                    "analysis": {"state": state},
                    "affects": refs,
                }
                if rating:
                    vuln["ratings"] = [rating]
                vulns.append(vuln)

        out = dict(sbom)
        out["vulnerabilities"] = vulns
        return out

    for scope in scopes:
        sbom_path = deploy / f"cyclonedx-{scope}.json"
        csaf_path = deploy / f"csaf-vex-{scope}.json"
        if not (sbom_path.is_file() and csaf_path.is_file()):
            bb.warn(f"sbom-trustify: missing {scope} inputs; skipping GUAC bom")
            continue
        bom = build_guac_bom(
            json.loads(sbom_path.read_text()),
            json.loads(csaf_path.read_text()),
        )
        out = deploy / f"cyclonedx-guac-{scope}.json"
        out.write_text(json.dumps(bom, indent=2))
        bb.note(f"Saved {out.name} ({len(bom['vulnerabilities'])} VEX entries) on {deploy}")

python do_generate_trustify_sbom() {
    generate_trustify_sbom(d)
    generate_trustify_csaf_vex(d)
    generate_guac_cyclonedx(d)
}
