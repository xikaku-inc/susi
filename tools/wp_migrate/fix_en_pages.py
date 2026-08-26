"""Promote spec tables to real header tables + fix English oddities.

Usage: fix_specs.py <base_url> <token> [--dry]
Targets the staging EN pages; ja_pages files are handled separately.
"""
import json, re, sys, urllib.request, urllib.parse

BASE, TOKEN = sys.argv[1], sys.argv[2]
DRY = "--dry" in sys.argv

SPEC_HEADINGS = re.compile(r"^#{2,4} (Specifications?|仕様)\s*$")

def promote_spec_tables(md):
    """After a Specifications heading, turn the empty-header table into a
    real table by using its first row as the header (bold stripped)."""
    lines = md.split("\n")
    out, i, changed = [], 0, False
    while i < len(lines):
        out.append(lines[i])
        if SPEC_HEADINGS.match(lines[i].strip()):
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith("|"):
                out.append(lines[j]); j += 1
            # Table start: empty header row + separator + first data row.
            if (j + 2 < len(lines)
                    and re.fullmatch(r"\|(\s*\|)+\s*", lines[j].strip())
                    and re.fullmatch(r"\|?[\s:|-]+\|[\s:|-]+\|?", lines[j+1].strip())
                    and lines[j+2].strip().startswith("|")):
                header = lines[j+2].replace("**", "")
                ncols = lines[j].count("|") - 1
                sep = "|" + " --- |" * ncols
                out.append(header)
                out.append(sep)
                i = j + 3
                changed = True
                continue
            i = j
            continue
        i += 1
    return "\n".join(out), changed

# Per-page English corrections (exact replacements, EN pages only).
FIXES = {
    "lp-research": [
        ("sub-dgree", "sub-degree"),
        ("At 50 Hz updates with sub-degree resolution, it runs in ergonomics analysis",
         "With 50 Hz updates and sub-degree resolution, it is used in ergonomics analysis"),
    ],
    "vr-ar-tracking-solutions-lpvr": [
        ("LPVR-CAD fuctionality", "LPVR-CAD functionality"),
    ],
    "lpms-b2": [
        ("Low Enery (LE) 4.1", "Low Energy (LE) 4.1"),
        ("(LPMS-B2) series  is a", "(LPMS-B2) series is a"),
        ("< 0. 5°(static)", "< 0.5° (static)"),
    ],
    "lpms-u3-usb-and-can-bus-imu": [
        ("with variant communication interfaces like USB",
         "with a variety of communication interfaces such as USB"),
        ("By the use of three different MEMS sensors", "Through the use of three different MEMS sensors"),
        ("sensors fit both machine and human motion measurements for size and cost sensitive applications",
         "sensors are a perfect fit for both machine and human motion measurement in size- and cost-sensitive applications"),
        ("< 0. 5° (static)", "< 0.5° (static)"),
    ],
    "lpms-al3-9-axis-imu-sensor": [
        ("with waterproof IP67 enclosure", "with a waterproof IP67 enclosure"),
        ("< 0. 5°(static)", "< 0.5° (static)"),
    ],
    "lpms-ig1": [
        ("is fused with a three-axis accelerometer and magnetometer data",
         "is fused with three-axis accelerometer and magnetometer data"),
        ("< 0. 3° (static)", "< 0.3° (static)"),
    ],
    "lpms-ig1p": [
        ("Roll: <0. 26°", "Roll: <0.26°"),
        ("Pitch: <0. 18°", "Pitch: <0.18°"),
        ("Yaw: <0. 02°", "Yaw: <0.02°"),
    ],
    "lpms-ig1w": [
        ("9-AxisIMU (Inertial Measurement Unit)/ AHRS", "9-Axis IMU (Inertial Measurement Unit) / AHRS"),
        ("< 0. 3° (static)", "< 0.3° (static)"),
    ],
    "lpms-nav3": [
        ("We created this unit, especially with automotive, mobile robotics, and automatic guided vehicle (AGV) application cases in mind.",
         "We created this unit especially with automotive, mobile robotics, and automated guided vehicle (AGV) applications in mind."),
    ],
    "lpms-hr": [
        ("Oder online", "Order online"),
    ],
    "lpms-curs3-oem-9-axis-imu-ahrs-usb-can-uart": [
        ("perfectly fits both machine and human motion measurements for size and cost sensitive applications",
         "is a perfect fit for both machine and human motion measurement in size- and cost-sensitive applications"),
        ("< 0. 5°(static)", "< 0.5° (static)"),
    ],
    "9-axis-usb-and-can-bus-imu-lpmsu2-series": [
        ("The unit in this series is very versatile, performing",
         "The units in this series are very versatile, performing"),
        ("By the use of three different MEMS sensors", "Through the use of three different MEMS sensors"),
        ("This series fits both machine and human motion measurements for size and cost sensitive applications",
         "This series is a perfect fit for both machine and human motion measurement in size- and cost-sensitive applications"),
        ("< 0. 5° (static)", "< 0.5° (static)"),
    ],
    "lpms-me1": [
        ("perfectly fits both machine and human motion measurements for size and cost sensitive applications",
         "is a perfect fit for both machine and human motion measurement in size- and cost-sensitive applications"),
        ("< 0. 5°(static)", "< 0.5° (static)"),
    ],
    "lpms-inc1": [
        ("including raw acceleration data, calibrated acceleration data, and inclination, and temperature readings",
         "including raw acceleration data, calibrated acceleration data, inclination, and temperature readings"),
        ("Froat 32-bit output", "Float 32-bit output"),
        ("Find a distributors", "Find a distributor"),
    ],
    "lpvr-cad": [
        ("Although the positioning accuracy of optical tracking systems are in the sub-millimeter range",
         "Although the positioning accuracy of optical tracking systems is in the sub-millimeter range"),
        ("especially orientation measurement is often not sufficient",
         "the orientation measurement in particular is often not sufficient"),
    ],
    "lpvr-duo": [],
    "lpvr-air": [],
    "lpvr-pos": [
        ("integrates a vehicle odometery data", "integrates vehicle odometry data"),
        ("leading to hinaccurate localization output", "leading to inaccurate localization output"),
        ("to fill in the frames inbetween", "to fill in the frames in between"),
        ("from RTK-GNS aren’t available", "from RTK-GNSS aren’t available"),
    ],
}

def req(method, path, body=None):
    r = urllib.request.Request(BASE + path, method=method)
    r.add_header("Authorization", "Bearer " + TOKEN)
    r.add_header("Content-Type", "application/json")
    data = json.dumps(body).encode() if body is not None else None
    with urllib.request.urlopen(r, data) as resp:
        return json.loads(resp.read().decode())

for slug, fixes in FIXES.items():
    d = req("GET", f"/api/v1/website/pages/{urllib.parse.quote(slug)}?site=lpr")
    body = d["body_md"]
    orig = body
    for old, new in fixes:
        if old not in body:
            print(f"  !! no match on {slug}: {old[:50]}")
        body = body.replace(old, new)
    body, table_changed = promote_spec_tables(body)
    if body == orig:
        print(f"{slug}: unchanged")
        continue
    print(f"{slug}: {'table+' if table_changed else ''}{sum(1 for o, n in fixes if o in orig)} fixes")
    if not DRY:
        req("PUT", f"/api/v1/website/pages/{urllib.parse.quote(slug)}?site=lpr", {
            "title": d["title"],
            "body_md": body,
            "parent_slug": d.get("parent_slug"),
            "ord": d.get("ord") or 0,
            "meta_description": d.get("meta_description") or "",
        })
print("done")
