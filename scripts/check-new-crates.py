import json
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

MIN_CRATE_AGE_DAYS = 90
MIN_VERSION_AGE_DAYS = 7
LOCKFILES = ["ows/Cargo.lock", "bindings/node/Cargo.lock", "bindings/python/Cargo.lock"]
USER_AGENT = "open-wallet-standard-ci (https://github.com/open-wallet-standard/core)"


def registry_packages(rev, path):
    shown = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True, text=True)
    packages = set()
    for block in shown.stdout.split("[[package]]")[1:]:
        fields = dict(
            line.split(" = ", 1) for line in block.strip().splitlines() if " = " in line
        )
        if "registry+" in fields.get("source", ""):
            packages.add((fields["name"].strip('"'), fields["version"].strip('"')))
    return packages


def age_days(timestamp):
    created_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - created_at).days


def crate_metadata(name):
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{name}", headers={"User-Agent": USER_AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def check(name, version, new_crate):
    metadata = crate_metadata(name)
    if metadata is None:
        return f"{name} {version}: not found on crates.io (removed)"
    if new_crate:
        crate_age = age_days(metadata["crate"]["created_at"])
        if crate_age < MIN_CRATE_AGE_DAYS:
            return f"{name} {version}: new crate, first published {crate_age} days ago"
    match = next((v for v in metadata.get("versions", []) if v["num"] == version), None)
    if match is None:
        return f"{name} {version}: version not found on crates.io"
    if match.get("yanked"):
        return f"{name} {version}: version is yanked"
    version_age = age_days(match["created_at"])
    if version_age < MIN_VERSION_AGE_DAYS:
        return f"{name} {version}: version published {version_age} days ago"
    print(f"ok {name} {version}: version published {version_age} days ago")
    return None


def main(base):
    base_packages = set()
    head_packages = set()
    for lockfile in LOCKFILES:
        base_packages |= registry_packages(base, lockfile)
        head_packages |= registry_packages("HEAD", lockfile)
    base_names = {name for name, _ in base_packages}
    changed = sorted(head_packages - base_packages)
    if not changed:
        print("no new crate versions")
    failures = [
        failure
        for name, version in changed
        if (failure := check(name, version, name not in base_names))
    ]
    for failure in failures:
        print(f"::error::{failure}; review its build.rs and owners before merging")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
