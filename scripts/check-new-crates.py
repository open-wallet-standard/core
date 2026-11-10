import json
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

MIN_AGE_DAYS = 90
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
            packages.add(fields["name"].strip('"'))
    return packages


def crate_age_days(name):
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{name}", headers={"User-Agent": USER_AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            created = json.load(response)["crate"]["created_at"]
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise
    created_at = datetime.fromisoformat(created.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - created_at).days


def main(base):
    new = set()
    for lockfile in LOCKFILES:
        new |= registry_packages("HEAD", lockfile) - registry_packages(base, lockfile)
    failures = []
    for name in sorted(new):
        age = crate_age_days(name)
        if age is None:
            failures.append(f"{name}: not found on crates.io (removed or yanked)")
        elif age < MIN_AGE_DAYS:
            failures.append(f"{name}: first published {age} days ago")
        else:
            print(f"ok {name}: first published {age} days ago")
    if not new:
        print("no new crates")
    for failure in failures:
        print(f"::error::new crate {failure}; review its build.rs and owners before merging")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
