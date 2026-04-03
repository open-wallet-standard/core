#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <version> --python|--node|--rust|--docs|--all" >&2
  exit 1
}

[[ $# -lt 2 ]] && usage

VERSION="$1"
SCOPE="$2"

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
  echo "Error: invalid version '$VERSION'" >&2
  exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"

set_python_version() {
  sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" \
    "$REPO_ROOT/bindings/python/pyproject.toml" \
    "$REPO_ROOT/bindings/python/Cargo.toml"
  rm -f "$REPO_ROOT/bindings/python/pyproject.toml.bak" \
        "$REPO_ROOT/bindings/python/Cargo.toml.bak"
  (cd "$REPO_ROOT/bindings/python" && cargo update --workspace)
}

set_node_version() {
  sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" \
    "$REPO_ROOT/bindings/node/Cargo.toml"
  rm -f "$REPO_ROOT/bindings/node/Cargo.toml.bak"

  cd "$REPO_ROOT/bindings/node"
  npm version "$VERSION" --no-git-tag-version --allow-same-version

  for pkg in npm/*/package.json; do
    jq --arg v "$VERSION" '.version = $v' "$pkg" > tmp.json && mv tmp.json "$pkg"
  done

  jq --arg v "$VERSION" \
    '.optionalDependencies |= with_entries(.value = $v)' \
    package.json > tmp.json && mv tmp.json package.json

  npm install

  cargo update --workspace
}

set_rust_version() {
  local crates_dir="$REPO_ROOT/ows/crates"

  # Update package versions
  for crate in ows-core ows-signer ows-lib ows-pay ows-cli; do
    sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" \
      "$crates_dir/$crate/Cargo.toml"
    rm -f "$crates_dir/$crate/Cargo.toml.bak"
  done

  # Update internal dependency version specifiers
  for crate in ows-signer ows-lib ows-pay ows-cli; do
    sed -i.bak -E "s/(ows-(core|signer|lib|pay) = \{[^}]*version = \")=[^\"]*\"/\1=$VERSION\"/" \
      "$crates_dir/$crate/Cargo.toml"
    rm -f "$crates_dir/$crate/Cargo.toml.bak"
  done

  (cd "$REPO_ROOT/ows" && cargo update --workspace)
}

set_skill_version() {
  sed -i.bak "s/^version: .*/version: $VERSION/" \
    "$REPO_ROOT/skills/ows/SKILL.md"
  rm -f "$REPO_ROOT/skills/ows/SKILL.md.bak"
}

set_docs_version() {
  local short_version
  short_version="$(echo "$VERSION" | sed 's/\([0-9]*\.[0-9]*\).*/\1/')"

  # website-docs/index.html — sidebar badge and page heading
  sed -i.bak \
    -e "s/<span class=\"version\">v[^<]*</<span class=\"version\">v${short_version}</" \
    -e "s/Open Wallet Standard v[0-9][0-9.a-zA-Z-]*/Open Wallet Standard v${VERSION}/" \
    "$REPO_ROOT/website-docs/index.html"
  rm -f "$REPO_ROOT/website-docs/index.html.bak"

  # website-docs/js/docs.js — sidebar badge in JS
  sed -i.bak \
    "s/<span class=\"version\">v[^<]*</<span class=\"version\">v${short_version}</" \
    "$REPO_ROOT/website-docs/js/docs.js"
  rm -f "$REPO_ROOT/website-docs/js/docs.js.bak"
}

case "$SCOPE" in
  --python) set_python_version ;;
  --node)   set_node_version ;;
  --rust)   set_rust_version ;;
  --docs)   set_docs_version ;;
  --all)    set_rust_version; set_python_version; set_node_version; set_skill_version; set_docs_version ;;
  *) usage ;;
esac
