#!/usr/bin/env bash
set -euo pipefail

REPO="open-wallet-standard/core"
INSTALL_DIR="${OWS_INSTALL_DIR:-$HOME/.ows/bin}"

info()  { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn()  { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
err()   { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

TMPDIR=""
REPO_DIR=""
cleanup() {
  if [ -n "$TMPDIR" ] && [ -d "$TMPDIR" ]; then
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT

# --- Clone repo into TMPDIR (idempotent) ---
ensure_repo_cloned() {
  if [ -n "$REPO_DIR" ] && [ -d "$REPO_DIR/.git" ]; then
    return
  fi
  if [ -z "$TMPDIR" ] || [ ! -d "$TMPDIR" ]; then
    TMPDIR="$(mktemp -d)"
  fi
  REPO_DIR="$TMPDIR/repo"
  info "Cloning repository..."
  git clone --depth 1 "https://github.com/${REPO}.git" "$REPO_DIR" --quiet
}

# --- Detect platform ---
detect_platform() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Linux)   os="linux" ;;
    Darwin)  os="darwin" ;;
    *)       err "unsupported OS: $os" ;;
  esac

  case "$arch" in
    x86_64|amd64)   arch="x86_64" ;;
    aarch64|arm64)   arch="aarch64" ;;
    *)               err "unsupported architecture: $arch" ;;
  esac

  echo "${os}-${arch}"
}

# --- Try to download prebuilt binary ---
try_download() {
  local platform="$1"
  TMPDIR="$(mktemp -d)"
  local bin_path="${TMPDIR}/ows"

  # Fetch recent release tags (latest first)
  local tags
  tags="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases?per_page=5" 2>/dev/null \
    | grep '"tag_name"' | sed 's/.*"tag_name": *"//;s/".*//')" || true

  if [ -z "$tags" ]; then
    # Fallback: try the /latest redirect if API call failed
    tags="latest"
  fi

  for tag in $tags; do
    local release_url
    if [ "$tag" = "latest" ]; then
      release_url="https://github.com/${REPO}/releases/latest/download/ows-${platform}"
    else
      release_url="https://github.com/${REPO}/releases/download/${tag}/ows-${platform}"
    fi

    info "Downloading prebuilt binary for ${platform} (${tag})..."
    if curl -fsSL -o "$bin_path" "$release_url" 2>/dev/null; then
      chmod +x "$bin_path"
      # Verify it's actually an executable
      if file "$bin_path" | grep -qi "executable\|mach-o\|elf"; then
        echo "$bin_path"
        return 0
      fi
    fi
    warn "Binary not available for ${tag}, trying previous release..."
  done

  return 1
}

# --- Build from source (fallback) ---
build_from_source() {
  info "No prebuilt binary available — building from source..."

  # Check prerequisites
  command -v git &>/dev/null || err "git is required. Install git first."

  if command -v rustup &>/dev/null; then
    info "Rust already installed ($(rustc --version))"
  elif command -v rustc &>/dev/null; then
    info "rustc found ($(rustc --version))"
  else
    info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet
    export PATH="$HOME/.cargo/bin:$PATH"
  fi

  if ! command -v cargo &>/dev/null; then
    if [ -f "$HOME/.cargo/env" ]; then
      . "$HOME/.cargo/env"
    else
      err "cargo not found. Install Rust: https://rustup.rs"
    fi
  fi

  ensure_repo_cloned

  info "Building ows..."
  cd "$REPO_DIR/ows"
  cargo build --workspace --release

  local bin_path="$REPO_DIR/ows/target/release/ows"
  if [ ! -f "$bin_path" ]; then
    err "Build failed — binary not found"
  fi

  echo "$bin_path"
}

# --- Install binary ---
install_bin() {
  local bin_path="$1"

  mkdir -p "$INSTALL_DIR"
  cp "$bin_path" "$INSTALL_DIR/ows"
  chmod +x "$INSTALL_DIR/ows"

  # Set strict permissions on the vault root
  chmod 700 "$(dirname "$INSTALL_DIR")" 2>/dev/null || true

  info "Installed ows to $INSTALL_DIR/ows"
}

# --- Add INSTALL_DIR to PATH ---
setup_path() {
  if echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    return
  fi

  local line="export PATH=\"$INSTALL_DIR:\$PATH\""
  local shell_name
  shell_name="$(basename "${SHELL:-/bin/bash}")"

  case "$shell_name" in
    zsh)
      local rc="$HOME/.zshrc"
      if [ -f "$rc" ] && grep -qF "$INSTALL_DIR" "$rc"; then return; fi
      echo "$line" >> "$rc"
      info "Added $INSTALL_DIR to PATH in $rc"
      ;;
    bash)
      local rc="$HOME/.bashrc"
      if [ -f "$HOME/.bash_profile" ]; then rc="$HOME/.bash_profile"; fi
      if [ -f "$rc" ] && grep -qF "$INSTALL_DIR" "$rc"; then return; fi
      echo "$line" >> "$rc"
      info "Added $INSTALL_DIR to PATH in $rc"
      ;;
    fish)
      local rc="$HOME/.config/fish/config.fish"
      local fish_line="fish_add_path $INSTALL_DIR"
      if [ -f "$rc" ] && grep -qF "$INSTALL_DIR" "$rc"; then return; fi
      mkdir -p "$(dirname "$rc")"
      echo "$fish_line" >> "$rc"
      info "Added $INSTALL_DIR to PATH in $rc"
      ;;
    *)
      info "Add $INSTALL_DIR to your PATH manually"
      ;;
  esac
}

# --- Install Python bindings ---
install_python_bindings() {
  if ! command -v python3 &>/dev/null; then
    info "python3 not found — skipping Python bindings"
    return
  fi
  if ! command -v pip3 &>/dev/null && ! python3 -m pip --version &>/dev/null 2>&1; then
    info "pip not found — skipping Python bindings"
    return
  fi

  info "Installing Python bindings..."
  if pip3 install open-wallet-standard 2>/dev/null || python3 -m pip install open-wallet-standard 2>/dev/null; then
    info "Python bindings installed successfully"
  else
    warn "Failed to install Python bindings from PyPI"
  fi
}

# --- Install Node bindings ---
install_node_bindings() {
  if ! command -v node &>/dev/null; then
    info "node not found — skipping Node bindings"
    return
  fi
  if ! command -v npm &>/dev/null; then
    info "npm not found — skipping Node bindings"
    return
  fi

  info "Installing Node bindings..."

  # Try installing from npm registry first
  if npm install -g @open-wallet-standard/node 2>/dev/null; then
    # Verify the package is usable (index.js must exist in the global install)
    local pkg_dir
    pkg_dir="$(npm root -g)/@open-wallet-standard/node"
    if [ -f "$pkg_dir/index.js" ]; then
      info "Node bindings installed successfully"
      return
    fi
    warn "npm package is incomplete — building from source"
    npm uninstall -g @open-wallet-standard/node 2>/dev/null || true
  fi

  # Fallback: build from source
  if ! command -v cargo &>/dev/null; then
    if [ -f "$HOME/.cargo/env" ]; then
      . "$HOME/.cargo/env"
    fi
  fi
  if ! command -v cargo &>/dev/null; then
    warn "cargo not found — skipping Node bindings (Rust required to build)"
    return
  fi

  ensure_repo_cloned

  local node_dir="$REPO_DIR/bindings/node"
  cd "$node_dir"

  npm install 2>/dev/null
  npx napi build --platform --release 2>/dev/null

  if [ ! -f "$node_dir/index.js" ]; then
    warn "Node bindings build failed — index.js not found"
    return
  fi

  # Pack into a tarball and install globally (avoids symlink-to-tmpdir issue)
  local tarball
  tarball="$(npm pack --pack-destination "$TMPDIR" 2>/dev/null | tail -1)"
  if [ -n "$tarball" ] && npm install -g "$TMPDIR/$tarball" 2>/dev/null; then
    info "Node bindings installed successfully (built from source)"
  else
    warn "Failed to install Node bindings globally"
  fi
}

# --- Install bindings ---
install_bindings() {
  install_python_bindings
  install_node_bindings
}

# --- Main ---
main() {
  info "OWS installer"
  echo

  # --- Migrate ~/.lws → ~/.ows ---
  OLD_DIR="$HOME/.lws"
  NEW_DIR="$HOME/.ows"
  if [ -d "$OLD_DIR" ] && [ ! -d "$NEW_DIR" ]; then
    info "Migrating vault from $OLD_DIR to $NEW_DIR..."
    mv "$OLD_DIR" "$NEW_DIR"
    # Update config.json vault_path if present
    if [ -f "$NEW_DIR/config.json" ]; then
      sed -i.bak 's|\.lws|.ows|g' "$NEW_DIR/config.json"
      rm -f "$NEW_DIR/config.json.bak"
    fi
    # Update PATH in shell rc files
    for rc in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.config/fish/config.fish"; do
      if [ -f "$rc" ]; then
        sed -i.bak 's|\.lws/bin|.ows/bin|g' "$rc"
        rm -f "$rc.bak"
      fi
    done
    info "Migrated vault to $NEW_DIR"
  elif [ -d "$OLD_DIR" ] && [ -d "$NEW_DIR" ]; then
    warn "Both $OLD_DIR and $NEW_DIR exist. Using $NEW_DIR. Remove $OLD_DIR manually if no longer needed."
  fi

  local platform bin_path
  platform="$(detect_platform)"

  if bin_path="$(try_download "$platform")"; then
    install_bin "$bin_path"
  else
    warn "Prebuilt binary not found for ${platform}, falling back to source build"
    bin_path="$(build_from_source)"
    install_bin "$bin_path"
  fi

  setup_path

  echo
  info "Installing language bindings..."
  install_bindings

  echo
  info "OWS installed successfully!"

  local shell_name
  shell_name="$(basename "${SHELL:-/bin/bash}")"
  local source_cmd=""
  case "$shell_name" in
    zsh)  source_cmd="source ~/.zshrc" ;;
    bash)
      if [ -f "$HOME/.bash_profile" ]; then
        source_cmd="source ~/.bash_profile"
      else
        source_cmd="source ~/.bashrc"
      fi
      ;;
    fish) source_cmd="source ~/.config/fish/config.fish" ;;
  esac

  if [ -n "$source_cmd" ]; then
    info "Run the following to start using ows immediately:"
    echo
    echo "  $source_cmd"
    echo
  else
    info "Restart your shell, then run 'ows --help' to get started."
  fi
}

main "$@"
