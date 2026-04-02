use std::fs;
use std::path::{Path, PathBuf};

use ows_core::ChainType;
use ows_signer::{signer_for_chain, Curve};

use crate::CliError;

const README_TEMPLATE: &str = include_str!("../../templates/chain-plugin-kit/README.md.tmpl");
const CONTRIBUTOR_GUIDE_TEMPLATE: &str =
    include_str!("../../templates/chain-plugin-kit/CONTRIBUTOR_GUIDE.md.tmpl");
const CHAIN_PROFILE_TEMPLATE: &str =
    include_str!("../../templates/chain-plugin-kit/chain-profile.toml.tmpl");
const CAIP_MAPPING_TEMPLATE: &str =
    include_str!("../../templates/chain-plugin-kit/caip-mapping.toml.tmpl");
const DERIVATION_RULES_TEMPLATE: &str =
    include_str!("../../templates/chain-plugin-kit/derivation-rules.toml.tmpl");
const SIGN_STUB_TEMPLATE: &str = include_str!("../../templates/chain-plugin-kit/sign.stub.rs.tmpl");
const SERIALIZE_STUB_TEMPLATE: &str =
    include_str!("../../templates/chain-plugin-kit/serialize.stub.rs.tmpl");
const DOCS_SUPPORTED_CHAIN_TEMPLATE: &str =
    include_str!("../../templates/chain-plugin-kit/docs/supported-chain-entry.md.tmpl");
const DOCS_IMPLEMENTATION_CHECKLIST_TEMPLATE: &str =
    include_str!("../../templates/chain-plugin-kit/docs/implementation-checklist.md.tmpl");
const DOCS_SECURITY_CHECKLIST_TEMPLATE: &str =
    include_str!("../../templates/chain-plugin-kit/docs/security-checklist.md.tmpl");
const TEST_VECTORS_TEMPLATE: &str =
    include_str!("../../templates/chain-plugin-kit/test-vectors/README.md.tmpl");
const TEST_VECTORS_DERIVATION_TEMPLATE: &str =
    include_str!("../../templates/chain-plugin-kit/test-vectors/derivation.json.tmpl");
const TEST_VECTORS_SIGN_MESSAGE_TEMPLATE: &str =
    include_str!("../../templates/chain-plugin-kit/test-vectors/sign-message.json.tmpl");
const TEST_VECTORS_TX_SERIALIZATION_TEMPLATE: &str =
    include_str!("../../templates/chain-plugin-kit/test-vectors/tx-serialization.json.tmpl");

pub struct ScaffoldChainOptions<'a> {
    pub slug: &'a str,
    pub family: ChainType,
    pub display_name: Option<&'a str>,
    pub curve: Option<&'a str>,
    pub address_format: Option<&'a str>,
    pub coin_type: Option<u32>,
    pub derivation_path: Option<&'a str>,
    pub caip_namespace: Option<&'a str>,
    pub caip_reference: Option<&'a str>,
    pub output: Option<&'a Path>,
    pub write: bool,
    pub force: bool,
}

pub fn scaffold_chain(options: ScaffoldChainOptions<'_>) -> Result<(), CliError> {
    let current_dir = std::env::current_dir()?;
    let repo_root = find_repo_root(&current_dir)?;
    let plan = build_plan(&repo_root, &options)?;

    if options.write {
        write_plan(&plan, options.force)?;
        println!("Chain Plugin Kit");
        println!(
            "  Generated scaffold for {} ({})",
            plan.context.display_name, plan.context.slug
        );
        println!("  Family baseline: {}", plan.context.family_display);
        println!("  Output: {}", plan.target_dir.display());
        if plan.target_exists {
            println!("  Existing target was replaced because --force was passed.");
        }
        println!(
            "  Next step: open {}",
            plan.target_dir.join("README.md").display()
        );
    } else {
        println!("Chain Plugin Kit");
        println!(
            "  Dry run for {} ({})",
            plan.context.display_name, plan.context.slug
        );
        println!("  Family baseline: {}", plan.context.family_display);
        println!("  Output: {}", plan.target_dir.display());
        if plan.target_exists {
            println!("  Existing target would be replaced because --force was passed.");
        }
    }

    println!();
    println!("Files:");
    for file in &plan.files {
        println!("  {}", file.relative_path.display());
    }

    if !options.write {
        println!();
        println!("Re-run with --write to create these files.");
    }

    Ok(())
}

#[derive(Debug)]
struct ScaffoldPlan {
    safe_output_root: PathBuf,
    target_dir: PathBuf,
    target_exists: bool,
    context: ScaffoldContext,
    files: Vec<PlannedFile>,
}

#[derive(Debug)]
struct PlannedFile {
    relative_path: PathBuf,
    contents: String,
}

#[derive(Debug)]
struct ScaffoldContext {
    slug: String,
    slug_ident: String,
    display_name: String,
    family_display: String,
    family_variant: &'static str,
    namespace: String,
    reference_hint: String,
    curve_display: String,
    curve_variant: &'static str,
    coin_type: u32,
    default_derivation_path: String,
    address_format: String,
}

fn build_plan(
    repo_root: &Path,
    options: &ScaffoldChainOptions<'_>,
) -> Result<ScaffoldPlan, CliError> {
    validate_slug(options.slug)?;
    if let Some(display_name) = options.display_name {
        validate_display_name(display_name)?;
    }
    validate_optional_token("--curve", options.curve)?;
    validate_optional_text("--address-format", options.address_format)?;
    validate_optional_text("--derivation-path", options.derivation_path)?;
    validate_optional_token("--caip-namespace", options.caip_namespace)?;
    validate_optional_token("--caip-reference", options.caip_reference)?;

    let safe_output_root = resolve_safe_output_root(repo_root)?;
    let target_dir = resolve_output_dir(&safe_output_root, options.slug, options.output)?;
    let target_exists = target_dir.exists();
    if target_exists && !options.force {
        return Err(CliError::InvalidArgs(format!(
            "target '{}' already exists; re-run with --force to replace it",
            target_dir.display()
        )));
    }

    let context = build_context(options);
    let files = vec![
        PlannedFile {
            relative_path: PathBuf::from("README.md"),
            contents: render_template(README_TEMPLATE, &context),
        },
        PlannedFile {
            relative_path: PathBuf::from("CONTRIBUTOR_GUIDE.md"),
            contents: render_template(CONTRIBUTOR_GUIDE_TEMPLATE, &context),
        },
        PlannedFile {
            relative_path: PathBuf::from("chain-profile.toml"),
            contents: render_template(CHAIN_PROFILE_TEMPLATE, &context),
        },
        PlannedFile {
            relative_path: PathBuf::from("caip-mapping.toml"),
            contents: render_template(CAIP_MAPPING_TEMPLATE, &context),
        },
        PlannedFile {
            relative_path: PathBuf::from("derivation-rules.toml"),
            contents: render_template(DERIVATION_RULES_TEMPLATE, &context),
        },
        PlannedFile {
            relative_path: PathBuf::from("sign.stub.rs"),
            contents: render_template(SIGN_STUB_TEMPLATE, &context),
        },
        PlannedFile {
            relative_path: PathBuf::from("serialize.stub.rs"),
            contents: render_template(SERIALIZE_STUB_TEMPLATE, &context),
        },
        PlannedFile {
            relative_path: PathBuf::from("docs").join("supported-chain-entry.md"),
            contents: render_template(DOCS_SUPPORTED_CHAIN_TEMPLATE, &context),
        },
        PlannedFile {
            relative_path: PathBuf::from("docs").join("implementation-checklist.md"),
            contents: render_template(DOCS_IMPLEMENTATION_CHECKLIST_TEMPLATE, &context),
        },
        PlannedFile {
            relative_path: PathBuf::from("docs").join("security-checklist.md"),
            contents: render_template(DOCS_SECURITY_CHECKLIST_TEMPLATE, &context),
        },
        PlannedFile {
            relative_path: PathBuf::from("test-vectors").join("README.md"),
            contents: render_template(TEST_VECTORS_TEMPLATE, &context),
        },
        PlannedFile {
            relative_path: PathBuf::from("test-vectors").join("derivation.json"),
            contents: render_template(TEST_VECTORS_DERIVATION_TEMPLATE, &context),
        },
        PlannedFile {
            relative_path: PathBuf::from("test-vectors").join("sign-message.json"),
            contents: render_template(TEST_VECTORS_SIGN_MESSAGE_TEMPLATE, &context),
        },
        PlannedFile {
            relative_path: PathBuf::from("test-vectors").join("tx-serialization.json"),
            contents: render_template(TEST_VECTORS_TX_SERIALIZATION_TEMPLATE, &context),
        },
    ];

    Ok(ScaffoldPlan {
        safe_output_root,
        target_dir,
        target_exists,
        context,
        files,
    })
}

fn write_plan(plan: &ScaffoldPlan, force: bool) -> Result<(), CliError> {
    validate_safe_scaffold_target(&plan.safe_output_root, &plan.target_dir)?;

    if plan.target_dir.exists() {
        if !force {
            return Err(CliError::InvalidArgs(format!(
                "target '{}' already exists; re-run with --force to replace it",
                plan.target_dir.display()
            )));
        }

        validate_safe_force_delete_target(&plan.safe_output_root, &plan.target_dir)?;

        if plan.target_dir.is_dir() {
            fs::remove_dir_all(&plan.target_dir)?;
        } else {
            fs::remove_file(&plan.target_dir)?;
        }
    }

    fs::create_dir_all(&plan.target_dir)?;
    for file in &plan.files {
        let path = plan.target_dir.join(&file.relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, &file.contents)?;
    }
    Ok(())
}

fn build_context(options: &ScaffoldChainOptions<'_>) -> ScaffoldContext {
    let signer = signer_for_chain(options.family);
    let curve = signer.curve();
    let curve_display = options
        .curve
        .map(str::to_string)
        .unwrap_or_else(|| curve_display(curve).to_string());
    let curve_variant = if curve_display == "ed25519" {
        "Ed25519"
    } else {
        "Secp256k1"
    };

    ScaffoldContext {
        slug: options.slug.to_string(),
        slug_ident: to_ident_name(options.slug),
        display_name: options
            .display_name
            .map(str::to_string)
            .unwrap_or_else(|| to_display_name(options.slug)),
        family_display: options.family.to_string(),
        family_variant: chain_type_variant(options.family),
        namespace: options
            .caip_namespace
            .map(str::to_string)
            .unwrap_or_else(|| options.family.namespace().to_string()),
        reference_hint: options
            .caip_reference
            .map(str::to_string)
            .unwrap_or_else(|| default_reference_hint(options.family).to_string()),
        curve_display,
        curve_variant,
        coin_type: options
            .coin_type
            .unwrap_or(options.family.default_coin_type()),
        default_derivation_path: options
            .derivation_path
            .map(str::to_string)
            .unwrap_or_else(|| signer.default_derivation_path(0)),
        address_format: options
            .address_format
            .map(str::to_string)
            .unwrap_or_else(|| default_address_format(options.family).to_string()),
    }
}

fn render_template(template: &str, context: &ScaffoldContext) -> String {
    template
        .replace("{{slug}}", &context.slug)
        .replace("{{slug_string}}", &escape_basic_string(&context.slug))
        .replace("{{slug_ident}}", &context.slug_ident)
        .replace("{{display_name}}", &context.display_name)
        .replace(
            "{{display_name_string}}",
            &escape_basic_string(&context.display_name),
        )
        .replace("{{family}}", &context.family_display)
        .replace(
            "{{family_string}}",
            &escape_basic_string(&context.family_display),
        )
        .replace("{{family_variant}}", context.family_variant)
        .replace("{{namespace}}", &context.namespace)
        .replace(
            "{{namespace_string}}",
            &escape_basic_string(&context.namespace),
        )
        .replace("{{reference_hint}}", &context.reference_hint)
        .replace(
            "{{reference_hint_string}}",
            &escape_basic_string(&context.reference_hint),
        )
        .replace("{{curve}}", &context.curve_display)
        .replace(
            "{{curve_string}}",
            &escape_basic_string(&context.curve_display),
        )
        .replace("{{curve_variant}}", context.curve_variant)
        .replace("{{coin_type}}", &context.coin_type.to_string())
        .replace(
            "{{default_derivation_path}}",
            &context.default_derivation_path,
        )
        .replace(
            "{{default_derivation_path_string}}",
            &escape_basic_string(&context.default_derivation_path),
        )
        .replace("{{address_format}}", &context.address_format)
        .replace(
            "{{address_format_string}}",
            &escape_basic_string(&context.address_format),
        )
}

fn escape_basic_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c.is_control() => escaped.push_str(&format!("\\u{:04X}", c as u32)),
            c => escaped.push(c),
        }
    }
    escaped
}

fn find_repo_root(start: &Path) -> Result<PathBuf, CliError> {
    let mut current = start;
    loop {
        if is_repo_root(current) {
            return Ok(current.to_path_buf());
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => break,
        }
    }

    Err(CliError::InvalidArgs(
        "ows dev scaffold-chain must be run from inside the open-wallet-standard/core repository"
            .into(),
    ))
}

fn is_repo_root(path: &Path) -> bool {
    path.join(".git").exists()
        && path.join("CONTRIBUTING.md").exists()
        && path.join("ows").join("Cargo.toml").exists()
        && path
            .join("ows")
            .join("crates")
            .join("ows-cli")
            .join("Cargo.toml")
            .exists()
}

fn validate_slug(slug: &str) -> Result<(), CliError> {
    if slug.is_empty() {
        return Err(CliError::InvalidArgs("--slug must not be empty".into()));
    }

    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(CliError::InvalidArgs(
            "--slug must contain only lowercase letters, numbers, and hyphens".into(),
        ));
    }

    if slug.starts_with('-') || slug.ends_with('-') || slug.contains("--") {
        return Err(CliError::InvalidArgs(
            "--slug must not start/end with a hyphen or contain repeated hyphens".into(),
        ));
    }

    Ok(())
}

fn validate_display_name(display_name: &str) -> Result<(), CliError> {
    if display_name.trim().is_empty() {
        return Err(CliError::InvalidArgs(
            "--display-name must not be empty".into(),
        ));
    }

    if display_name.trim() != display_name {
        return Err(CliError::InvalidArgs(
            "--display-name must not start or end with whitespace".into(),
        ));
    }

    if display_name.len() > 80 || display_name.chars().any(char::is_control) {
        return Err(CliError::InvalidArgs(
            "--display-name must be printable text up to 80 characters".into(),
        ));
    }

    Ok(())
}

fn validate_optional_token(flag: &str, value: Option<&str>) -> Result<(), CliError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_empty() {
        return Err(CliError::InvalidArgs(format!("{flag} must not be empty")));
    }
    if value.chars().any(char::is_whitespace)
        || value.contains('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return Err(CliError::InvalidArgs(format!(
            "{flag} must not contain whitespace, path separators, or control characters"
        )));
    }
    Ok(())
}

fn validate_optional_text(flag: &str, value: Option<&str>) -> Result<(), CliError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.trim().is_empty() {
        return Err(CliError::InvalidArgs(format!("{flag} must not be empty")));
    }
    if value.chars().any(char::is_control) {
        return Err(CliError::InvalidArgs(format!(
            "{flag} must be printable text"
        )));
    }
    Ok(())
}

fn resolve_safe_output_root(repo_root: &Path) -> Result<PathBuf, CliError> {
    resolve_path_for_creation(&repo_root.join(".ows-dev").join("chain-plugin-kit"))
}

fn resolve_output_dir(
    safe_output_root: &Path,
    slug: &str,
    output: Option<&Path>,
) -> Result<PathBuf, CliError> {
    let default_dir = safe_output_root.join(slug);
    let requested = output.unwrap_or(default_dir.as_path());
    let candidate = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        safe_output_root
            .parent()
            .and_then(Path::parent)
            .unwrap_or(safe_output_root)
            .join(requested)
    };

    let resolved_candidate = resolve_path_for_creation(&candidate)?;
    ensure_path_in_safe_scaffold_area(requested, safe_output_root, &resolved_candidate)?;
    Ok(resolved_candidate)
}

// Resolve as many components as currently exist so symlinked parents cannot
// lexically smuggle scaffold output outside the dedicated safe area.
fn resolve_path_for_creation(path: &Path) -> Result<PathBuf, CliError> {
    let mut missing_components = Vec::new();
    let mut current = path.to_path_buf();

    loop {
        if current.exists() {
            let mut resolved = clean_canonical_path(fs::canonicalize(&current)?);
            for component in missing_components.iter().rev() {
                resolved.push(component);
            }
            return Ok(resolved);
        }

        let name = current.file_name().ok_or_else(|| {
            CliError::InvalidArgs(format!("output path '{}' is invalid", path.display()))
        })?;
        missing_components.push(PathBuf::from(name));
        current = current
            .parent()
            .ok_or_else(|| {
                CliError::InvalidArgs(format!("output path '{}' is invalid", path.display()))
            })?
            .to_path_buf();
    }
}

#[cfg(windows)]
fn clean_canonical_path(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(stripped) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{stripped}"))
    } else if let Some(stripped) = text.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path
    }
}

#[cfg(not(windows))]
fn clean_canonical_path(path: PathBuf) -> PathBuf {
    path
}

fn ensure_path_in_safe_scaffold_area(
    requested: &Path,
    safe_output_root: &Path,
    resolved_candidate: &Path,
) -> Result<(), CliError> {
    if resolved_candidate == safe_output_root || !resolved_candidate.starts_with(safe_output_root) {
        return Err(CliError::InvalidArgs(format!(
            "output path '{}' is unsafe; scaffold output must live under '{}' and may not target the safe scaffold area root",
            requested.display(),
            safe_output_root.display()
        )));
    }

    Ok(())
}

fn validate_safe_scaffold_target(
    safe_output_root: &Path,
    target_dir: &Path,
) -> Result<(), CliError> {
    let resolved_target = resolve_path_for_creation(target_dir)?;
    ensure_path_in_safe_scaffold_area(target_dir, safe_output_root, &resolved_target)
}

fn validate_safe_force_delete_target(
    safe_output_root: &Path,
    target_dir: &Path,
) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(target_dir)?;
    if metadata.file_type().is_symlink() {
        return Err(CliError::InvalidArgs(format!(
            "output path '{}' is unsafe; scaffold targets must not be symlinks",
            target_dir.display()
        )));
    }

    validate_safe_scaffold_target(safe_output_root, target_dir)
}

fn default_reference_hint(family: ChainType) -> &'static str {
    match family {
        ChainType::Evm => "TODO_CHAIN_ID",
        ChainType::Solana => "TODO_CLUSTER_OR_GENESIS_HASH",
        ChainType::Cosmos => "TODO_CHAIN_ID",
        ChainType::Bitcoin => "TODO_GENESIS_HASH",
        ChainType::Tron => "mainnet",
        ChainType::Ton => "mainnet",
        ChainType::Spark => "mainnet",
        ChainType::Filecoin => "mainnet",
        ChainType::Sui => "mainnet",
    }
}

fn default_address_format(family: ChainType) -> &'static str {
    match family {
        ChainType::Evm => "EIP-55 checksummed hex (0x...)",
        ChainType::Solana => "base58-encoded public key",
        ChainType::Cosmos => "bech32 account address",
        ChainType::Bitcoin => "bech32 native segwit address",
        ChainType::Tron => "base58check with 0x41 prefix",
        ChainType::Ton => "base64url wallet address",
        ChainType::Spark => "spark: prefixed compressed pubkey",
        ChainType::Filecoin => "f1 + base32(blake2b-160)",
        ChainType::Sui => "0x + BLAKE2b-256 hex",
    }
}

fn chain_type_variant(chain_type: ChainType) -> &'static str {
    match chain_type {
        ChainType::Evm => "Evm",
        ChainType::Solana => "Solana",
        ChainType::Cosmos => "Cosmos",
        ChainType::Bitcoin => "Bitcoin",
        ChainType::Tron => "Tron",
        ChainType::Ton => "Ton",
        ChainType::Spark => "Spark",
        ChainType::Filecoin => "Filecoin",
        ChainType::Sui => "Sui",
    }
}

fn curve_display(curve: Curve) -> &'static str {
    match curve {
        Curve::Secp256k1 => "secp256k1",
        Curve::Ed25519 => "ed25519",
    }
}

fn to_display_name(slug: &str) -> String {
    slug.split('-')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => {
                    let mut rendered = String::new();
                    rendered.push(first.to_ascii_uppercase());
                    rendered.push_str(chars.as_str());
                    rendered
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn to_ident_name(slug: &str) -> String {
    let ident = slug.replace('-', "_");
    if ident
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        format!("chain_{ident}")
    } else {
        ident
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(unix)]
    fn create_dir_symlink(link: &Path, target: &Path) {
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    #[cfg(windows)]
    fn create_dir_symlink(link: &Path, target: &Path) {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn expected_tree_entries() -> Vec<PathBuf> {
        vec![
            PathBuf::from("CONTRIBUTOR_GUIDE.md"),
            PathBuf::from("README.md"),
            PathBuf::from("caip-mapping.toml"),
            PathBuf::from("chain-profile.toml"),
            PathBuf::from("derivation-rules.toml"),
            PathBuf::from("docs"),
            PathBuf::from("docs").join("implementation-checklist.md"),
            PathBuf::from("docs").join("security-checklist.md"),
            PathBuf::from("docs").join("supported-chain-entry.md"),
            PathBuf::from("serialize.stub.rs"),
            PathBuf::from("sign.stub.rs"),
            PathBuf::from("test-vectors"),
            PathBuf::from("test-vectors").join("README.md"),
            PathBuf::from("test-vectors").join("derivation.json"),
            PathBuf::from("test-vectors").join("sign-message.json"),
            PathBuf::from("test-vectors").join("tx-serialization.json"),
        ]
    }

    fn collect_tree_entries(root: &Path) -> Vec<PathBuf> {
        let mut entries = Vec::new();
        collect_tree_entries_inner(root, root, &mut entries);
        entries.sort();
        entries
    }

    fn collect_tree_entries_inner(root: &Path, current: &Path, entries: &mut Vec<PathBuf>) {
        let mut children = fs::read_dir(current)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect::<Vec<_>>();
        children.sort_by_key(|entry| entry.path());

        for child in children {
            let path = child.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            entries.push(relative.clone());
            if child.file_type().unwrap().is_dir() {
                collect_tree_entries_inner(root, &path, entries);
            }
        }
    }

    fn make_repo_root() -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".git")).unwrap();
        fs::create_dir_all(dir.path().join("ows").join("crates").join("ows-cli")).unwrap();
        fs::write(dir.path().join("CONTRIBUTING.md"), "contrib").unwrap();
        fs::write(dir.path().join("ows").join("Cargo.toml"), "[workspace]").unwrap();
        fs::write(
            dir.path()
                .join("ows")
                .join("crates")
                .join("ows-cli")
                .join("Cargo.toml"),
            "[package]\nname = \"ows-cli\"\n",
        )
        .unwrap();
        dir
    }

    fn test_options<'a>() -> ScaffoldChainOptions<'a> {
        ScaffoldChainOptions {
            slug: "example-chain",
            family: ChainType::Evm,
            display_name: None,
            curve: None,
            address_format: None,
            coin_type: None,
            derivation_path: None,
            caip_namespace: None,
            caip_reference: None,
            output: None,
            write: false,
            force: false,
        }
    }

    #[test]
    fn build_plan_uses_default_output_without_writing() {
        let repo = make_repo_root();
        let options = test_options();
        let plan = build_plan(repo.path(), &options).unwrap();

        assert_eq!(
            plan.target_dir,
            repo.path()
                .join(".ows-dev")
                .join("chain-plugin-kit")
                .join("example-chain")
        );
        assert!(!plan.target_dir.exists());
        assert_eq!(plan.files.len(), 14);
    }

    #[test]
    fn write_plan_creates_expected_files() {
        let repo = make_repo_root();
        let mut options = test_options();
        options.family = ChainType::Solana;
        let plan = build_plan(repo.path(), &options).unwrap();

        write_plan(&plan, false).unwrap();

        assert!(plan.target_dir.join("README.md").exists());
        assert!(plan.target_dir.join("chain-profile.toml").exists());
        assert!(plan.target_dir.join("CONTRIBUTOR_GUIDE.md").exists());
        assert!(plan.target_dir.join("caip-mapping.toml").exists());
        assert!(plan.target_dir.join("derivation-rules.toml").exists());
        assert!(plan.target_dir.join("sign.stub.rs").exists());
        assert!(plan.target_dir.join("serialize.stub.rs").exists());
        assert!(plan
            .target_dir
            .join("docs")
            .join("supported-chain-entry.md")
            .exists());
        assert!(plan
            .target_dir
            .join("docs")
            .join("implementation-checklist.md")
            .exists());
        assert!(plan
            .target_dir
            .join("docs")
            .join("security-checklist.md")
            .exists());
        assert!(plan
            .target_dir
            .join("test-vectors")
            .join("README.md")
            .exists());
        assert!(plan
            .target_dir
            .join("test-vectors")
            .join("derivation.json")
            .exists());
        assert!(plan
            .target_dir
            .join("test-vectors")
            .join("sign-message.json")
            .exists());
        assert!(plan
            .target_dir
            .join("test-vectors")
            .join("tx-serialization.json")
            .exists());
    }

    #[test]
    fn generated_tree_matches_expected_structure() {
        let repo = make_repo_root();
        let plan = build_plan(repo.path(), &test_options()).unwrap();

        write_plan(&plan, false).unwrap();

        assert_eq!(
            collect_tree_entries(&plan.target_dir),
            expected_tree_entries()
        );
    }

    #[test]
    fn rendered_templates_include_slug_and_override_metadata() {
        let repo = make_repo_root();
        let options = ScaffoldChainOptions {
            slug: "example-chain",
            family: ChainType::Bitcoin,
            display_name: Some("Example Chain"),
            curve: Some("ed25519"),
            address_format: Some("hex-with-custom-checksum"),
            coin_type: Some(777),
            derivation_path: Some("m/44'/777'/0'/0/0"),
            caip_namespace: Some("example"),
            caip_reference: Some("alpha"),
            output: None,
            write: false,
            force: false,
        };
        let plan = build_plan(repo.path(), &options).unwrap();

        let profile = plan
            .files
            .iter()
            .find(|file| file.relative_path == PathBuf::from("chain-profile.toml"))
            .unwrap();
        assert!(profile.contents.contains("slug = \"example-chain\""));
        assert!(profile
            .contents
            .contains("display_name = \"Example Chain\""));
        assert!(profile.contents.contains("curve = \"ed25519\""));
        assert!(profile
            .contents
            .contains("address_format = \"hex-with-custom-checksum\""));

        let derivation = plan
            .files
            .iter()
            .find(|file| file.relative_path == PathBuf::from("derivation-rules.toml"))
            .unwrap();
        assert!(derivation.contents.contains("coin_type = 777"));
        assert!(derivation.contents.contains("m/44'/777'/0'/0/0"));

        let mapping = plan
            .files
            .iter()
            .find(|file| file.relative_path == PathBuf::from("caip-mapping.toml"))
            .unwrap();
        assert!(mapping.contents.contains("namespace = \"example\""));
        assert!(mapping.contents.contains("reference = \"alpha\""));

        let sign_stub = plan
            .files
            .iter()
            .find(|file| file.relative_path == PathBuf::from("sign.stub.rs"))
            .unwrap();
        assert!(sign_stub.contents.contains("sign_message_example_chain"));

        let contributor_guide = plan
            .files
            .iter()
            .find(|file| file.relative_path == PathBuf::from("CONTRIBUTOR_GUIDE.md"))
            .unwrap();
        assert!(contributor_guide.contents.contains("example:alpha"));

        let tx_vectors = plan
            .files
            .iter()
            .find(|file| {
                file.relative_path == PathBuf::from("test-vectors").join("tx-serialization.json")
            })
            .unwrap();
        assert!(tx_vectors.contents.contains("\"canonical_encoding\""));
    }

    #[test]
    fn templates_include_practical_contributor_guidance() {
        let repo = make_repo_root();
        let plan = build_plan(repo.path(), &test_options()).unwrap();

        let readme = plan
            .files
            .iter()
            .find(|file| file.relative_path == PathBuf::from("README.md"))
            .unwrap();
        assert!(readme.contents.contains("docs/supported-chain-entry.md"));
        assert!(readme.contents.contains("test-vectors/sign-message.json"));
        assert!(readme
            .contents
            .contains("Closest existing OWS family baseline"));

        let contributor_guide = plan
            .files
            .iter()
            .find(|file| file.relative_path == PathBuf::from("CONTRIBUTOR_GUIDE.md"))
            .unwrap();
        assert!(contributor_guide
            .contents
            .contains("ows/crates/ows-core/src/chain.rs"));
        assert!(contributor_guide
            .contents
            .contains("ows/crates/ows-signer/src/chains/mod.rs"));
        assert!(contributor_guide
            .contents
            .contains("Closest existing OWS family baseline"));

        let caip_mapping = plan
            .files
            .iter()
            .find(|file| file.relative_path == PathBuf::from("caip-mapping.toml"))
            .unwrap();
        assert!(caip_mapping.contents.contains("[account_format_notes]"));
    }

    #[test]
    fn output_dot_is_rejected() {
        let repo = make_repo_root();
        let mut options = test_options();
        options.output = Some(Path::new("."));
        let error = build_plan(repo.path(), &options).unwrap_err();

        match error {
            CliError::InvalidArgs(message) => {
                assert!(
                    message.contains(".ows-dev\\chain-plugin-kit")
                        || message.contains(".ows-dev/chain-plugin-kit")
                );
            }
            other => panic!("expected InvalidArgs, got {other}"),
        }
    }

    #[test]
    fn protected_top_level_outputs_are_rejected() {
        let repo = make_repo_root();

        for output in [
            PathBuf::from("ows"),
            PathBuf::from("docs"),
            PathBuf::from(".git"),
            PathBuf::from(".ows-dev"),
            PathBuf::from(".ows-dev").join("chain-plugin-kit"),
        ] {
            let mut options = test_options();
            options.output = Some(output.as_path());
            let error = build_plan(repo.path(), &options).unwrap_err();

            match error {
                CliError::InvalidArgs(message) => {
                    assert!(
                        message.contains(".ows-dev\\chain-plugin-kit")
                            || message.contains(".ows-dev/chain-plugin-kit")
                    );
                }
                other => panic!("expected InvalidArgs, got {other}"),
            }
        }
    }

    #[test]
    fn output_path_cannot_escape_repo_root() {
        let repo = make_repo_root();
        let output = Path::new("..").join("outside");
        let mut options = test_options();
        options.output = Some(&output);
        let error = build_plan(repo.path(), &options).unwrap_err();

        match error {
            CliError::InvalidArgs(message) => {
                assert!(
                    message.contains(".ows-dev\\chain-plugin-kit")
                        || message.contains(".ows-dev/chain-plugin-kit")
                );
            }
            other => panic!("expected InvalidArgs, got {other}"),
        }
    }

    #[test]
    fn symlink_escape_outside_safe_output_area_is_rejected() {
        let repo = make_repo_root();
        let external = tempfile::tempdir().unwrap();
        let safe_base = repo.path().join(".ows-dev").join("chain-plugin-kit");
        fs::create_dir_all(&safe_base).unwrap();
        let link = safe_base.join("escape-link");
        create_dir_symlink(&link, external.path());

        let mut options = test_options();
        let output = PathBuf::from(".ows-dev")
            .join("chain-plugin-kit")
            .join("escape-link")
            .join("nested");
        options.output = Some(output.as_path());
        let error = build_plan(repo.path(), &options).unwrap_err();

        match error {
            CliError::InvalidArgs(message) => {
                assert!(message.contains("safe scaffold area") || message.contains("symlink"));
            }
            other => panic!("expected InvalidArgs, got {other}"),
        }
    }

    #[test]
    fn invalid_slug_is_rejected() {
        let repo = make_repo_root();
        let mut options = test_options();
        options.slug = "Bad_Slug";
        let error = build_plan(repo.path(), &options).unwrap_err();

        match error {
            CliError::InvalidArgs(message) => {
                assert!(message.contains("--slug"));
            }
            other => panic!("expected InvalidArgs, got {other}"),
        }
    }

    #[test]
    fn invalid_display_name_is_rejected() {
        let repo = make_repo_root();
        let mut options = test_options();
        options.display_name = Some("  ");
        let error = build_plan(repo.path(), &options).unwrap_err();

        match error {
            CliError::InvalidArgs(message) => {
                assert!(message.contains("--display-name"));
            }
            other => panic!("expected InvalidArgs, got {other}"),
        }
    }

    #[test]
    fn existing_target_requires_force() {
        let repo = make_repo_root();
        let target = repo
            .path()
            .join(".ows-dev")
            .join("chain-plugin-kit")
            .join("example-chain");
        fs::create_dir_all(&target).unwrap();

        let options = test_options();
        let error = build_plan(repo.path(), &options).unwrap_err();

        match error {
            CliError::InvalidArgs(message) => {
                assert!(message.contains("--force"));
            }
            other => panic!("expected InvalidArgs, got {other}"),
        }
    }

    #[test]
    fn existing_target_is_left_untouched_without_force() {
        let repo = make_repo_root();
        let target = repo
            .path()
            .join(".ows-dev")
            .join("chain-plugin-kit")
            .join("example-chain");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("stale.txt"), "keep-me").unwrap();

        let error = build_plan(repo.path(), &test_options()).unwrap_err();

        match error {
            CliError::InvalidArgs(message) => {
                assert!(message.contains("--force"));
            }
            other => panic!("expected InvalidArgs, got {other}"),
        }
        assert_eq!(
            fs::read_to_string(target.join("stale.txt")).unwrap(),
            "keep-me"
        );
    }

    #[test]
    fn force_replaces_existing_target_deterministically() {
        let repo = make_repo_root();
        let target = repo
            .path()
            .join(".ows-dev")
            .join("chain-plugin-kit")
            .join("example-chain");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("stale.txt"), "old").unwrap();

        let mut options = test_options();
        options.force = true;
        let plan = build_plan(repo.path(), &options).unwrap();
        write_plan(&plan, true).unwrap();

        assert!(!target.join("stale.txt").exists());
        assert!(target.join("README.md").exists());
        assert!(plan.target_exists);
        assert_eq!(
            collect_tree_entries(&plan.target_dir),
            expected_tree_entries()
        );
    }

    #[test]
    fn force_rejects_deleting_safe_base_root() {
        let repo = make_repo_root();
        let safe_base = repo.path().join(".ows-dev").join("chain-plugin-kit");
        fs::create_dir_all(&safe_base).unwrap();
        fs::write(safe_base.join("marker.txt"), "keep-me").unwrap();

        let mut options = test_options();
        let output = PathBuf::from(".ows-dev").join("chain-plugin-kit");
        options.output = Some(output.as_path());
        options.force = true;
        let error = build_plan(repo.path(), &options).unwrap_err();

        match error {
            CliError::InvalidArgs(message) => {
                assert!(
                    message.contains(".ows-dev\\chain-plugin-kit")
                        || message.contains(".ows-dev/chain-plugin-kit")
                );
            }
            other => panic!("expected InvalidArgs, got {other}"),
        }

        assert_eq!(
            fs::read_to_string(safe_base.join("marker.txt")).unwrap(),
            "keep-me"
        );
    }

    #[test]
    fn golden_path_aptos_scaffold_writes_expected_tree_and_contents() {
        let repo = make_repo_root();
        let options = ScaffoldChainOptions {
            slug: "aptos",
            family: ChainType::Sui,
            display_name: Some("Aptos"),
            curve: Some("ed25519"),
            address_format: Some("0x-prefixed hex account address"),
            coin_type: Some(637),
            derivation_path: Some("m/44'/637'/0'/0'/0'"),
            caip_namespace: Some("aptos"),
            caip_reference: Some("mainnet"),
            output: None,
            write: false,
            force: false,
        };
        let plan = build_plan(repo.path(), &options).unwrap();

        write_plan(&plan, false).unwrap();

        assert_eq!(
            collect_tree_entries(&plan.target_dir),
            expected_tree_entries()
        );

        let readme = fs::read_to_string(plan.target_dir.join("README.md")).unwrap();
        assert!(readme.contains("# Aptos Chain Plugin Kit"));
        assert!(readme.contains("docs/supported-chain-entry.md"));
        assert!(readme.contains("Closest existing OWS family baseline: `sui`"));

        let profile = fs::read_to_string(plan.target_dir.join("chain-profile.toml")).unwrap();
        assert!(profile.contains("slug = \"aptos\""));
        assert!(profile.contains("display_name = \"Aptos\""));
        assert!(profile.contains("family = \"sui\""));
        assert!(profile.contains("namespace = \"aptos\""));
        assert!(profile.contains("curve = \"ed25519\""));
        assert!(profile.contains("default_derivation_path = \"m/44'/637'/0'/0'/0'\""));

        let caip = fs::read_to_string(plan.target_dir.join("caip-mapping.toml")).unwrap();
        assert!(caip.contains("chain_id = \"aptos:mainnet\""));
        assert!(caip.contains("caip10_account_format = \"aptos:mainnet:TODO_ACCOUNT_ADDRESS\""));

        let derivation = fs::read_to_string(plan.target_dir.join("derivation-rules.toml")).unwrap();
        assert!(derivation.contains("coin_type = 637"));
        assert!(derivation.contains("account_0_change_0_index_0 = \"m/44'/637'/0'/0'/0'\""));

        let sign_stub = fs::read_to_string(plan.target_dir.join("sign.stub.rs")).unwrap();
        assert!(sign_stub.contains("pub fn sign_message_aptos"));

        let serialize_stub = fs::read_to_string(plan.target_dir.join("serialize.stub.rs")).unwrap();
        assert!(serialize_stub.contains("TODO(canonical-encoding)"));

        let docs = fs::read_to_string(
            plan.target_dir
                .join("docs")
                .join("supported-chain-entry.md"),
        )
        .unwrap();
        assert!(docs.contains("Canonical chain id: `aptos:mainnet`"));
        assert!(docs.contains("Scaffold family baseline: `sui`"));

        let vectors = fs::read_to_string(
            plan.target_dir
                .join("test-vectors")
                .join("sign-message.json"),
        )
        .unwrap();
        assert!(vectors.contains("\"chain_id\": \"aptos:mainnet\""));
        assert!(vectors.contains("\"domain_separation\": \"TODO\""));
    }

    #[test]
    fn toml_templates_escape_quotes_and_backslashes() {
        let repo = make_repo_root();
        let options = ScaffoldChainOptions {
            slug: "example-chain",
            family: ChainType::Evm,
            display_name: Some("Foo \"Bar\" \\\\ Name"),
            curve: None,
            address_format: Some("Backslash \\\\ Format"),
            coin_type: None,
            derivation_path: Some("m/44'/60'/0'/0/0"),
            caip_namespace: Some("example"),
            caip_reference: Some("alpha\"beta"),
            output: None,
            write: false,
            force: false,
        };
        let plan = build_plan(repo.path(), &options).unwrap();

        let profile = plan
            .files
            .iter()
            .find(|file| file.relative_path == PathBuf::from("chain-profile.toml"))
            .unwrap();
        assert!(profile
            .contents
            .contains("display_name = \"Foo \\\"Bar\\\" \\\\\\\\ Name\""));
        assert!(profile
            .contents
            .contains("address_format = \"Backslash \\\\\\\\ Format\""));

        let caip = plan
            .files
            .iter()
            .find(|file| file.relative_path == PathBuf::from("caip-mapping.toml"))
            .unwrap();
        assert!(caip.contents.contains("reference = \"alpha\\\"beta\""));
    }

    #[test]
    fn rust_string_literals_escape_quotes_and_backslashes() {
        let repo = make_repo_root();
        let options = ScaffoldChainOptions {
            slug: "example-chain",
            family: ChainType::Evm,
            display_name: Some("Foo \"Bar\" \\\\ Name"),
            curve: None,
            address_format: None,
            coin_type: None,
            derivation_path: None,
            caip_namespace: None,
            caip_reference: None,
            output: None,
            write: false,
            force: false,
        };
        let plan = build_plan(repo.path(), &options).unwrap();

        let sign_stub = plan
            .files
            .iter()
            .find(|file| file.relative_path == PathBuf::from("sign.stub.rs"))
            .unwrap();
        assert!(sign_stub.contents.contains(
            "\"TODO(hash): define raw signing behavior for Foo \\\"Bar\\\" \\\\\\\\ Name\""
        ));

        let serialize_stub = plan
            .files
            .iter()
            .find(|file| file.relative_path == PathBuf::from("serialize.stub.rs"))
            .unwrap();
        assert!(serialize_stub.contents.contains(
            "\"TODO(canonical-encoding): decide how Foo \\\"Bar\\\" \\\\\\\\ Name derives signable bytes\""
        ));
    }
}
