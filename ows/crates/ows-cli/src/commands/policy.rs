use crate::CliError;

/// Register a policy from a JSON file.
pub fn create(file: &str) -> Result<(), CliError> {
    let contents = std::fs::read_to_string(file)
        .map_err(|e| CliError::InvalidArgs(format!("failed to read policy file '{file}': {e}")))?;

    let policy: ows_core::Policy = serde_json::from_str(&contents)
        .map_err(|e| CliError::InvalidArgs(format!("invalid policy JSON: {e}")))?;

    ows_lib::policy_store::save_policy(&policy, None)?;

    println!("Policy registered: {}", policy.id);
    println!("Name:              {}", policy.name);
    println!("Rules:             {}", policy.rules.len());
    if let Some(ref exe) = policy.executable {
        println!("Executable:        {exe}");
    }
    Ok(())
}

/// List all registered policies.
pub fn list() -> Result<(), CliError> {
    let policies = ows_lib::policy_store::list_policies(None)?;

    if policies.is_empty() {
        println!("No policies found.");
        return Ok(());
    }

    for p in &policies {
        println!("ID:      {}", p.id);
        println!("Name:    {}", p.name);
        println!("Version: {}", p.version);
        println!("Rules:   {}", p.rules.len());
        if let Some(ref exe) = p.executable {
            println!("Exec:    {exe}");
        }
        println!();
    }

    Ok(())
}

/// Show detailed information about a policy.
pub fn show(id: &str) -> Result<(), CliError> {
    let policy = ows_lib::policy_store::load_policy(id, None)?;

    println!("ID:         {}", policy.id);
    println!("Name:       {}", policy.name);
    println!("Version:    {}", policy.version);
    println!("Created:    {}", policy.created_at);
    println!("Action:     {:?}", policy.action);
    println!();

    if policy.rules.is_empty() {
        println!("Rules:      (none)");
    } else {
        println!("Rules:");
        for rule in &policy.rules {
            let desc = match rule {
                ows_core::PolicyRule::AllowedChains { chain_ids } => {
                    format!("  allowed_chains: {}", chain_ids.join(", "))
                }
                ows_core::PolicyRule::ExpiresAt { timestamp } => {
                    format!("  expires_at: {timestamp}")
                }
                ows_core::PolicyRule::AllowedTypedDataContracts { contracts } => {
                    format!("  allowed_typed_data_contracts: {}", contracts.join(", "))
                }
            };
            println!("{desc}");
        }
    }

    if let Some(ref exe) = policy.executable {
        println!();
        println!("Executable: {exe}");
    }
    if let Some(ref cfg) = policy.config {
        println!("Config:     {cfg}");
    }

    Ok(())
}

/// Delete a policy by ID.
pub fn delete(id: &str, confirm: bool) -> Result<(), CliError> {
    if !confirm {
        eprintln!("To delete a policy, pass --confirm.");
        return Err(CliError::InvalidArgs(
            "--confirm is required to delete a policy".into(),
        ));
    }

    let policy = ows_lib::policy_store::load_policy(id, None)?;
    ows_lib::policy_store::delete_policy(id, None)?;

    println!("Policy deleted: {} ({})", policy.id, policy.name);
    Ok(())
}
