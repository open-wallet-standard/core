//! An in-process stand-in for a Midnight proof server, for authorize tests: it answers `/check` and
//! `/prove` on a loopback port as the real server does, with a proof of the right size that does not
//! verify, for the builtin circuits. A vault whose config names it as the network's `:prover` lets a
//! test run a whole authorize, DUST spends included, with no proving keys and no network.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;

use midnight_ledger::structure::{ProofPreimageVersioned, ProofVersioned};
use midnight_serialize::{tagged_deserialize, tagged_serialize};
use transient_crypto::curve::Fr;
use transient_crypto::proofs::{Proof, ProvingKeyMaterial};

/// Start the mock and return its base URL, to set as `rpc["{chain_id}:prover"]`.
pub(crate) fn spawn() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let _ = serve(conn);
        }
    });
    url
}

/// A vault of its own under the system temp dir whose config names a fresh mock as `chain_id`'s
/// prover, and as its indexer a loopback port nothing listens on, so a test that authorizes against
/// it fails if authorizing syncs anything.
pub(crate) fn vault(chain_id: &str, name: &str) -> std::path::PathBuf {
    let vault =
        std::env::temp_dir().join(format!("ows-midnight-prover-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&vault);
    std::fs::create_dir_all(&vault).expect("vault dir");
    let mut rpc = serde_json::Map::new();
    rpc.insert(
        chain_id.to_string(),
        "http://127.0.0.1:1/api/v4/graphql".into(),
    );
    rpc.insert(format!("{chain_id}:prover"), spawn().into());
    let config = serde_json::json!({ "vault_path": "/ignored", "rpc": rpc });
    std::fs::write(vault.join("config.json"), config.to_string()).expect("config");
    vault
}

fn serve(conn: TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(conn);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let path = request_line.split_whitespace().nth(1).unwrap_or_default();
    let path = path.split('?').next().unwrap_or_default().to_string();
    let mut content_length = 0;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        if header.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;

    let mut reply = Vec::new();
    match path.as_str() {
        "/check" => tagged_serialize(&Vec::<Option<u64>>::new(), &mut reply)?,
        "/prove" => {
            let (preimage, _keys, _binding): (
                ProofPreimageVersioned,
                Option<ProvingKeyMaterial>,
                Option<Fr>,
            ) = tagged_deserialize(&mut body.as_slice())?;
            let ProofPreimageVersioned::V2(preimage) = preimage else {
                return respond(reader.get_mut(), 400, b"unsupported preimage version");
            };
            let size = match preimage.key_location.0.as_ref() {
                "midnight/zswap/spend" => midnight_zswap::INPUT_PROOF_SIZE,
                "midnight/zswap/output" => midnight_zswap::OUTPUT_PROOF_SIZE,
                "midnight/dust/spend" => midnight_ledger::dust::DUST_SPEND_PROOF_SIZE,
                other => return respond(reader.get_mut(), 400, other.as_bytes()),
            };
            tagged_serialize(&ProofVersioned::V2(Proof(vec![0xde; size])), &mut reply)?;
        }
        other => return respond(reader.get_mut(), 404, other.as_bytes()),
    }
    respond(reader.get_mut(), 200, &reply)
}

fn respond(conn: &mut TcpStream, status: u16, body: &[u8]) -> std::io::Result<()> {
    write!(
        conn,
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    conn.write_all(body)
}
