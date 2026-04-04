/**
 * EIP-2612 permit signing helper for OWS.
 * Handles token metadata resolution, nonce fetching, and EIP-712 typed data
 * construction automatically.
 *
 * @see https://eips.ethereum.org/EIPS/eip-2612
 */

const DOMAIN_OVERRIDES = {
  "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": { version: "2" },
  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": { version: "2" },
  "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359": { version: "2" },
  "0xaf88d065e77c8cc2239327c5edb3a432268e5831": { version: "2" },
  "0x0b2c639c533813f4aa9d7837caf62653d097ff85": { version: "2" },
  "0x6b175474e89094c44da98b954eedeac495271d0f": { version: "1" },
  "0xfde4c96c8593536e31f229ea8f37b2ada2699bb2": { version: "1" },
};

const SELECTORS = {
  name:         "0x06fdde03",
  nonces:       "0x7ecebe00",
  eip712Domain: "0x84b0196e",
};

const DEFAULT_RPCS = {
  1:     "https://eth.llamarpc.com",
  8453:  "https://mainnet.base.org",
  137:   "https://polygon-rpc.com",
  42161: "https://arb1.arbitrum.io/rpc",
  10:    "https://mainnet.optimism.io",
};

async function ethCall(rpcUrl, to, data) {
  const res = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0", id: 1,
      method: "eth_call",
      params: [{ to, data }, "latest"],
    }),
  });
  if (!res.ok) throw new Error(`RPC request failed: ${res.status}`);
  const json = await res.json();
  if (json.error) throw new Error(`eth_call error: ${json.error.message}`);
  return json.result ?? "0x";
}

function encodeAddressArg(address) {
  return address.toLowerCase().replace("0x", "").padStart(64, "0");
}

function decodeString(hex) {
  const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (raw.length < 128) return "";
  const length = parseInt(raw.slice(64, 128), 16);
  const dataHex = raw.slice(128, 128 + length * 2);
  return Buffer.from(dataHex, "hex").toString("utf8");
}

function decodeUint256(hex) {
  const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
  return BigInt("0x" + (raw || "0"));
}

async function resolveDomain(rpcUrl, tokenAddress, chainId) {
  const lower = tokenAddress.toLowerCase();

  try {
    const raw = await ethCall(rpcUrl, tokenAddress, SELECTORS.eip712Domain);
    const stripped = raw.startsWith("0x") ? raw.slice(2) : raw;
    if (stripped.length > 64) {
      const words = stripped.match(/.{1,64}/g) ?? [];
      const nameOffset    = parseInt(words[1] ?? "0", 16) / 32;
      const versionOffset = parseInt(words[2] ?? "0", 16) / 32;
      const domainChainId = parseInt(words[3] ?? "0", 16);

      const nameLength   = parseInt(words[nameOffset] ?? "0", 16);
      const nameData     = words.slice(nameOffset + 1).join("").slice(0, nameLength * 2);
      const resolvedName = Buffer.from(nameData, "hex").toString("utf8");

      const versionLength   = parseInt(words[versionOffset] ?? "0", 16);
      const versionData     = words.slice(versionOffset + 1).join("").slice(0, versionLength * 2);
      const resolvedVersion = Buffer.from(versionData, "hex").toString("utf8");

      if (resolvedName) {
        return {
          name: resolvedName,
          version: resolvedVersion || undefined,
          chainId: domainChainId || chainId,
          verifyingContract: tokenAddress,
        };
      }
    }
  } catch { /* eip712Domain() not supported */ }

  const override  = DOMAIN_OVERRIDES[lower];
  const nameHex   = await ethCall(rpcUrl, tokenAddress, SELECTORS.name);
  const tokenName = decodeString(nameHex);

  if (!tokenName) {
    throw new Error(
      `Could not resolve EIP-712 domain for token ${tokenAddress}. ` +
      `Ensure the token implements name() or eip712Domain(), or pass rpcUrl.`
    );
  }

  return {
    name: tokenName,
    version: override?.omitVersion ? undefined : (override?.version ?? "1"),
    chainId,
    verifyingContract: tokenAddress,
  };
}

function buildTypedData(domain, owner, spender, value, nonce, deadline) {
  const domainFields = [
    { name: "name", type: "string" },
    ...(domain.version !== undefined ? [{ name: "version", type: "string" }] : []),
    { name: "chainId", type: "uint256" },
    { name: "verifyingContract", type: "address" },
  ];

  return {
    types: {
      EIP712Domain: domainFields,
      Permit: [
        { name: "owner",    type: "address" },
        { name: "spender",  type: "address" },
        { name: "value",    type: "uint256" },
        { name: "nonce",    type: "uint256" },
        { name: "deadline", type: "uint256" },
      ],
    },
    primaryType: "Permit",
    domain: {
      name: domain.name,
      ...(domain.version !== undefined && { version: domain.version }),
      chainId: domain.chainId,
      verifyingContract: domain.verifyingContract,
    },
    message: { owner, spender, value, nonce, deadline },
  };
}

/**
 * Signs an EIP-2612 permit for an ERC-20 token.
 *
 * @param {string}   ownerAddress  - Token owner address (from OWS wallet)
 * @param {string}   chainId       - CAIP-2 chain ID, e.g. "eip155:8453"
 * @param {object}   params        - { token, spender, value, deadline, nonce?, rpcUrl? }
 * @param {Function} signTypedData - OWS signTypedData(typedDataJson) => Promise<hexSig>
 * @returns {Promise<{ signature, v, r, s, typedData }>}
 *
 * @example
 * const sig = await signPermit(ownerAddress, "eip155:8453", {
 *   token:    "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
 *   spender:  "0xYourProtocol",
 *   value:    "1000000",
 *   deadline: Math.floor(Date.now() / 1000) + 3600,
 * }, owsSignTypedData);
 */
export async function signPermit(ownerAddress, chainId, params, signTypedData) {
  const { token, spender, value, deadline } = params;
  const numericChainId = parseInt(chainId.split(":")[1] ?? "1", 10);
  const rpcUrl = params.rpcUrl ?? DEFAULT_RPCS[numericChainId];

  if (!rpcUrl) {
    throw new Error(
      `No default RPC configured for chain ${numericChainId}. Pass rpcUrl in params.`
    );
  }

  let nonce = params.nonce;
  if (nonce === undefined) {
    const nonceData = SELECTORS.nonces + encodeAddressArg(ownerAddress);
    const nonceHex  = await ethCall(rpcUrl, token, nonceData);
    nonce = Number(decodeUint256(nonceHex));
  }

  const domain       = await resolveDomain(rpcUrl, token, numericChainId);
  const typedData    = buildTypedData(domain, ownerAddress, spender, value, nonce, deadline);
  const rawSignature = await signTypedData(JSON.stringify(typedData));

  const sig = rawSignature.startsWith("0x") ? rawSignature.slice(2) : rawSignature;
  const r   = "0x" + sig.slice(0, 64);
  const s   = "0x" + sig.slice(64, 128);
  const v   = parseInt(sig.slice(128, 130), 16);

  return { signature: "0x" + sig, v, r, s, typedData };
}
