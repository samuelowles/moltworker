#!/usr/bin/env node

const { ethers } = require("ethers");
const https = require("https");
const readline = require("readline");

const CHAIN_ID = 137;

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
function ask(q) { return new Promise((r) => rl.question(q, r)); }

function httpRequest(method, path, body = null) {
    return new Promise((resolve, reject) => {
        const bodyStr = body ? JSON.stringify(body) : "";
        const options = {
            hostname: "clob.polymarket.com",
            port: 443,
            path,
            method,
            headers: { "Content-Type": "application/json" },
        };
        const req = https.request(options, (res) => {
            let data = "";
            res.on("data", (chunk) => (data += chunk));
            res.on("end", () => {
                try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
                catch { resolve({ status: res.statusCode, body: data }); }
            });
        });
        req.on("error", reject);
        if (bodyStr) req.write(bodyStr);
        req.end();
    });
}

async function main() {
    console.log("═══════════════════════════════════════════════════════");
    console.log("  Polymarket CLOB API Key Generator");
    console.log("  Your key never leaves this machine.");
    console.log("═══════════════════════════════════════════════════════\n");

    const privateKey = await ask("Paste your Polymarket private key (0x...): ");
    if (!privateKey.startsWith("0x") || privateKey.length < 64) {
        console.error("Invalid private key format.");
        process.exit(1);
    }

    const wallet = new ethers.Wallet(privateKey);
    console.log(`\nWallet address: ${wallet.address}`);

    // Sign EIP-712 ClobAuth message
    console.log("\n[1/2] Signing authentication message...");
    const timestamp = Math.floor(Date.now() / 1000);

    const domain = {
        name: "ClobAuthDomain",
        version: "1",
        chainId: CHAIN_ID,
    };
    const types = {
        ClobAuth: [
            { name: "address", type: "address" },
            { name: "timestamp", type: "string" },
            { name: "nonce", type: "uint256" },
            { name: "message", type: "string" },
        ],
    };
    const value = {
        address: wallet.address,
        timestamp: timestamp.toString(),
        nonce: 0,
        message: "This message attests that I control the given wallet",
    };

    const signature = await wallet.signTypedData(domain, types, value);
    console.log("  Message signed.");

    // Derive API key via POST /auth/derive-api-key
    console.log("[2/2] Deriving CLOB API credentials...\n");
    const resp = await httpRequest("POST", "/auth/derive-api-key", {
        address: wallet.address,
        signature,
        timestamp: timestamp.toString(),
        nonce: "0",
        message: value.message,
    });

    if (resp.status !== 200 && resp.status !== 201) {
        console.error(`Failed (HTTP ${resp.status}):`, JSON.stringify(resp.body, null, 2));
        console.error("\n── Alternative: Generate keys manually at:");
        console.error("   https://polymarket.com/settings?tab=builder");
        console.error("   Click '+ Create New' under Builder Keys.\n");
        rl.close();
        process.exit(1);
    }

    const creds = resp.body;

    console.log("═══════════════════════════════════════════════════════");
    console.log("  ✅ CLOB API Credentials Generated!");
    console.log("═══════════════════════════════════════════════════════");
    console.log(`  API Key:      ${creds.apiKey}`);
    console.log(`  Secret:       ${creds.secret}`);
    console.log(`  Passphrase:   ${creds.passphrase}`);
    console.log("═══════════════════════════════════════════════════════");
    console.log("\nPaste these into your Cloudflare dashboard as:");
    console.log("  POLYMARKET_CLOB_API_KEY        → API Key");
    console.log("  POLYMARKET_CLOB_API_SECRET     → Secret");
    console.log("  POLYMARKET_CLOB_API_PASSPHRASE → Passphrase");
    console.log("═══════════════════════════════════════════════════════");

    rl.close();
}

main().catch((e) => { console.error(e); process.exit(1); });
