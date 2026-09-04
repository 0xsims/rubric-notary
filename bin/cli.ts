#!/usr/bin/env node
/** rubric-notary CLI — sign, verify, hash. */
import { readFileSync, writeFileSync } from "node:fs";
import { notarize, verify, hashRecord, canonicalize } from "../src/index.js";

const args = process.argv.slice(2);
const cmd = args[0];
const flag = (n: string) => { const i = args.indexOf("--" + n); return i > -1 ? args[i + 1] : undefined; };
const has = (n: string) => args.includes("--" + n);

function readJson(p: string) {
  try { return JSON.parse(readFileSync(p, "utf8")); }
  catch (e: any) { console.error("cannot read JSON from " + p + ": " + e.message); process.exit(2); }
}

const usage = `rubric-notary - prove a record existed, unaltered, at a point in time.

  rubric-notary hash <file.json>
      Print the canonical SHA3-256 hash. No network, no account.

  rubric-notary sign <file.json> [--label "..."] [--key KEY] [--payment PROOF] [--out proof.json]
      Anchor the record's hash. With --key anchors immediately; without, prints
      the x402 payment challenge (half a cent, no account).

  rubric-notary verify <proof.json> [record.json]
      Check a proof. Always free, no credentials. Supply the record to confirm
      it is the one that was anchored.

Proves the record existed unaltered at that time. Does NOT prove it is true.`;

(async () => {
  if (!cmd || cmd === "help" || has("help")) { console.log(usage); process.exit(0); }

  if (cmd === "hash") {
    const rec = readJson(args[1]);
    console.log(hashRecord(rec));
    if (has("canonical")) console.error(canonicalize(rec));
    return;
  }

  if (cmd === "sign") {
    const rec = readJson(args[1]);
    const res: any = await notarize(rec, {
      apiKey: flag("key") ?? process.env.RUBRIC_API_KEY,
      payment: flag("payment"),
      label: flag("label"),
    });
    if (res.paymentRequired) {
      const a = res.challenge?.accepts?.[0] ?? {};
      console.log(JSON.stringify({ paymentRequired: true, recordHash: res.recordHash,
        cost: "$0.005 USDC", payTo: a.payTo, amount: a.amount, network: a.network,
        asset: a.asset, how: res.how }, null, 2));
      process.exit(3);
    }
    const out = flag("out");
    if (out) { writeFileSync(out, JSON.stringify(res, null, 2)); console.error("proof written to " + out); }
    console.log(JSON.stringify(res, null, 2));
    return;
  }

  if (cmd === "verify") {
    const proof = readJson(args[1]);
    const rec = args[2] ? readJson(args[2]) : undefined;
    const res = await verify(proof, rec);
    console.log(JSON.stringify(res, null, 2));
    if (rec !== undefined && res.recordMatches !== true) {
      console.error("\nRECORD DOES NOT MATCH THE ANCHORED HASH");
      process.exit(4);
    }
    if (!res.found) process.exit(5);
    return;
  }

  console.error(usage); process.exit(2);
})().catch((e) => { console.error("error:", e.message); process.exit(1); });
