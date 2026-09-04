/**
 * rubric-notary — prove a record existed, unaltered, at a point in time.
 *
 * WHAT THIS PROVES: a record with this exact content existed no later than the
 * anchored timestamp, and has not been altered since.
 *
 * WHAT IT DOES NOT PROVE: that the record is true, that the event it describes
 * happened, or that the issuer is who they say. Notarizing a lie produces a
 * timestamped lie. This is a notary, not an auditor.
 */
import { createHash } from "node:crypto";

const ATTEST_KEY_URL = "https://rubric-protocol.com/v1/tiered-attest";
const ATTEST_X402_URL = "https://rubric-protocol.com/v1/x402/tiered-attest";
const VERIFY_URL = "https://rubric-protocol.com/v1/verify";

const PROVES = "A record with this exact content existed no later than the anchored timestamp and has not been altered since. Verifiable by anyone, without Rubric or the issuer.";
const NOT_PROVES = "Not that the record is true, not that the described event occurred, and not the identity of the issuer. Notarizing a false record produces a timestamped false record.";

export interface NotaryProof {
  attestationId: string;
  recordHash: string;
  label: string | null;
  notarizedAt: string;
  hashAlgorithm: "sha3-256";
  canonicalization: "sorted-keys-json";
  verifyUrl: string;
}

export interface PaymentRequired {
  paymentRequired: true;
  recordHash: string;
  challenge: any;
  how: string;
}

export interface VerifyResult {
  recordMatches?: boolean;
  anchored: boolean;
  found: boolean;
  status?: string;
  hcsSequence?: number | null;
  anchoredAt?: string | null;
  hcsExplorerUrl?: string | null;
  /** True once anchored on consensus. Pending immediately after notarizing. */
  valid: boolean;
  /** Signed but not yet flushed to the chain. Re-verify in a minute. */
  pending?: boolean;
  proves: string;
  doesNotProve: string;
}

/** Deterministic serialization: recursive key sort, no whitespace. Throws on
 *  anything that cannot be represented deterministically. */
export function canonicalize(value: unknown): string {
  const seen = new WeakSet<object>();
  const walk = (v: unknown): unknown => {
    if (v === null) return null;
    const t = typeof v;
    if (t === "number") {
      if (!Number.isFinite(v as number)) throw new Error("cannot canonicalize non-finite number");
      return v;
    }
    if (t === "string" || t === "boolean") return v;
    if (t === "undefined") throw new Error("cannot canonicalize undefined (remove the key instead)");
    if (t === "function" || t === "symbol" || t === "bigint") throw new Error("cannot canonicalize " + t);
    if (Array.isArray(v)) return v.map(walk);
    if (t === "object") {
      const o = v as Record<string, unknown>;
      if (seen.has(o)) throw new Error("cannot canonicalize circular reference");
      seen.add(o);
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(o).sort()) out[k] = walk(o[k]);
      return out;
    }
    throw new Error("cannot canonicalize value of type " + t);
  };
  return JSON.stringify(walk(value));
}

/** SHA3-256 of the canonical form, hex, lowercase. */
export function hashRecord(record: unknown): string {
  return createHash("sha3-256").update(canonicalize(record), "utf8").digest("hex");
}

function mkProof(attestationId: string, recordHash: string, label: string | null, notarizedAt: string): NotaryProof {
  return { attestationId, recordHash, label, notarizedAt,
           hashAlgorithm: "sha3-256", canonicalization: "sorted-keys-json",
           verifyUrl: VERIFY_URL + "/" + attestationId };
}

/** Notarize a record. Returns a proof file to keep alongside the record. */
export async function notarize(
  record: unknown,
  opts: { apiKey?: string; payment?: string; label?: string } = {}
): Promise<NotaryProof | PaymentRequired> {
  const recordHash = hashRecord(record);
  const notarizedAt = new Date().toISOString();
  const body = JSON.stringify({
    agentId: "rubric-notary",
    sourceId: "notary-" + recordHash.slice(0, 16),
    decision: opts.label || "notarized-record",
    data: { recordHash, label: opts.label ?? null, notarizedAt,
            hashAlgorithm: "sha3-256", canonicalization: "sorted-keys-json" },
  });

  if (opts.apiKey) {
    const r = await fetch(ATTEST_KEY_URL, { method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": opts.apiKey }, body });
    const j: any = await r.json().catch(() => ({}));
    if (!j.attestationId) throw new Error("notarize failed: " + r.status + " " + JSON.stringify(j).slice(0, 200));
    return mkProof(j.attestationId, recordHash, opts.label ?? null, notarizedAt);
  }

  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (opts.payment) { headers["PAYMENT-SIGNATURE"] = opts.payment; headers["X-PAYMENT"] = opts.payment; }
  const r = await fetch(ATTEST_X402_URL, { method: "POST", headers, body });
  const j: any = await r.json().catch(() => ({}));
  if (r.status === 200 && j.attestationId) {
    return mkProof(j.attestationId, recordHash, opts.label ?? null, notarizedAt);
  }
  return { paymentRequired: true, recordHash, challenge: j,
           how: "Sign this x402 payment (half a cent USDC on Base) and call notarize again with { payment }. No account required." };
}

/** Verify. Free, unauthenticated, forever. Offline: does the record hash match
 *  the proof. Online: is the attestation anchored. */
export async function verify(proof: NotaryProof, record?: unknown): Promise<VerifyResult> {
  const recordMatches = record === undefined ? undefined : hashRecord(record) === proof.recordHash;
  let found = false, anchored = false, status: string | undefined;
  let hcsSequence: number | null = null, anchoredAt: string | null = null, hcsExplorerUrl: string | null = null;
  try {
    const r = await fetch(VERIFY_URL + "/" + encodeURIComponent(proof.attestationId));
    const j: any = await r.json().catch(() => ({}));
    found = !!j.found;
    status = j.status;
    anchored = j.status === "anchored" && j.verified === true;
    hcsSequence = j.hcsSequence ?? j.sequenceNumber ?? null;
    anchoredAt = j?.attestation?.issued_at ?? null;
    hcsExplorerUrl = j.hcsExplorerUrl ?? null;
  } catch { /* leaves anchored=false; caller sees valid=false */ }
  const pending = found && !anchored && (status || '').includes('pending');
  return { recordMatches, anchored, found, status, hcsSequence, anchoredAt, hcsExplorerUrl,
           valid: anchored && (recordMatches !== false), pending: pending || undefined,
           proves: PROVES, doesNotProve: NOT_PROVES };
}
