# rubric-notary

Prove a record existed, unaltered, at a point in time. Anchored to public consensus. Free to verify, forever, by anyone.

    import { notarize, verify } from "rubric-notary";

    const proof = await notarize(myRecord, { apiKey });   // keep this proof file
    // ... later, in a dispute ...
    const result = await verify(proof, myRecord);
    // result.valid === true  ->  this exact record existed by result.anchoredAt

## What this proves, and what it does not

Proves: a record with this exact content existed no later than the anchored timestamp, and has not been altered since. Anyone can check this without Rubric's cooperation or yours.

Does not prove: that the record is true, that the event it describes happened, or that you are who you say. Notarizing a false record produces a timestamped false record. This is a notary, not an auditor.

## How verification works

The chain stores a cryptographic commitment, never your record. Verification has two independent halves:

Offline - your record is hashed and compared to the hash in your proof file. No network, no permission.

Online - the attestation is checked against Hedera consensus, confirming when it was anchored.

Both passing means the record you hold is the record that was notarized, at that time. Keep the proof file with the record; Rubric cannot reconstruct either one for you.

Immediately after notarizing, verify returns pending: the record is signed but not yet flushed to the chain. It anchors within about a minute.

## Paying

With a Rubric API key, notarize anchors immediately. Without one it returns an x402 payment challenge: sign it with any wallet, call again with the payment, no account required. Half a cent per record.

Verification is always free and never requires credentials. A proof only the issuer can check is not a proof.

## CLI

    npx rubric-notary hash record.json
    npx rubric-notary sign record.json --label consent --out proof.json
    npx rubric-notary verify proof.json record.json

Exit codes: 3 payment required, 4 record does not match, 5 attestation not found.

## Canonicalization

Two parties must produce identical bytes for the same logical record or verification is meaningless. The rule is fixed and reimplementable: recursive key sort, JSON.stringify with no whitespace, JavaScript number formatting, then SHA3-256, hex, lowercase.

Rejected rather than silently coerced: undefined, functions, symbols, bigint, non-finite numbers, circular references. Note that 1 and 1.0 collapse, as they do in JSON.

canonicalize and hashRecord are exported so you can check this yourself.

## License

MIT (c) Echelon Intelligence Group LLC
