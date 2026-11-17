# Witness Builder

A teaching tool for the zkVerify Agent Games **GatekeeperEvaluation** circuit:
paste gatekeeper task fields, get the 13-input witness JSON in circuit order,
see the five on-circuit checks evaluated, and preview the Poseidon
`publicSignals` layout — with copyable output.

## Honest scope

This tool builds witness JSON and validates inputs. It does **NOT** generate
proofs, it does not verify proofs, and the `publicSignals` preview proves
nothing by itself. A real proof still needs the official circuit artifacts
and a prover (e.g. `snarkjs.groth16.fullProve`). Nothing here signs, reads
the chain, persists data, or makes external calls; inputs are processed in
memory and never stored.

## What it does

- **Witness JSON** — the 13 circuit inputs in order, as decimal strings:
  `registeredVkHash`, `proofVkHash`, `minimum`, `publicBalance`,
  `expiryBlock`, `currentBlock`, `recipient`, `conditionRecipient`,
  `amount`, `maxTransfer`, `decision`, `taskId`, `salt`. This is the shape
  `snarkjs.groth16.fullProve` accepts as circuit input.
- **Field parsing, exactly like the circuit** — hex fields (vk hashes,
  recipients) accept an optional `0x` prefix, any case, and leading zeros,
  and are reduced mod p (BN128 scalar field prime), so different spellings
  of the same value compare equal. Decimal fields must be non-negative
  integers; values ≥ p are flagged as unprovable rather than silently
  wrapped.
- **The five on-circuit checks** — vk match, threshold
  (`publicBalance >= minimum`), **strict** expiry
  (`currentBlock < expiryBlock`; equality is EXPIRED), recipient match,
  and amount (`amount <= maxTransfer`). APPROVE (decision `1`) only when
  all five pass; otherwise REJECT (`0`) with the first failing reason code
  in circuit order.
- **taskId mapping** — a UUID substring maps to its 128-bit integer; else a
  bare 32-hex value maps directly; else `0x`-hex reduces mod p; anything
  else falls back to SHA-256 of the UTF-8 string, mod p.
- **Salt** — leave blank for a fresh random salt (31 random bytes, always
  below 2^248), or supply your own decimal.
- **publicSignals preview** — 13 signals: `Poseidon(salt, taskId)` first
  (computed with circomlibjs), then the 12 inputs in order minus salt.
  This layout was verified empirically by running the official circuit
  artifacts through `snarkjs.groth16.fullProve` and comparing every signal.
- **Proof-reuse is deliberately not checked** — replay detection is
  off-circuit state (a seen-set), not part of the witness decision, so the
  tool says so instead of pretending to check it.
- **7 bundled examples**, all invented values: valid approval, expiry at
  the boundary, amount overflow, VK substitution, threshold mismatch,
  recipient mismatch, and hex spelling variants.

## Run

```sh
npm install
npm start        # listens on $PORT (default 3000)
npm test         # 52 tests: parsers, mapping, checks, witness, signals, HTTP
```

## Endpoints

- `GET /` — the UI.
- `GET /health`, `GET /api/health` — `{ ok: true, service, version }`.
- `GET /api/examples` — the bundled examples.
- `POST /api/build` — JSON task fields in, `{ witness, publicSignals,
  publicSignalsLayout, checks, decision, reason_code, warnings, note }`
  out. Body cap 64 KB.

## Stack

Node.js ≥ 20, zero-framework HTTP server (Node built-ins), one dependency
(circomlibjs, for Poseidon). Deploys on Vercel's free Hobby tier:
`server.js` default-exports the server (Vercel Node runtime) and also
listens on `$PORT` when run directly.

## License

MIT.
