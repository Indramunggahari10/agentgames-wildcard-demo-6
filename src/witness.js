// Witness Builder — pure logic for the GatekeeperEvaluation witness layout.
//
// Ground truth: the gatekeeper agent's own parsers (fields.ts), decision
// logic (decide.ts), and prover input construction (prover.ts), plus an
// empirical check: a real snarkjs fullProve with the OFFICIAL circuit
// artifacts confirmed publicSignals = [Poseidon(salt, taskId), then the 12
// inputs in order minus salt]. This module builds witness JSON and validates
// inputs only. It never generates proofs.
import { createHash, randomBytes } from "node:crypto";

// BN128 scalar field prime.
export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// The 13 circuit inputs, in circuit order.
export const WITNESS_KEYS = [
  "registeredVkHash",
  "proofVkHash",
  "minimum",
  "publicBalance",
  "expiryBlock",
  "currentBlock",
  "recipient",
  "conditionRecipient",
  "amount",
  "maxTransfer",
  "decision",
  "taskId",
  "salt",
];

// The 12 public inputs after the Poseidon binding, in order.
export const PUBLIC_INPUT_KEYS = WITNESS_KEYS.slice(0, 12);

// Reason codes in circuit-check order. PROOF_REUSED is deliberately absent:
// replay detection is off-circuit state (a seen-set), not part of the witness.
export const REASON_CODES = [
  "VALID_CONDITION",
  "VK_SUBSTITUTION",
  "THRESHOLD_MISMATCH",
  "EXPIRED_CONDITION",
  "RECIPIENT_MISMATCH",
  "AMOUNT_OVERFLOW",
];

/**
 * Parse a hex field element (vk hashes, recipients): optional 0x prefix,
 * any case, leading zeros allowed, surrounding whitespace tolerated.
 * Returns the field element (reduced mod p), or null when unusable.
 * Two spellings of the same value parse to the same element.
 */
export function parseHexField(value) {
  if (typeof value !== "string") return null;
  const s = value.trim().toLowerCase();
  const hex = s.startsWith("0x") ? s.slice(2) : s;
  if (hex.length === 0 || !/^[0-9a-f]+$/.test(hex)) return null;
  return BigInt("0x" + hex) % FIELD_PRIME;
}

/**
 * Parse a decimal integer field: JSON integers or integer strings.
 * Rejects negatives, fractions, empty strings, and non-numeric values.
 * Unbounded: range checks are the caller's job. Mirrors the gatekeeper
 * parser exactly, including its BigInt() semantics.
 */
export function parseDecimalField(value) {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) return null;
    return BigInt(value);
  }
  if (typeof value !== "string") return null;
  const s = value.trim();
  if (s === "") return null;
  try {
    const b = BigInt(s);
    return b < 0n ? null : b;
  } catch {
    return null;
  }
}

/**
 * Parse a block number: an integer (number or integer string). Negative
 * integers parse (the gatekeeper historically accepted them for decision
 * purposes) but are flagged unprovable by buildWitness, because the prover
 * cannot represent a negative block as a field element.
 */
export function parseBlockField(value) {
  if (typeof value === "number") {
    return Number.isInteger(value) ? BigInt(value) : null;
  }
  if (typeof value !== "string") return null;
  const s = value.trim();
  if (!/^[+-]?\d+$/.test(s)) return null;
  try {
    return BigInt(s);
  } catch {
    return null;
  }
}

/**
 * Map an arbitrary task id string onto a BN128 field element, reporting
 * which mapping branch applied. UUID substring (if present) as a 128-bit
 * integer; else bare 32-hex; else 0x-hex reduced mod p; else SHA-256 of
 * the UTF-8 string, mod p. Mirrors the gatekeeper's mapping exactly,
 * including its documented aliasing: different strings can map to the
 * same element (e.g. any string containing the same UUID substring, or
 * values differing by a multiple of p). The branch is reported so the
 * aliasing is explicit, not hidden. When several UUIDs appear, the FIRST
 * match wins (String.match semantics).
 */
export function taskIdMapping(taskId) {
  const s = String(taskId).trim();
  const uuidMatch = s.match(
    /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/,
  );
  if (uuidMatch) {
    return {
      method: "uuid-substring",
      value: BigInt("0x" + uuidMatch[0].replace(/-/g, "")).toString(),
    };
  }
  const uuid = s.replace(/-/g, "");
  if (/^[0-9a-fA-F]{32}$/.test(uuid)) {
    return { method: "bare-32-hex", value: BigInt("0x" + uuid).toString() };
  }
  if (/^0x[0-9a-fA-F]+$/.test(s)) {
    return { method: "0x-hex-mod-p", value: (BigInt(s) % FIELD_PRIME).toString() };
  }
  const digest = createHash("sha256").update(s, "utf8").digest();
  return {
    method: "sha256-mod-p",
    value: (BigInt("0x" + digest.toString("hex")) % FIELD_PRIME).toString(),
  };
}

export function taskIdToField(taskId) {
  return taskIdMapping(taskId).value;
}

/** Fresh random salt: 31 random bytes, always < 2^248 < FIELD_PRIME. */
export function randomSalt() {
  return BigInt("0x" + randomBytes(31).toString("hex")).toString();
}

const REQUIRED_FIELDS = [
  "registered_vk",
  "proof_vk",
  "minimum",
  "public_balance",
  "expiry_block",
  "current_block",
  "recipient",
  "condition_recipient",
  "amount",
  "max_transfer",
  "task_id",
];

/**
 * Structural validation. Returns an error string, or null when usable.
 * Uses the SAME parsers as the evaluation, so accepted input evaluates
 * identically downstream.
 */
export function validateTaskInput(input) {
  if (typeof input !== "object" || input === null) return "input must be an object";
  for (const f of REQUIRED_FIELDS) {
    if (input[f] === undefined || input[f] === null || input[f] === "") {
      return `missing input field: ${f}`;
    }
  }
  for (const f of ["registered_vk", "proof_vk", "recipient", "condition_recipient"]) {
    if (parseHexField(input[f]) === null) return `field ${f} is not a hex string`;
  }
  for (const f of ["minimum", "public_balance", "amount", "max_transfer"]) {
    if (parseDecimalField(input[f]) === null) {
      return `field ${f} is not a non-negative integer`;
    }
  }
  for (const f of ["expiry_block", "current_block"]) {
    if (parseBlockField(input[f]) === null) return `field ${f} is not an integer`;
  }
  if (typeof input.task_id !== "string" || input.task_id.trim() === "") {
    return "field task_id is not a non-empty string";
  }
  if (input.salt !== undefined && input.salt !== null && input.salt !== "") {
    const salt = parseDecimalField(input.salt);
    if (salt === null) return "field salt is not a non-negative integer";
    if (salt >= FIELD_PRIME) return "field salt is out of field range";
  }
  return null;
}

/**
 * Evaluate the five on-circuit checks. Never throws on validated input.
 * Expiry is STRICT: current_block == expiry_block is EXPIRED.
 */
export function evaluateChecks(input) {
  const registeredVk = parseHexField(input.registered_vk);
  const proofVk = parseHexField(input.proof_vk);
  const minimum = parseDecimalField(input.minimum);
  const publicBalance = parseDecimalField(input.public_balance);
  const recipient = parseHexField(input.recipient);
  const conditionRecipient = parseHexField(input.condition_recipient);
  const amount = parseDecimalField(input.amount);
  const maxTransfer = parseDecimalField(input.max_transfer);
  const expiryBlock = parseBlockField(input.expiry_block);
  const currentBlock = parseBlockField(input.current_block);

  const checks = {
    vkMatch: registeredVk !== null && proofVk !== null && registeredVk === proofVk,
    thresholdOk: minimum !== null && publicBalance !== null && publicBalance >= minimum,
    notExpired:
      expiryBlock !== null && currentBlock !== null && currentBlock < expiryBlock,
    recipientOk:
      recipient !== null && conditionRecipient !== null && recipient === conditionRecipient,
    amountOk: amount !== null && maxTransfer !== null && amount <= maxTransfer,
  };

  let reason_code = "VALID_CONDITION";
  if (!checks.vkMatch) reason_code = "VK_SUBSTITUTION";
  else if (!checks.thresholdOk) reason_code = "THRESHOLD_MISMATCH";
  else if (!checks.notExpired) reason_code = "EXPIRED_CONDITION";
  else if (!checks.recipientOk) reason_code = "RECIPIENT_MISMATCH";
  else if (!checks.amountOk) reason_code = "AMOUNT_OVERFLOW";

  return { checks, reason_code, decision: reason_code === "VALID_CONDITION" ? "APPROVE" : "REJECT" };
}

/**
 * Build the 13-input witness object (all values decimal strings, circuit
 * key order), plus the evaluation and provability warnings. Throws on
 * invalid input — call validateTaskInput first, or catch the error.
 * A fresh random salt is generated when none is supplied.
 */
export function buildWitness(input) {
  const err = validateTaskInput(input);
  if (err) throw new Error(err);
  const { checks, reason_code, decision } = evaluateChecks(input);
  const warnings = [];

  const expiryBlock = parseBlockField(input.expiry_block);
  const currentBlock = parseBlockField(input.current_block);
  for (const [name, v] of [["expiry_block", expiryBlock], ["current_block", currentBlock]]) {
    if (v < 0n) warnings.push(`${name} is negative: decidable, but not provable (no negative field element)`);
    if (v >= FIELD_PRIME) warnings.push(`${name} is out of field range: decidable, but not provable`);
  }
  for (const f of ["minimum", "public_balance", "amount", "max_transfer"]) {
    if (parseDecimalField(input[f]) >= FIELD_PRIME) {
      warnings.push(`${f} is out of field range: decidable, but not provable`);
    }
  }

  const salt =
    input.salt !== undefined && input.salt !== null && input.salt !== ""
      ? parseDecimalField(input.salt).toString()
      : randomSalt();

  const mapping = taskIdMapping(input.task_id);

  const witness = {
    registeredVkHash: parseHexField(input.registered_vk).toString(),
    proofVkHash: parseHexField(input.proof_vk).toString(),
    minimum: parseDecimalField(input.minimum).toString(),
    publicBalance: parseDecimalField(input.public_balance).toString(),
    expiryBlock: expiryBlock.toString(),
    currentBlock: currentBlock.toString(),
    recipient: parseHexField(input.recipient).toString(),
    conditionRecipient: parseHexField(input.condition_recipient).toString(),
    amount: parseDecimalField(input.amount).toString(),
    maxTransfer: parseDecimalField(input.max_transfer).toString(),
    decision: decision === "APPROVE" ? "1" : "0",
    taskId: mapping.value,
    salt,
  };

  return { witness, checks, reason_code, decision, warnings, taskIdMapping: mapping };
}

// Lazy Poseidon singleton (circomlibjs builds over wasm; build once).
let poseidonPromise = null;
async function getPoseidon() {
  if (!poseidonPromise) {
    poseidonPromise = import("circomlibjs").then(({ buildPoseidon }) => buildPoseidon());
  }
  return poseidonPromise;
}

/**
 * Compute the 13-element publicSignals preview for a built witness:
 * [Poseidon(salt, taskId), then the 12 inputs in order minus salt].
 * This layout was verified empirically against the official circuit.
 * The preview shows what the prover would publish; it is NOT a proof,
 * and computing it does not prove anything.
 */
export async function publicSignalsPreview(witness) {
  const poseidon = await getPoseidon();
  const binding = poseidon.F.toString(
    poseidon([BigInt(witness.salt), BigInt(witness.taskId)]),
  );
  return [binding, ...PUBLIC_INPUT_KEYS.map((k) => witness[k])];
}

/** Full request handler for POST /api/build. Throws Error on bad input. */
export async function buildRequest(body) {
  const built = buildWitness(body);
  const publicSignals = await publicSignalsPreview(built.witness);
  return {
    witness: built.witness,
    publicSignals,
    publicSignalsLayout: ["poseidon(salt, taskId)", ...PUBLIC_INPUT_KEYS],
    checks: built.checks,
    decision: built.decision,
    reason_code: built.reason_code,
    warnings: built.warnings,
    taskIdMapping: built.taskIdMapping,
    note: "Expected public signals, computed locally using the stated circuit conventions. No proof has been generated or verified; this preview does not establish circuit satisfiability.",
  };
}
