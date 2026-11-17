import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  FIELD_PRIME,
  WITNESS_KEYS,
  PUBLIC_INPUT_KEYS,
  parseHexField,
  parseDecimalField,
  parseBlockField,
  taskIdToField,
  taskIdMapping,
  randomSalt,
  validateTaskInput,
  evaluateChecks,
  buildWitness,
  publicSignalsPreview,
  buildRequest,
} from "../src/witness.js";
import { EXAMPLES } from "../src/examples.js";
import { createServer } from "../server.js";

const P = FIELD_PRIME;

const BASE = {
  registered_vk: "0x00aa11",
  proof_vk: "0xaa11",
  minimum: "100",
  public_balance: "250",
  expiry_block: 500,
  current_block: 499,
  recipient: "0x1234",
  condition_recipient: "0x1234",
  amount: "10",
  max_transfer: "100",
  task_id: "task_R05_123e4567-e89b-12d3-a456-426614174000",
  salt: "12345",
};

// ---------- parseHexField ----------

test("hex: 0x prefix, bare, upper-case, and padded spellings are equal", () => {
  const a = parseHexField("0x00ab");
  assert.equal(a, parseHexField("AB"));
  assert.equal(a, parseHexField(" 0xab "));
  assert.equal(a, parseHexField("0XAB"));
  assert.equal(a, 0xabn);
});

test("hex: empty, non-hex, and non-string inputs return null", () => {
  assert.equal(parseHexField(""), null);
  assert.equal(parseHexField("0x"), null);
  assert.equal(parseHexField("zz"), null);
  assert.equal(parseHexField("0x12g4"), null);
  assert.equal(parseHexField(123), null);
  assert.equal(parseHexField(null), null);
  assert.equal(parseHexField("   "), null);
});

test("hex: values at and above the prime reduce mod p", () => {
  assert.equal(parseHexField("0x" + P.toString(16)), 0n);
  assert.equal(parseHexField("0x" + (P + 1n).toString(16)), 1n);
});

// ---------- parseDecimalField ----------

test("decimal: numbers and integer strings parse", () => {
  assert.equal(parseDecimalField(0), 0n);
  assert.equal(parseDecimalField(42), 42n);
  assert.equal(parseDecimalField("42"), 42n);
  assert.equal(parseDecimalField("  42  "), 42n);
  assert.equal(parseDecimalField("007"), 7n);
});

test("decimal: negatives, fractions, empty, and non-numeric inputs return null", () => {
  assert.equal(parseDecimalField(-1), null);
  assert.equal(parseDecimalField("-5"), null);
  assert.equal(parseDecimalField(1.5), null);
  assert.equal(parseDecimalField("1.5"), null);
  assert.equal(parseDecimalField(""), null);
  assert.equal(parseDecimalField("   "), null);
  assert.equal(parseDecimalField("abc"), null);
  assert.equal(parseDecimalField(null), null);
  assert.equal(parseDecimalField(true), null);
});

test("decimal: unbounded — huge values parse (range is the caller's job)", () => {
  const huge = 10n ** 100n;
  assert.equal(parseDecimalField(huge.toString()), huge);
});

// ---------- parseBlockField ----------

test("blocks: integer numbers and strings parse, including negatives", () => {
  assert.equal(parseBlockField(500), 500n);
  assert.equal(parseBlockField("500"), 500n);
  assert.equal(parseBlockField(-3), -3n);
  assert.equal(parseBlockField("-3"), -3n);
  assert.equal(parseBlockField("  12 "), 12n);
});

test("blocks: fractions and non-integers return null", () => {
  assert.equal(parseBlockField(1.5), null);
  assert.equal(parseBlockField("1.5"), null);
  assert.equal(parseBlockField(""), null);
  assert.equal(parseBlockField("abc"), null);
  assert.equal(parseBlockField(null), null);
});

// ---------- taskIdToField ----------

test("taskId: UUID substring maps to the 128-bit integer", () => {
  const uuid = "123e4567-e89b-12d3-a456-426614174000";
  const expected = BigInt("0x123e4567e89b12d3a456426614174000").toString();
  assert.equal(taskIdToField(`task_R05_${uuid}`), expected);
  assert.equal(taskIdToField(uuid), expected);
  assert.equal(taskIdToField(`practice_${uuid}`), expected);
});

test("taskId: bare 32-hex (with or without dashes) maps directly", () => {
  const expected = BigInt("0x123e4567e89b12d3a456426614174000").toString();
  assert.equal(taskIdToField("123e4567e89b12d3a456426614174000"), expected);
});

test("taskId: 0x-hex reduces mod p", () => {
  assert.equal(taskIdToField("0x" + (P + 5n).toString(16)), "5");
  assert.equal(taskIdToField("0xff"), "255");
});

test("taskId: arbitrary strings fall back to SHA-256 mod p, deterministically", () => {
  const digest = createHash("sha256").update("hello-task", "utf8").digest();
  const expected = (BigInt("0x" + digest.toString("hex")) % P).toString();
  assert.equal(taskIdToField("hello-task"), expected);
  assert.equal(taskIdToField("hello-task"), taskIdToField("hello-task"));
  assert.ok(BigInt(taskIdToField("hello-task")) < P);
});

test("taskId: surrounding whitespace is trimmed", () => {
  assert.equal(taskIdToField("  0xff  "), "255");
});

test("taskIdMapping: reports the branch used for each form", () => {
  const uuid = "123e4567-e89b-12d3-a456-426614174000";
  assert.equal(taskIdMapping(`task_R05_${uuid}`).method, "uuid-substring");
  assert.equal(taskIdMapping("123e4567e89b12d3a456426614174000").method, "bare-32-hex");
  assert.equal(taskIdMapping("0xff").method, "0x-hex-mod-p");
  assert.equal(taskIdMapping("hello-task").method, "sha256-mod-p");
  assert.equal(
    taskIdMapping(`task_R05_${uuid}`).value,
    BigInt("0x123e4567e89b12d3a456426614174000").toString(),
  );
});

test("taskIdMapping: aliasing is real — different strings, same element", () => {
  const uuid = "123e4567-e89b-12d3-a456-426614174000";
  assert.equal(taskIdToField(`task_R05_${uuid}`), taskIdToField(`practice_${uuid}`));
  assert.equal(taskIdToField(`task_R05_${uuid}`), taskIdToField(uuid));
  // Values differing by a multiple of p alias through the 0x-hex branch.
  assert.equal(taskIdToField("0x" + (P + 5n).toString(16)), taskIdToField("0x5"));
});

test("taskIdMapping: first UUID wins when several appear", () => {
  const a = "123e4567-e89b-12d3-a456-426614174000";
  const b = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
  assert.equal(
    taskIdToField(`x-${a}-y-${b}`),
    BigInt("0x123e4567e89b12d3a456426614174000").toString(),
  );
});

// ---------- randomSalt ----------

test("salt: fresh salts are decimal strings below 2^248", () => {
  for (let i = 0; i < 5; i++) {
    const s = randomSalt();
    assert.match(s, /^\d+$/);
    assert.ok(BigInt(s) < 2n ** 248n);
    assert.ok(BigInt(s) < P);
  }
});

test("salt: consecutive salts differ", () => {
  assert.notEqual(randomSalt(), randomSalt());
});

// ---------- validateTaskInput ----------

test("validate: complete valid input passes", () => {
  assert.equal(validateTaskInput(BASE), null);
});

test("validate: salt is optional", () => {
  const { salt, ...rest } = BASE;
  assert.equal(validateTaskInput(rest), null);
});

test("validate: missing fields are reported", () => {
  for (const f of ["registered_vk", "proof_vk", "minimum", "public_balance", "expiry_block", "current_block", "recipient", "condition_recipient", "amount", "max_transfer", "task_id"]) {
    const bad = { ...BASE, [f]: undefined };
    assert.match(validateTaskInput(bad), new RegExp(`missing input field: ${f}`));
  }
});

test("validate: bad hex, decimal, block, task_id, and salt are reported", () => {
  assert.match(validateTaskInput({ ...BASE, registered_vk: "zz" }), /not a hex string/);
  assert.match(validateTaskInput({ ...BASE, amount: "-1" }), /not a non-negative integer/);
  assert.match(validateTaskInput({ ...BASE, expiry_block: 1.5 }), /not an integer/);
  assert.match(validateTaskInput({ ...BASE, task_id: "   " }), /not a non-empty string/);
  assert.match(validateTaskInput({ ...BASE, salt: "-1" }), /not a non-negative integer/);
  assert.match(validateTaskInput({ ...BASE, salt: P.toString() }), /out of field range/);
  assert.equal(validateTaskInput(null), "input must be an object");
  assert.equal(validateTaskInput("x"), "input must be an object");
});

// ---------- evaluateChecks ----------

test("checks: all-pass input approves with VALID_CONDITION", () => {
  const r = evaluateChecks(BASE);
  assert.equal(r.decision, "APPROVE");
  assert.equal(r.reason_code, "VALID_CONDITION");
  assert.deepEqual(r.checks, { vkMatch: true, thresholdOk: true, notExpired: true, recipientOk: true, amountOk: true });
});

test("checks: vk mismatch -> VK_SUBSTITUTION", () => {
  const r = evaluateChecks({ ...BASE, proof_vk: "0xbb22" });
  assert.equal(r.decision, "REJECT");
  assert.equal(r.reason_code, "VK_SUBSTITUTION");
  assert.equal(r.checks.vkMatch, false);
});

test("checks: balance below minimum -> THRESHOLD_MISMATCH", () => {
  const r = evaluateChecks({ ...BASE, public_balance: "99" });
  assert.equal(r.reason_code, "THRESHOLD_MISMATCH");
  assert.equal(r.checks.thresholdOk, false);
});

test("checks: balance equal to minimum passes threshold", () => {
  const r = evaluateChecks({ ...BASE, public_balance: "100" });
  assert.equal(r.checks.thresholdOk, true);
  assert.equal(r.decision, "APPROVE");
});

test("checks: strict expiry — current == expiry is EXPIRED", () => {
  const r = evaluateChecks({ ...BASE, current_block: 500 });
  assert.equal(r.decision, "REJECT");
  assert.equal(r.reason_code, "EXPIRED_CONDITION");
  assert.equal(r.checks.notExpired, false);
});

test("checks: current one below expiry passes", () => {
  assert.equal(evaluateChecks({ ...BASE, current_block: 499 }).checks.notExpired, true);
  assert.equal(evaluateChecks({ ...BASE, current_block: 501 }).checks.notExpired, false);
});

test("checks: recipient mismatch -> RECIPIENT_MISMATCH", () => {
  const r = evaluateChecks({ ...BASE, condition_recipient: "0x5678" });
  assert.equal(r.reason_code, "RECIPIENT_MISMATCH");
  assert.equal(r.checks.recipientOk, false);
});

test("checks: amount above max -> AMOUNT_OVERFLOW; equal passes", () => {
  assert.equal(evaluateChecks({ ...BASE, amount: "101" }).reason_code, "AMOUNT_OVERFLOW");
  assert.equal(evaluateChecks({ ...BASE, amount: "100" }).checks.amountOk, true);
  assert.equal(evaluateChecks({ ...BASE, amount: "100" }).decision, "APPROVE");
});

test("checks: hex spelling variants compare equal", () => {
  const r = evaluateChecks({ ...BASE, registered_vk: "  0x00AA11 ", proof_vk: "aa11" });
  assert.equal(r.checks.vkMatch, true);
});

test("checks: reason priority follows circuit order", () => {
  // vk + threshold + expiry all failing -> vk wins (first check)
  const r = evaluateChecks({ ...BASE, proof_vk: "0xbb22", public_balance: "1", current_block: 999 });
  assert.equal(r.reason_code, "VK_SUBSTITUTION");
  // threshold + expiry failing -> threshold wins
  const r2 = evaluateChecks({ ...BASE, public_balance: "1", current_block: 999 });
  assert.equal(r2.reason_code, "THRESHOLD_MISMATCH");
  // expiry + amount failing -> expiry wins
  const r3 = evaluateChecks({ ...BASE, current_block: 999, amount: "999" });
  assert.equal(r3.reason_code, "EXPIRED_CONDITION");
});

// ---------- buildWitness ----------

test("witness: 13 keys in circuit order, decimal strings", () => {
  const { witness } = buildWitness(BASE);
  assert.deepEqual(Object.keys(witness), WITNESS_KEYS);
  assert.equal(witness.registeredVkHash, "43537");
  assert.equal(witness.proofVkHash, "43537");
  assert.equal(witness.minimum, "100");
  assert.equal(witness.publicBalance, "250");
  assert.equal(witness.expiryBlock, "500");
  assert.equal(witness.currentBlock, "499");
  assert.equal(witness.recipient, "4660");
  assert.equal(witness.decision, "1");
  assert.equal(witness.taskId, BigInt("0x123e4567e89b12d3a456426614174000").toString());
  assert.equal(witness.salt, "12345");
  for (const v of Object.values(witness)) assert.equal(typeof v, "string");
});

test("witness: REJECT decisions encode decision 0", () => {
  const { witness, decision, reason_code } = buildWitness({ ...BASE, current_block: 500 });
  assert.equal(witness.decision, "0");
  assert.equal(decision, "REJECT");
  assert.equal(reason_code, "EXPIRED_CONDITION");
});

test("witness: omitted salt generates a fresh valid salt", () => {
  const { salt, ...rest } = BASE;
  const { witness } = buildWitness(rest);
  assert.match(witness.salt, /^\d+$/);
  assert.ok(BigInt(witness.salt) < P);
});

test("witness: out-of-range decimal warns but still builds", () => {
  const { witness, warnings } = buildWitness({ ...BASE, public_balance: (P + 1n).toString() });
  assert.equal(witness.publicBalance, (P + 1n).toString());
  assert.ok(warnings.some((w) => w.includes("public_balance") && w.includes("out of field range")));
});

test("witness: negative block warns but still decides", () => {
  const { witness, warnings, decision } = buildWitness({ ...BASE, current_block: -5 });
  assert.equal(witness.currentBlock, "-5");
  assert.equal(decision, "APPROVE");
  assert.ok(warnings.some((w) => w.includes("current_block") && w.includes("negative")));
});

test("witness: invalid input throws", () => {
  assert.throws(() => buildWitness({ ...BASE, amount: "nope" }), /not a non-negative integer/);
});

test("witness: public input keys are the 12 witness keys minus salt", () => {
  assert.deepEqual(PUBLIC_INPUT_KEYS, WITNESS_KEYS.slice(0, 12));
  assert.equal(PUBLIC_INPUT_KEYS.length, 12);
  assert.ok(!PUBLIC_INPUT_KEYS.includes("salt"));
});

// ---------- publicSignalsPreview ----------

test("signals: 13 elements, binding first, then inputs in order minus salt", async () => {
  const { witness } = buildWitness(BASE);
  const signals = await publicSignalsPreview(witness);
  assert.equal(signals.length, 13);
  assert.deepEqual(signals.slice(1), PUBLIC_INPUT_KEYS.map((k) => witness[k]));
  assert.equal(typeof signals[0], "string");
  assert.ok(BigInt(signals[0]) < P);
});

test("signals: binding equals circomlibjs Poseidon(salt, taskId)", async () => {
  const { buildPoseidon } = await import("circomlibjs");
  const poseidon = await buildPoseidon();
  const { witness } = buildWitness(BASE);
  const signals = await publicSignalsPreview(witness);
  const expected = poseidon.F.toString(poseidon([BigInt(witness.salt), BigInt(witness.taskId)]));
  assert.equal(signals[0], expected);
});

test("signals: known Poseidon vector poseidon([1,2])", async () => {
  const { buildPoseidon } = await import("circomlibjs");
  const poseidon = await buildPoseidon();
  assert.equal(
    poseidon.F.toString(poseidon([1n, 2n])),
    "7853200120776062878684798364095072458815029376092732009249414926327459813530",
  );
});

test("signals: order matters — Poseidon(salt,taskId) differs from Poseidon(taskId,salt)", async () => {
  const { buildPoseidon } = await import("circomlibjs");
  const poseidon = await buildPoseidon();
  const a = poseidon.F.toString(poseidon([12345n, 999n]));
  const b = poseidon.F.toString(poseidon([999n, 12345n]));
  assert.notEqual(a, b);
});

test("signals: changing only the salt changes only signal 0", async () => {
  const s1 = await publicSignalsPreview(buildWitness(BASE).witness);
  const s2 = await publicSignalsPreview(buildWitness({ ...BASE, salt: "777" }).witness);
  assert.notEqual(s1[0], s2[0]);
  assert.deepEqual(s1.slice(1), s2.slice(1));
});

// ---------- buildRequest ----------

test("buildRequest: full shape with layout labels and honesty note", async () => {
  const r = await buildRequest(BASE);
  assert.equal(r.decision, "APPROVE");
  assert.equal(r.reason_code, "VALID_CONDITION");
  assert.equal(r.publicSignals.length, 13);
  assert.equal(r.publicSignalsLayout[0], "poseidon(salt, taskId)");
  assert.deepEqual(r.publicSignalsLayout.slice(1), PUBLIC_INPUT_KEYS);
  assert.deepEqual(r.warnings, []);
  assert.match(r.note, /No proof has been generated or verified/);
  assert.match(r.note, /does not establish circuit satisfiability/);
  assert.equal(r.taskIdMapping.method, "uuid-substring");
  assert.equal(r.taskIdMapping.value, r.witness.taskId);
});

// ---------- examples ----------

test("examples: every bundled example validates and its decision matches its story", async () => {
  const expected = {
    "valid-approval": "APPROVE",
    "expired-boundary": "REJECT",
    "amount-overflow": "REJECT",
    "vk-substitution": "REJECT",
    "threshold-mismatch": "REJECT",
    "recipient-mismatch": "REJECT",
    "spelling-variants": "APPROVE",
  };
  assert.equal(EXAMPLES.length, 7);
  for (const ex of EXAMPLES) {
    assert.equal(validateTaskInput(ex.input), null, ex.id);
    const r = await buildRequest(ex.input);
    assert.equal(r.decision, expected[ex.id], ex.id);
    assert.equal(r.publicSignals.length, 13, ex.id);
  }
});

test("examples: expired-boundary example fails ONLY the expiry check", () => {
  const ex = EXAMPLES.find((e) => e.id === "expired-boundary");
  const { checks, reason_code } = evaluateChecks(ex.input);
  assert.equal(reason_code, "EXPIRED_CONDITION");
  assert.deepEqual(checks, { vkMatch: true, thresholdOk: true, notExpired: false, recipientOk: true, amountOk: true });
});

// ---------- HTTP ----------

async function withServer(fn) {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await fn(base);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test("http: /health and /api/health return ok", async () => {
  await withServer(async (base) => {
    for (const p of ["/health", "/api/health"]) {
      const res = await fetch(base + p);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.ok, true);
      assert.equal(body.service, "witness-builder");
    }
  });
});

test("http: / serves the UI page", async () => {
  await withServer(async (base) => {
    const res = await fetch(base + "/");
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type"), /text\/html/);
    const html = await res.text();
    assert.match(html, /Witness Builder/);
    assert.match(html, /Honest scope/);
    assert.match(html, /NOT<\/b> generate proofs/);
  });
});

test("http: /api/examples returns the bundled examples", async () => {
  await withServer(async (base) => {
    const res = await fetch(base + "/api/examples");
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.examples.length, 7);
    assert.equal(body.examples[0].id, "valid-approval");
  });
});

test("http: POST /api/build returns witness + signals for valid input", async () => {
  await withServer(async (base) => {
    const res = await fetch(base + "/api/build", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(BASE),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.decision, "APPROVE");
    assert.equal(Object.keys(body.witness).length, 13);
    assert.equal(body.publicSignals.length, 13);
  });
});

test("http: POST /api/build rejects invalid input with 400", async () => {
  await withServer(async (base) => {
    const res = await fetch(base + "/api/build", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...BASE, amount: "nope" }),
    });
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.match(body.error, /not a non-negative integer/);
  });
});

test("http: POST /api/build rejects malformed JSON with 400", async () => {
  await withServer(async (base) => {
    const res = await fetch(base + "/api/build", { method: "POST", body: "{bad json" });
    assert.equal(res.status, 400);
  });
});

test("http: oversized body returns 413", async () => {
  await withServer(async (base) => {
    const res = await fetch(base + "/api/build", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ pad: "x".repeat(70 * 1024) }),
    });
    assert.equal(res.status, 413);
  });
});

test("http: unknown path returns 404", async () => {
  await withServer(async (base) => {
    const res = await fetch(base + "/nope");
    assert.equal(res.status, 404);
  });
});
