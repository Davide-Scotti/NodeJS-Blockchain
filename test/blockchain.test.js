import assert from "node:assert/strict";
import test from "node:test";
import { Blockchain } from "../src/core/blockchain.js";

test("adds blocks and maintains validity", () => {
  const chain = new Blockchain();

  const b1 = chain.addBlock({ value: 1 });
  const b2 = chain.addBlock({ value: 2 });

  assert.equal(chain.chain.length, 3); // genesis + 2 blocks
  assert.equal(chain.latestBlock, b2);
  assert.ok(chain.isValid());

  // Tamper with the chain
  chain.chain[1].data = { value: 999 };

  assert.equal(chain.isValid(), false);
});