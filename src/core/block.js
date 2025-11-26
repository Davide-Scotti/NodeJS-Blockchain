import crypto from "crypto";
import { BLOCKCHAIN_CONFIG } from "../config.js";

export class Block {
  constructor({ index, timestamp, data, previousHash = "0", nonce = 0, hash = "" }) {
    this.index = index;
    this.timestamp = timestamp;
    this.data = data;
    this.previousHash = previousHash;
    this.nonce = nonce;
    this.hash = hash || Block.calculateHash({ index, timestamp, data, previousHash, nonce });
  }

  static calculateHash({ index, timestamp, data, previousHash, nonce }) {
    const payload = `${index}${timestamp}${JSON.stringify(data)}${previousHash}${nonce}`;
    return crypto.createHash("sha256").update(payload).digest("hex");
  }

  static genesis() {
    return new Block({
      index: 0,
      timestamp: new Date("2024-01-01T00:00:00.000Z").toISOString(),
      data: { message: "Genesis Block" },
      previousHash: "0",
      nonce: 0,
    });
  }

  static mineBlock(previousBlock, data) {
    const index = previousBlock.index + 1;
    const timestamp = new Date().toISOString();
    let nonce = 0;
    let hash = "";

    const prefix = "0".repeat(BLOCKCHAIN_CONFIG.difficulty);

    do {
      nonce += 1;
      hash = Block.calculateHash({ index, timestamp, data, previousHash: previousBlock.hash, nonce });
    } while (!hash.startsWith(prefix));

    return new Block({ index, timestamp, data, previousHash: previousBlock.hash, nonce, hash });
  }
}
