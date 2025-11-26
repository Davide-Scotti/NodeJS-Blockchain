import { Block } from "./block.js";

export class Blockchain {
  constructor() {
    this.chain = [Block.genesis()];
  }

  get latestBlock() {
    return this.chain[this.chain.length - 1];
  }

  addBlock(data) {
    const newBlock = Block.mineBlock(this.latestBlock, data);
    this.chain.push(newBlock);
    return newBlock;
  }

  isValid() {
    for (let i = 1; i < this.chain.length; i += 1) {
      const current = this.chain[i];
      const previous = this.chain[i - 1];

      if (current.previousHash !== previous.hash) {
        return false;
      }

      const recalculatedHash = Block.calculateHash({
        index: current.index,
        timestamp: current.timestamp,
        data: current.data,
        previousHash: current.previousHash,
        nonce: current.nonce,
      });

      if (current.hash !== recalculatedHash) {
        return false;
      }
    }

    return true;
  }
}
