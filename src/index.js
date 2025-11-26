import { Blockchain } from "./core/blockchain.js";

function main() {
  const chain = new Blockchain();

  console.log("Starting blockchain demo...\n");
  console.log("Genesis block:");
  console.dir(chain.latestBlock, { depth: null });

  console.log("\nMining a couple of blocks...\n");

  chain.addBlock({ from: "alice", to: "bob", amount: 10 });
  chain.addBlock({ from: "bob", to: "charlie", amount: 5 });

  console.log("Full chain:");
  console.dir(chain.chain, { depth: null });

  console.log("\nChain valid?", chain.isValid());
}

main();
