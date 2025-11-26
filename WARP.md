# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project commands

This repository is a Node.js (ES module) project. Dependency installation and tooling are managed via `npm`.

- Install dependencies (including dev tooling like ESLint):
  - `npm install`
- Run the demo blockchain node (logs the chain to stdout):
  - `npm start`
- Run the test suite (Node built-in test runner, looks under `test/`):
  - `npm test`
- Run lint on source and tests:
  - `npm run lint`
- Auto-fix simple lint issues where possible:
  - `npm run lint:fix`
- Run a single test file:
  - `node --test test/blockchain.test.js`

If `npm` is not available in the environment, install Node.js (which includes `npm`) and ensure it is on the `PATH` before using these commands.

## High-level architecture

### Overview

The current implementation focuses on the core blockchain data structures and a simple demo entrypoint. The design separates **domain logic** (blocks and chain) from the **runtime/CLI entrypoint**.

Top-level layout:

- `src/`
  - `config.js`: Central blockchain configuration (e.g., mining difficulty, mining reward). Imported by core modules that need consensus parameters.
  - `core/`
    - `block.js`: Defines the `Block` class, responsible for block structure, hashing, genesis block creation, and proof-of-work mining.
    - `blockchain.js`: Defines the `Blockchain` class, which manages the chain of blocks, appending new blocks, and validating the chain.
  - `index.js`: Entry script that creates a `Blockchain` instance, mines a few example blocks, prints the chain, and reports validity.
- `test/`
  - `blockchain.test.js`: Uses the Node built-in test runner (`node:test`) and `assert` to verify that blocks can be added, the chain stays valid, and tampering invalidates the chain.

### Core domain logic

- **Block (`src/core/block.js`)**
  - Encodes block properties: `index`, `timestamp`, `data`, `previousHash`, `nonce`, `hash`.
  - Uses Node's `crypto` module and `BLOCKCHAIN_CONFIG.difficulty` to implement a simple proof-of-work: hashes must start with a configurable number of leading zeros.
  - Provides:
    - `Block.genesis()` to create the fixed genesis block.
    - `Block.mineBlock(previousBlock, data)` to mine a new block given the previous block and arbitrary payload `data`.

- **Blockchain (`src/core/blockchain.js`)**
  - Holds an in-memory array of `Block` instances (`this.chain`).
  - Ensures the chain is initialized with the genesis block.
  - Provides:
    - `latestBlock` getter for convenience.
    - `addBlock(data)` to mine and append a new block.
    - `isValid()` to walk the chain and ensure:
      - Each block's `previousHash` matches the actual hash of the preceding block.
      - Each block's `hash` matches a recomputed hash of its contents.

### Runtime / entrypoint

- **Demo entry (`src/index.js`)**
  - Creates a `Blockchain` instance and logs:
    - The genesis block.
    - A couple of mined blocks with example transaction-like payloads.
    - The full chain and the result of `isValid()`.
  - This file is the main hook for expanding into a CLI, HTTP API, or node process in future iterations.

Future changes should keep the core consensus and data-structure logic under `src/core/`, and add new surfaces (CLI, HTTP API, P2P, persistence) as separate layers that **depend on** but do not embed core logic.
