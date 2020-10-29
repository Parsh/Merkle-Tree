# Merkle Tree Implementation

> A quick implementation of Bitcoin style merkle tree (carry forwarding mono-hash rather than dual hashing it)

## Prerequisites:

- [Node](https://nodejs.org/en/)

## Instructions

### How to execute

```sh
git clone https://github.com/Parsh/Merkle-Tree.git
cd Merkle-Tree
node Merkle.js
```

### Generating(and logging) the merkle tree

```javascript
const merkle = new Merkle();
const merkle_root = merkle.generate_merkle_root(txids);
console.log("Merkle Root: ", merkle_root);
merkle.log_merkle_tree();
```

### Fetching merkle path and inclusion status

```javascript
const txId = "522137b80ce9a66845e05d5abc09a1dad04ec80f774a7e585c6e8db975962d06";
const { hasTransaction, merklePath, merkleRoot } = merkle.hasTransaction(txId);
```

### Self-validation of tx-inclusion using merkle path & root

```javascript
// user validates the inclusion of the tx by regenerating the root via merkle path
validateUsingMerklePath(txId, merklePath, merkleRoot); // true or false
```
