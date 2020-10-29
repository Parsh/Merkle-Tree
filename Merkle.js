const crypto = require("crypto");

class Merkle {
  constructor() {
    this.merkleTree = [];
  }

  static doubleSHA256(data) {
    const hash = crypto.createHash("sha256").update(data).digest("hex");
    const doubleHash = crypto.createHash("sha256").update(hash).digest("hex");
    return doubleHash;
  }

  generate_merkle_root(transactionIds) {
    // generates the merkle tree & returns the merkle root corresponding to the supplied transaction ids

    // clean-ups and checks
    if (!transactionIds || !transactionIds.length) {
      throw new Error("Transaction IDs missing");
    }
    if (this.merkleTree.length) this.merkleTree = [];

    // initiate the base merkle layer
    const transactionHashes = transactionIds.map((txId) =>
      Merkle.doubleSHA256(txId)
    );
    this.merkleTree.push(transactionHashes);

    // iteratively generate the intermediate merkle layers(bottom-up) till merkle root
    do {
      let nextMerkleLayer = [];
      const previousMerkleLayer = this.merkleTree[0];
      for (let index = 0; index < previousMerkleLayer.length; index += 2) {
        if (index % 2 == 0 && index < previousMerkleLayer.length - 1) {
          // forwards the squashed has to the next merkle layer
          const merkleHash = previousMerkleLayer[index];
          const adjacentMerkleHash = previousMerkleLayer[index + 1];
          nextMerkleLayer.push(
            Merkle.doubleSHA256(merkleHash + adjacentMerkleHash)
          );
        } else {
          // forward the mono-hash to the next layer
          nextMerkleLayer.push(previousMerkleLayer[index]);
        }
      }
      this.merkleTree.unshift(nextMerkleLayer); // insert the intermediate merkle layer
    } while (this.merkleTree[0].length > 1);

    const merkleRoot = this.merkleTree[0][0];
    return merkleRoot;
  }
}
