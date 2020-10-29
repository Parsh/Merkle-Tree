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

  hasTransaction(transactionId) {
    // returns whether the txn is included or not in the cached merkle tree, in case of containment a merkle path is provided along w/ merkle root for self validation

    if (!this.merkleTree.length)
      throw new Error(
        "Please generate a merkle tree prior to checking for containment"
      );

    const txHash = Merkle.doubleSHA256(transactionId);

    // validate against the base merkle layer (first layer elimination for non-contained txn)
    const baseMerkleLayer = this.merkleTree[this.merkleTree.length - 1];
    if (!baseMerkleLayer.includes(txHash)) {
      // returns false if txHash for the supplied txId is not present in the base layer
      return { hasTransaction: false, merklePath: null };
    } else {
      // returns the merkle path w/ merkle root
      const merklePath = [];
      let merkleHash = txHash;
      for (const merkleLayer of [...this.merkleTree].reverse()) {
        if (merkleLayer.length < 2) break; // break away at merkle root

        const merkleIndex = merkleLayer.indexOf(merkleHash);

        if (merkleIndex % 2 == 0) {
          const nextMerkleHash = merkleLayer[merkleIndex + 1];
          merklePath.push({ hash: nextMerkleHash, offset: 1 }); // offset is used during self validation of tx-inclusion using the merkle path
          merkleHash = Merkle.doubleSHA256(merkleHash + nextMerkleHash);
        } else {
          const prevMerkleHash = merkleLayer[merkleIndex - 1];
          merklePath.push({ hash: prevMerkleHash, offset: -1 });
          merkleHash = Merkle.doubleSHA256(prevMerkleHash + merkleHash);
        }
      }

      return {
        hasTransaction: true,
        merklePath,
        merkleRoot: this.merkleTree[0][0],
      };
    }
  }
}
