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

  log_merkle_tree() {
    if (!this.merkleTree.length)
      throw new Error("Please generate a merkle tree prior to logging");

    console.log("\n\n\t\t\tMerkle Tree\n\n");
    let layerIndex = 0;
    this.merkleTree.forEach((merkleLayer) => {
      console.info(
        `${
          layerIndex === 0
            ? "Root " // Root merkle layer(merkle-root)
            : layerIndex === this.merkleTree.length - 1
            ? "Base " // Base merkle layer
            : "Inter" // Intermediate merkle layer
        }: ${merkleLayer.join(" -- -- ")}\n`
      );
      layerIndex++;
    });
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

// SMOKE TEST :: Merkle Tree
const txids = [
  "162e6f3dbbfb62ac1d1ff30f8b955a824984aefa3d06d878c14f0db3df150123",
  "525b8931402dd09222c50775608f7578fff79702c427bd2b87e56995a7bdd30f",
  "66d98fad6b012c8ed2b79a236ec46359f0868171b1d194cbee1af2f16ea598ae",
  "522137b80ce9a66845e05d5abc09a1dad04ec80f774a7e585c6e8db975962d06",
  "80c1de9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b",
  "f774a7e585c6e8db976845e05d5abc0ad04ec805962d069a522137b80c1de9a6",
  "ec80f774a7e585c6e82b79a236ec46359f0868171b166d98fad6b012c8ed2b59",
];

// generating a merkle tree
const merkle = new Merkle();
const merkle_root = merkle.generate_merkle_root(txids);
console.log("Merkle Root: ", merkle_root);
merkle.log_merkle_tree();

// checking whether a particular txid is present in the merkle tree
const txId = "ec80f774a7e585c6e82b79a236ec46359f0868171b166d98fad6b012c8ed2b59";
const { hasTransaction, merklePath, merkleRoot } = merkle.hasTransaction(txId);

// self validate that the merkle path, inconjunction with txId's hash, leads to merkle root
const validateUsingMerklePath = (txId, merklePath, merkleRoot) => {
  const txHash = Merkle.doubleSHA256(txId);
  let regeneratedRoot = txHash; // re-generating the root based on merkle path
  merklePath.forEach(({ hash, offset }) => {
    if (offset === 1)
      regeneratedRoot = Merkle.doubleSHA256(regeneratedRoot + hash);
    else regeneratedRoot = Merkle.doubleSHA256(hash + regeneratedRoot);
  });
  //   console.log({regeneratedRoot, merkleRoot})
  return regeneratedRoot === merkleRoot;
};

if (hasTransaction) {
  console.info(`Merkle tree do contain the supplied txid: ${txId}`);
  console.log({ merklePath, merkleRoot });
  console.info(
    "Self Validation successful: ",
    validateUsingMerklePath(txId, merklePath, merkleRoot)
  );
} else {
  console.info(`Merkle tree does not contain the following txid: ${txId}`);
}
