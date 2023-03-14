use sha2::Digest;
use std::collections::VecDeque;

pub type Data = Vec<u8>;
pub type Hash = Vec<u8>;

#[derive(Debug)]
pub struct MerkleTree {
    hash: Hash,
    level: usize,
    left: Option<Box<MerkleTree>>,
    right: Option<Box<MerkleTree>>,
}

/// Which side to put Hash on when concatinating proof hashes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashDirection {
    Left,
    Right,
}

#[derive(Debug, Default)]
pub struct Proof<'a> {
    /// The hashes to use when verifying the proof
    /// The first element of the tuple is which side the hash should be on when concatinating
    hashes: Vec<(HashDirection, &'a Hash)>,
}

impl MerkleTree {
    /// Gets root hash for this tree
    pub fn root(&self) -> Hash {
        self.hash.clone()
    }

    fn merge_tree(left: MerkleTree, right: MerkleTree) -> Self {
        Self {
            hash: hash_concat(&left.hash, &right.hash),
            level: std::cmp::max(left.level, right.level) + 1,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
        }
    }

    fn make_leaf(hash: Hash) -> Self {
        Self {
            hash,
            level: 0,
            left: None,
            right: None,
        }
    }

    fn make_leaves(input: &[Data]) -> Vec<MerkleTree> {
        input
            .iter()
            .map(hash_data)
            .map(MerkleTree::make_leaf)
            .collect()
    }

    fn make_root(mut queue: VecDeque<MerkleTree>) -> Option<MerkleTree> {
        loop {
            match (queue.pop_front(), queue.pop_front()) {
                (Some(left), Some(right)) => {
                    // handle odd number case
                    if left.level < right.level {
                        queue.push_back(left);
                        queue.push_front(right);
                        continue;
                    }

                    queue.push_back(MerkleTree::merge_tree(left, right))
                }
                (Some(node), None) => break Some(node),
                _ => break None,
            }
        }
    }

    /// Constructs a Merkle tree from given input data
    pub fn construct(input: &[Data]) -> MerkleTree {
        let queue = VecDeque::from_iter(MerkleTree::make_leaves(input));
        let root = MerkleTree::make_root(queue);
        root.map_or(MerkleTree::make_leaf(vec![]), |tree| tree)
    }

    /// Verifies that the given input data produces the given root hash
    pub fn verify(input: &[Data], root_hash: &Hash) -> bool {
        MerkleTree::construct(input).root() == *root_hash
    }

    /// Verifies that the given data and proof_path correctly produce the given root_hash
    pub fn verify_proof(data: &Data, proof: &Proof, root_hash: &Hash) -> bool {
        let calculated_hash = proof
            .hashes
            .iter()
            .fold(hash_data(data), |acc, (dir, hash)| match *dir {
                HashDirection::Left => hash_concat(hash, &acc),
                HashDirection::Right => hash_concat(&acc, hash),
            });
        calculated_hash == *root_hash
    }

    fn dfs_proof_path<'a: 'b, 'b>(&'a self, target_hash: &Hash, proof: &mut Proof<'b>) -> bool {
        if self.root() == *target_hash {
            return true;
        }

        if let (Some(ref l), Some(ref r)) = (&self.left, &self.right) {
            proof.hashes.push((HashDirection::Right, &r.hash));
            if l.dfs_proof_path(target_hash, proof) {
                return true;
            }
            proof.hashes.pop();

            proof.hashes.push((HashDirection::Left, &l.hash));
            if r.dfs_proof_path(target_hash, proof) {
                return true;
            }
            proof.hashes.pop();
        }

        false
    }

    /// Returns a list of hashes that can be used to prove that the given data is in this tree
    pub fn prove(&self, data: &Data) -> Option<Proof> {
        let target_hash = hash_data(data);
        let mut proof = Proof::default();
        if self.dfs_proof_path(&target_hash, &mut proof) {
            // dfs_proof_path produce hashes from top down
            // hashes needed to be reversed in order to make it bottom up
            proof.hashes.reverse();
            Some(proof)
        } else {
            None
        }
    }
}

fn hash_data(data: &Data) -> Hash {
    sha2::Sha256::digest(data).to_vec()
}

fn hash_concat(h1: &Hash, h2: &Hash) -> Hash {
    let h3 = h1.iter().chain(h2).copied().collect();
    hash_data(&h3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_data(n: usize) -> Vec<Data> {
        let mut data = vec![];
        for i in 0..n {
            data.push(vec![i as u8]);
        }
        data
    }

    #[test]
    fn test_constructions() {
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let expected_root = "9675e04b4ba9dc81b06e81731e2d21caa2c95557a85dcfa3fff70c9ff0f30b2e";
        assert_eq!(hex::encode(tree.root()), expected_root);

        let data = example_data(3);
        let tree = MerkleTree::construct(&data);
        let expected_root = "773a93ac37ea78b3f14ac31872c83886b0a0f1fec562c4e848e023c889c2ce9f";
        assert_eq!(hex::encode(tree.root()), expected_root);

        let data = example_data(8);
        let tree = MerkleTree::construct(&data);
        let expected_root = "0727b310f87099c1ba2ec0ba408def82c308237c8577f0bdfd2643e9cc6b7578";
        assert_eq!(hex::encode(tree.root()), expected_root);
    }

    #[test]
    fn test_verify() {
        let data = example_data(4);
        let root_hash =
            hex::decode("9675e04b4ba9dc81b06e81731e2d21caa2c95557a85dcfa3fff70c9ff0f30b2e")
                .unwrap();
        assert!(MerkleTree::verify(&data, &root_hash));

        let data = example_data(3);
        let root_hash =
            hex::decode("773a93ac37ea78b3f14ac31872c83886b0a0f1fec562c4e848e023c889c2ce9f")
                .unwrap();
        assert!(MerkleTree::verify(&data, &root_hash));

        let data = example_data(8);
        let root_hash =
            hex::decode("0727b310f87099c1ba2ec0ba408def82c308237c8577f0bdfd2643e9cc6b7578")
                .unwrap();
        assert!(MerkleTree::verify(&data, &root_hash));

        let data = example_data(3);
        let root_hash =
            hex::decode("0727b310f87099c1ba2ec0ba408def82c308237c8577f0bdfd2643e9cc6b7578")
                .unwrap();
        assert!(!MerkleTree::verify(&data, &root_hash));
    }

    #[test]
    fn test_prove() {
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let proof0 = tree.prove(data.get(0).unwrap()).unwrap();
        let proof1 = tree.prove(data.get(1).unwrap()).unwrap();
        let proof2 = tree.prove(data.get(2).unwrap()).unwrap();
        let proof3 = tree.prove(data.get(3).unwrap()).unwrap();
        assert!(MerkleTree::verify_proof(
            data.get(0).unwrap(),
            &proof0,
            &tree.root()
        ));
        assert!(MerkleTree::verify_proof(
            data.get(1).unwrap(),
            &proof1,
            &tree.root()
        ));
        assert!(MerkleTree::verify_proof(
            data.get(2).unwrap(),
            &proof2,
            &tree.root()
        ));
        assert!(MerkleTree::verify_proof(
            data.get(3).unwrap(),
            &proof3,
            &tree.root()
        ));
        assert!(!MerkleTree::verify_proof(
            data.get(3).unwrap(),
            &proof1,
            &tree.root()
        ))
    }
}
