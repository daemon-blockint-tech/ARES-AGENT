use crate::{AresError, AresResult, Finding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub finding_id: String,
    pub trace: Vec<TraceEntry>,
    pub state_diff: serde_json::Value,
    pub exploit_scenario: String,
    pub merkle_leaf: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEntry {
    pub step: u32,
    pub program_id: String,
    pub instruction: String,
    pub accounts: Vec<String>,
    pub data: String,
}

impl Evidence {
    pub fn new(finding: &Finding) -> Self {
        let leaf = finding.merkle_leaf();
        Self {
            finding_id: finding.id.clone(),
            trace: Vec::new(),
            state_diff: serde_json::Value::Null,
            exploit_scenario: finding.exploit_scenario.clone().unwrap_or_default(),
            merkle_leaf: hex::encode(&leaf),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub batch_id: String,
    pub findings: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub merkle_root: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub anchored: bool,
    pub anchor_tx: Option<String>,
}

impl EvidenceBundle {
    pub fn new(batch_id: &str, evidence: Vec<Evidence>) -> AresResult<Self> {
        let leaves: Vec<Vec<u8>> = evidence
            .iter()
            .map(|e| hex::decode(&e.merkle_leaf).map_err(|e| AresError::Evidence(format!("Invalid merkle leaf hex: {}", e))))
            .collect::<Result<_, _>>()?;
        let tree = MerkleTree::new(&leaves);
        let root = hex::encode(tree.root());
        let finding_ids: Vec<String> = evidence.iter().map(|e| e.finding_id.clone()).collect();

        let bundle = Self {
            batch_id: batch_id.to_string(),
            findings: finding_ids,
            evidence,
            merkle_root: root,
            created_at: chrono::Utc::now(),
            anchored: false,
            anchor_tx: None,
        };

        Ok(bundle)
    }
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    nodes: Vec<Vec<u8>>,
    leaf_count: usize,
}

impl MerkleTree {
    pub fn new(leaves: &[Vec<u8>]) -> Self {
        if leaves.is_empty() {
            return Self {
                nodes: vec![vec![0u8; 32]],
                leaf_count: 0,
            };
        }

        let leaf_count = leaves.len();
        let mut nodes: Vec<Vec<u8>> = leaves.to_vec();

        let mut level_start = 0;
        let mut level_len = leaf_count;

        while level_len > 1 {
            let next_start = nodes.len();
            for i in (0..level_len).step_by(2) {
                let left = &nodes[level_start + i];
                let right = if i + 1 < level_len {
                    &nodes[level_start + i + 1]
                } else {
                    left
                };
                nodes.push(hash_pair(left, right));
            }
            level_start = next_start;
            level_len = level_len.div_ceil(2);
        }

        Self {
            nodes,
            leaf_count,
        }
    }

    pub fn root(&self) -> &[u8] {
        self.nodes.last().expect("root exists")
    }

    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    pub fn proof(&self, index: usize) -> Vec<MerkleProofStep> {
        if index >= self.leaf_count {
            return Vec::new();
        }

        let mut proof = Vec::new();
        let mut idx = index;
        let mut level_start = 0;
        let mut level_len = self.leaf_count;

        while level_len > 1 {
            let sibling_idx = if idx.is_multiple_of(2) {
                if idx + 1 < level_len {
                    Some(idx + 1)
                } else {
                    None
                }
            } else {
                Some(idx - 1)
            };

            if let Some(sib) = sibling_idx {
                let is_right = idx.is_multiple_of(2);
                proof.push(MerkleProofStep {
                    hash: self.nodes[level_start + sib].clone(),
                    is_right,
                });
            }

            level_start += level_len;
            level_len = level_len.div_ceil(2);
            idx /= 2;
        }

        proof
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofStep {
    pub hash: Vec<u8>,
    pub is_right: bool,
}

fn hash_pair(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::new(&[]);
        assert_eq!(tree.root(), &[0u8; 32]);
    }

    #[test]
    fn test_single_leaf() {
        let leaf = vec![1u8; 32];
        let tree = MerkleTree::new(std::slice::from_ref(&leaf));
        assert_eq!(tree.root(), leaf.as_slice());
    }

    #[test]
    fn test_two_leaves() {
        let l1 = vec![1u8; 32];
        let l2 = vec![2u8; 32];
        let tree = MerkleTree::new(&[l1, l2]);
        let expected = hash_pair(&[1u8; 32], &[2u8; 32]);
        assert_eq!(tree.root(), expected.as_slice());
    }

    #[test]
    fn test_odd_leaves() {
        let leaves = vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]];
        let tree = MerkleTree::new(&leaves);
        assert_eq!(tree.leaf_count(), 3);
        assert_eq!(tree.root().len(), 32);
    }
}
