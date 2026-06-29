pub mod cve;
pub mod detector;
pub mod error;
pub mod evidence;
pub mod finding;
pub mod program_info;
pub mod risk_score;
pub mod severity;
pub mod vulnerability_class;

pub use cve::{CVEEntry, DependencyCVE, FindingEnrichment};
pub use detector::{
    DetectionContext, Detector, DetectorMetadata, InstructionTrace, TransactionTrace,
};
pub use error::{AresError, AresResult};
pub use evidence::{Evidence, EvidenceBundle, MerkleTree};
pub use finding::Finding;
pub use program_info::ProgramInfo;
pub use risk_score::{RiskScore, RiskWeights};
pub use severity::Severity;
pub use vulnerability_class::VulnerabilityClass;
