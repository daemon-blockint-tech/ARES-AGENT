pub mod severity;
pub mod vulnerability_class;
pub mod finding;
pub mod evidence;
pub mod risk_score;
pub mod program_info;
pub mod detector;
pub mod error;
pub mod cve;

pub use severity::Severity;
pub use vulnerability_class::VulnerabilityClass;
pub use finding::Finding;
pub use evidence::{Evidence, EvidenceBundle, MerkleTree};
pub use risk_score::{RiskScore, RiskWeights};
pub use program_info::ProgramInfo;
pub use detector::{Detector, DetectionContext, DetectorMetadata, TransactionTrace, InstructionTrace};
pub use error::{AresError, AresResult};
pub use cve::{CVEEntry, DependencyCVE, FindingEnrichment};
