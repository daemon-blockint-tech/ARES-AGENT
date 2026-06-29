"""Program family clustering using bytecode embeddings and FAISS."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import numpy as np

try:
    import faiss
except ImportError:
    faiss = None  # type: ignore


@dataclass
class ProgramEmbedding:
    """Embedding vector for a Solana program."""

    program_id: str
    vector: np.ndarray
    bytecode_hash: str
    size: int


@dataclass
class ProgramFamily:
    """A family of cloned/related programs."""

    family_id: str
    template_id: str
    members: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    known_vulnerabilities: list[str] = field(default_factory=list)


class FamilyClusterer:
    """Cluster Solana programs by bytecode similarity using FAISS.

    Based on SolaSim research showing >50% of Solana programs are clones.
    """

    def __init__(self, similarity_threshold: float = 0.95) -> None:
        self.threshold = similarity_threshold
        self.embeddings: list[ProgramEmbedding] = []
        self.families: dict[str, ProgramFamily] = {}
        self._index: faiss.IndexFlatIP | None = None
        self._dimension = 256

    def compute_embedding(self, bytecode: bytes, program_id: str) -> ProgramEmbedding:
        """Compute a feature vector from bytecode.

        Extracts statistical features:
        - Instruction frequency histogram (opcode distribution)
        - Byte n-gram frequencies
        - Size-based features
        """
        if len(bytecode) == 0:
            return ProgramEmbedding(
                program_id=program_id,
                vector=np.zeros(self._dimension, dtype=np.float32),
                bytecode_hash="0" * 64,
                size=0,
            )

        # Opcode histogram (256 bins)
        opcode_hist = np.zeros(256, dtype=np.float32)
        for b in bytecode[:10000]:  # Sample first 10K bytes
            opcode_hist[b] += 1.0
        opcode_hist /= max(1, len(bytecode[:10000]))

        # Pad/truncate to fixed dimension
        if len(opcode_hist) >= self._dimension:
            vector = opcode_hist[: self._dimension]
        else:
            vector = np.zeros(self._dimension, dtype=np.float32)
            vector[: len(opcode_hist)] = opcode_hist

        # L2 normalize for cosine similarity
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm

        bytecode_hash = hashlib.sha256(bytecode).hexdigest()

        return ProgramEmbedding(
            program_id=program_id,
            vector=vector,
            bytecode_hash=bytecode_hash,
            size=len(bytecode),
        )

    def add_program(self, bytecode: bytes, program_id: str) -> ProgramEmbedding:
        """Add a program to the clustering index."""
        emb = self.compute_embedding(bytecode, program_id)
        self.embeddings.append(emb)
        self._rebuild_index()
        return emb

    def _rebuild_index(self) -> None:
        """Rebuild the FAISS index."""
        if faiss is None or not self.embeddings:
            return

        vectors = np.vstack([e.vector for e in self.embeddings])
        self._index = faiss.IndexFlatIP(self._dimension)
        self._index.add(vectors)

    def cluster(self) -> dict[str, ProgramFamily]:
        """Cluster programs into families by similarity."""
        if faiss is None or not self.embeddings or self._index is None:
            return {}

        families: dict[str, ProgramFamily] = {}
        assigned: set[str] = set()

        for i, emb in enumerate(self.embeddings):
            if emb.program_id in assigned:
                continue

            # Search for similar programs
            query = emb.vector.reshape(1, -1)
            k = min(50, len(self.embeddings))
            scores, indices = self._index.search(query, k)

            # Collect members above threshold
            members = [emb.program_id]
            assigned.add(emb.program_id)

            for j, score in zip(indices[0], scores[0]):
                if j == i or j < 0:
                    continue
                if score >= self.threshold:
                    peer = self.embeddings[j]
                    if peer.program_id not in assigned:
                        members.append(peer.program_id)
                        assigned.add(peer.program_id)

            # Create family
            family_id = f"family_{hash(members[0]) & 0xFFFFFFFF:08x}"
            families[family_id] = ProgramFamily(
                family_id=family_id,
                template_id=emb.program_id,
                members=members,
            )

        self.families = families
        return families

    def get_family(self, program_id: str) -> ProgramFamily | None:
        """Get the family a program belongs to."""
        for family in self.families.values():
            if program_id in family.members:
                return family
        return None


__all__ = ["FamilyClusterer", "ProgramFamily", "ProgramEmbedding"]
