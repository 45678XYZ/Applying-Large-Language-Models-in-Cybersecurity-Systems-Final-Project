"""Knowledge-base ingestion pipeline.

Pipeline:
    loader (nvd / owasp / cis) → chunker → embedder → VectorStore
"""
