# Foundational Design Decisions: ANSS

## Comprehensive Feature List
1. **Ingress Shield (Deterministic Jailbreak Detection)**: Employs an offline, deterministic SentenceTransformer (`all-MiniLM-L6-v2`) to compute cosine similarity against canonical attack templates. Immediate layer-1 blocking of prompt injection and jailbreaks.
2. **Secure RAG (Verifiable Context Integrity)**: Implements semantic vector search combined with strict HMAC-SHA256 cryptographic verification of every retrieved document to prevent data poisoning.
3. **PCTL Root of Trust (Markov Chain Execution Modeling)**: Models tool execution as a Discrete-Time Markov Chain (DTMC). Uses `stormpy` and PCTL formal verification to mathematically prove a tool's safety. Suspends and hard-blocks execution upon formal logic violation.
4. **Symbolic Bridge (NLP-to-PRISM Synthesis)**: Translates natural language security intents into formal PRISM mathematics via an Azure Copilot metadata mapping layer.
5. **Dynamic Intent Manifests (HMAC Signed Capabilities)**: Prevents Confused Deputy Attacks by issuing short-lived, cryptographically signed JSON Web Tokens (`X-Intent-Manifest`) that strictly bind downstream tool execution capabilities.
6. **Semantic Egress Router (Data Leakage Prevention)**: Continuously models outgoing text generation as a DTMC, actively comparing text against sensitivity thresholds to intercept data leakage.
7. **Verification Visualizer (Azure Portal CISO Mockup)**: Interactive dashboard with Mermaid.js state-space live rendering, enabling real-time visual auditing of formal safety proofs against dynamic session states.
8. **Interactive Zero-Trust Chat Terminal**: A responsive chat interface showcasing real-time interception telemetry and architectural visualization pipelines.

---

This document outlines the foundational engineering decisions and core philosophy underpinning the Azure Neural-Symbolic Sentinel (ANSS). It focuses on *why* the architecture is structured this way to solve the fundamental vulnerabilities of generative models.

## 1. The Separation of Reasoning and Execution

**Decision:** ANSS strictly decouples the AI's probabilistic reasoning layer (Semantic Kernel + Azure OpenAI) from the determinist execution boundary (PCTL Middleware).

**Technical Justification:**
Modern safety frameworks attempt to bound LLM behaviors probabilistically through system prompts (e.g., "You are a helpful assistant. Do not execute destructive commands"). This relies on the model's internal attention mechanisms remaining stable. However, token sequence probabilities are inherently malleable. Advanced jailbreaks, data poisoning, or adversarial perturbations can shift the probabilistic distribution, causing the LLM to prioritize the malicious instruction over its alignment protocols.

By separating reasoning from execution, we operate under a true **Zero-Trust Assumption**: The LLM is assumed to be in a perpetually compromised state. Even if the orchestrator hallucinates an intent to invoke the `delete_database` tool, the mathematical execution boundary acts as an impenetrable firewall. The execution block operates entirely independently of the LLM's probability matrix.

## 2. Formal Methods in Agentic Flows over Procedural Validation

**Decision:** We utilize formal model checking (Probabilistic Computation Tree Logic - PCTL) rather than procedural `if/else` guardrails for tool authorization.

**Technical Justification:**
Traditional application layers rely on simple boolean validation (`if action == "transfer" and not mfa: raise Error`). While sufficient for strict web APIs, agentic loops allow LLMs to sequence tools in stochastic, highly unpredictable chains. This leads to **state space explosion**, where security engineers cannot procedurally anticipate the precise sequence of intermediate tool calls that might put the system in a vulnerable state.

By declaring valid system states as a Discrete-Time Markov Chain (DTMC) using the `stormpy` C++ library, we transition from *testing* (probing specific paths) to *verification* (exhaustively proving all paths). The global PCTL constraint `P<=0 [ F "unauthorized_tool_execution" ]` ensures that the mathematical probability of reaching the forbidden node is identically zero, irrespective of the traversal path the LLM orchestrator generated.

## 3. Cryptographic Validation of RAG Payload Matrices

**Decision:** Every piece of context ingested into the Vector Database is cryptographically signed via HMAC-SHA256. At retrieval time (RAG), the cosine similarity ranking is superseded by signature validation.

**Technical Justification:**
LLM context windows are vulnerable to **Data Poisoning** and **Indirect Prompt Injection**. If an attacker embeds a payload inside a document (e.g., a candidate's resume injected into the vector DB), the LLM reads that semantic data as a literal instruction, conflating the data plane with the control plane.

We mitigate this by treating the vector database exactly like an untrusted public network. During ingestion, a secure enclave signs the document chunk. During the vector similarity search, `secure_rag.py` re-computes the hash using the enclave's symmetric key. If the hash fails (indicating tampering post-ingestion), the document is completely excised from the LLM's context window. This prevents poisoned embeddings from ever influencing the generative attention heads.

## 4. The Symbolic Bridge: Abstracting Formal Verification

**Decision:** We implemented a Meta-Agent routing layer (Symbolic Bridge) to synthesize formal `.prism` specification files derived directly from natural language compliance policies.

**Technical Justification:**
Cybersecurity analysts (CISOs) understand compliance boundaries ("Contractors cannot read financial tables without VDI access") but are generally not trained in Markov logic or PRISM equation syntax.

The Symbolic Bridge acts as a deterministic compiler. Using semantic extraction, it maps entities (`Contractor`), actions (`read_financials`), and constraints (`requires_vdi`) into strict PRISM language. This allows ANSS to be deployed at immense enterprise scale: human compliance officers interact with declarative natural language, while the underlying pipeline operates strictly on mathematically indisputable graph traversals.
