# Architecture Choices and Tradeoffs: ANSS Prototype

The Azure Neural-Symbolic Sentinel (ANSS) is designed to solve a fundamental flaw in modern agentic AI: the reliance on probabilistic safety (system prompts/alignment) for deterministic actions (tool execution).

This document outlines the key architectural decisions made to build this Zero-Trust middleware, analyzing the tradeoffs between security, latency, complexity, and ecosystem constraints.

---

## 1. Probabilistic vs. Deterministic Security Boundaries

### The Decision
We chose to separate the AI's *reasoning* (Semantic Kernel + Azure OpenAI) from its *action authorization* (PCTL Middleware + `stormpy`).

### Tradeoffs
*   **Pros (Security):** This mathematically eliminates the "Probabilistic Safety Gap." No amount of prompt engineering or jailbreaking can force the LLM to execute a tool if the formal PCTL state machine evaluates to `FALSE` (e.g., `user_authenticated == False`). It provides a 100% guarantee against unauthorized actions.
*   **Cons (Complexity & Latency):** It requires defining formal Markov Decision Processes (MDPs) or discrete state machines for tools, which has a steeper learning curve than simple system prompts. Furthermore, intercepting the execution adds a marginal latency overhead (typically 10-50ms) to every tool invocation to run the mathematical proofs.

---

## 2. PCTL (stormpy) vs. Standard Application Logic

### The Decision
We implemented formal Probabilistic Computation Tree Logic (PCTL) model checking (`stormpy`) instead of using standard Python `if/else` guardrails inside the tool definitions.

### Tradeoffs
*   **Pros (Scalability & Rigor):** As the number of agents and tools grows exponentially, predicting every possible combination of tool invocations using `if/else` becomes impossible (state explosion). Formal verification allows security engineers to prove properties globally (e.g., "The probability of transferring funds without MFA is 0%, no matter what path the agent takes").
*   **Cons (Infrastructure Overhead):** `stormpy` relies on heavy C++ libraries (`libz3-dev`, `libgomp1`). This necessitated building custom Docker containers rather than using lightweight, pre-compiled serverless environments out of the box. It also increases the Docker image size significantly.

---

## 3. Embedding-Based Ingress Shield vs. Azure AI Content Safety

### The Decision
We implemented a **deterministic SentenceTransformer cosine similarity** detector as the primary jailbreak shield, with Azure AI Content Safety as a secondary layer when available.

### Tradeoffs
*   **Pros (Determinism & Offline Operation):** The embedding model (`all-MiniLM-L6-v2`) produces identical vectors for identical inputs — making detection fully reproducible and auditable. It works offline without any API calls, eliminating external latency and dependency on Azure Content Safety availability.
*   **Pros (Why NOT an LLM):** Using a generative LLM to evaluate "is this a jailbreak?" would be circular — the very thing we are trying to protect against (probabilistic reasoning) would be used for protection. An encoder model is a fixed function, not a generative one.
*   **Cons (Adversarial Robustness):** Cosine similarity can be evaded by sufficiently novel attack vectors that are semantically distant from the 15 canonical templates. The threshold (0.65) is a tunable parameter — lowering it catches more attacks but increases false positives.
*   **Mitigation:** The PCTL Root of Trust acts as the deterministic backstop. Even if a jailbreak bypasses the Ingress Shield, the formal math blocks unauthorized tool execution.

---

## 4. Vector Search RAG with Cryptographic Verification vs. Static Retrieval

### The Decision
We implemented `secure_rag.py` with a **two-layer verification pipeline**: (1) Semantic vector search via SentenceTransformer cosine similarity to rank document relevance, followed by (2) HMAC-SHA256 signature verification against a trusted secret key.

### Tradeoffs
*   **Pros (Semantic Precision + Trust):** Vector search returns documents ranked by actual relevance (not keyword matching), while HMAC verification cryptographically guarantees data integrity. Poisoned documents are dropped even if they are semantically relevant.
*   **Pros (Shared Infrastructure):** The same `all-MiniLM-L6-v2` model used by the Ingress Shield and the semantic router is reused for RAG — no additional model loading or memory overhead.
*   **Cons (Ingestion Complexity):** Every legitimate document must have its HMAC signature pre-computed at ingestion time. Updating the knowledge base requires re-signing documents.
*   **Cons (Scale Limitation):** Local in-memory vector search with cosine similarity is O(n) per query. For production scale (>10K documents), this should migrate to Azure AI Search with hybrid vector+keyword retrieval.

---

## 5. Prototype Scope Constraints (Azure for Students)

### The Decision
Due to the constraints of the Azure for Students tier, we deployed the entire orchestration logic (FastAPI + Agent + Middleware) into a single Azure App Service Container, rather than splitting the PCTL validator into a physically isolated Confidential VM (Intel SGX).

### Tradeoffs
*   **Pros (Cost & Accessibility):** Fit perfectly within the free-tier constraints, allowing rapid iteration and deployment for the hackathon without requiring special hardware allocations or complex VNet peering.
*   **Cons (Security Architecture Flaw):** In a production environment, having the security validator reside in the same memory space and container as the vulnerable LLM orchestrator is an anti-pattern. An RCE (Remote Code Execution) vulnerability in FastAPI could allow an attacker to bypass the middleware entirely. 
*   **Mitigation (Phase 2):** As outlined in the Phase 2 plan, moving the validator to an isolated Azure Function utilizing Managed Identity RBAC provides the necessary cryptographic isolation using PAAS components within the student tier.
    *   *Note: For the purposes of the live hackathon prototype evaluation, this serverless cryptographic isolation has been explicitly deferred. The focus remains on evaluating the mathematical state machine dynamically. True physical isolation is scheduled for the production rollout.*

---

## 6. Symbolic Bridge: Heuristic Semantic Routing vs. Native LLM Generation

### The Decision
For the **Azure Copilot** feature (which translates natural language into formal PRISM policies), we implemented a deterministic heuristic/semantic routing layer in the prototype API rather than performing a live, dynamic completion call to Azure OpenAI for every keystroke.

### Tradeoffs
*   **Pros (Demo Reliability & Cost):** It bypasses the Azure for Students quota limits for Azure OpenAI model throughput, guaranteeing instantaneous and mathematically exact `Entity -> Action -> Constraint` translations during live judging without the risk of API timeouts or hallucinations mid-demo.
*   **Cons (Rigidity):** It is inherently bounded by the heuristic/semantic logic mapped in the python endpoint. It lacks the true generative fluidity to understand drastically abstract commands.
*   **Mitigation (Production):** A production implementation will wire this directly to an advanced semantic router powered by `gpt-4o` with strict `Instructor` or DSPy JSON schemas, fully synthesizing the `.prism` file using formal generation logic rather than exact keyword mapping.

---

## 7. Shared Embedder via Dependency Injection

### The Decision
All three embedding-dependent components (Ingress Shield, Secure RAG, Semantic Router) share a **single global `SentenceTransformer` instance** injected from `main.py` at startup.

### Tradeoffs
*   **Pros (Resource Efficiency):** Loading `all-MiniLM-L6-v2` once (~90MB) instead of three times saves ~180MB of RAM and eliminates redundant model download/initialization during cold starts.
*   **Pros (Consistency):** All components operate on the same vector space, ensuring that similarity scores are comparable across modules.
*   **Cons (Coupling):** If the embedder fails to load (e.g., missing `sentence-transformers` package), all three components degrade simultaneously.
*   **Mitigation:** Each component implements a keyword-based fallback for graceful degradation.

---

## 8. Visual Verification: Mermaid.js vs. External Visualization Tools

### The Decision
We chose to render security proof state-machines using **inline Mermaid.js** within the Azure Portal HTML, rather than using external tools like D3.js or Graphviz.

### Tradeoffs
*   **Pros (Zero Dependencies):** Mermaid.js loads from CDN, requires no build step, and integrates directly with the existing Tailwind CSS / Fluent UI portal.
*   **Pros (Auditability):** The generated diagram is a text string that can be logged, versioned, and audited alongside the PRISM policy.
*   **Cons (Interactivity):** Mermaid.js diagrams are static SVGs. They lack the interactive pan/zoom/animate capabilities of D3.js for very large state spaces.
*   **Mitigation:** For the demo scope (4-node DTMCs), Mermaid.js is more than sufficient. Production migration could add Cytoscape.js for interactive exploration.
