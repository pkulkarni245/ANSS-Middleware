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

## 3. Azure AI Content Safety as an Ingress API Firewall

### The Decision
We placed Azure AI Content Safety (Prompt Shields) at the very edge of the network, before the request even hits the Orchestrator's internal RAG pipeline or the LLM.

### Tradeoffs
*   **Pros (Defense-in-Depth):** This acts as an early-termination filter. By blocking obvious jailbreaks or toxic content immediately (`403 Forbidden`), we save compute cycles, reduce API costs for the LLM, and prevent the malicious payload from ever entering the vulnerable context window.
*    **Cons (False Positives & API Latency):** The Content Safety API requires an additional outbound HTTP request, adding ~100-200ms of latency to the total Round Trip Time (RTT). Furthermore, strict deterministic filters can occasionally flag legitimate, benign queries that use aggressive phrasing as false positives, degrading the UX.

---

## 4. Cryptographic RAG Verification vs. Standard VDB Retrieval

### The Decision
We implemented `secure_rag.py` to dynamically verify the HMAC signatures of documents retrieved from Azure AI Search against keys stored in Azure Key Vault.

### Tradeoffs
*   **Pros (Trust Boundary):** This neutralizes Data Poisoning attacks. If an attacker injects a malicious invisible prompt into a PDF stored in the vector database, the lack of a valid HMAC signature will flag it, and the architecture will drop the poisoned context before feeding it to the LLM.
*   **Cons (Ingestion Complexity):** This requires a much more complex data ingestion pipeline. Every legitimate document uploaded to the system *must* have its hash calculated, signed via Key Vault, and stored as metadata in the search index before it can be used. It makes updating knowledge bases significantly harder.

---

## 5. Prototype Scope Constraints (Azure for Students)

### The Decision
Due to the constraints of the Azure for Students tier, we deployed the entire orchestration logic (FastAPI + Agent + Middleware) into a single Azure App Service Container, rather than splitting the PCTL validator into a physically isolated Confidential VM (Intel SGX).

### Tradeoffs
*   **Pros (Cost & Accessibility):** Fit perfectly within the free-tier constraints, allowing rapid iteration and deployment for the hackathon without requiring special hardware allocations or complex VNet peering.
*   **Cons (Security Architecture Flaw):** In a production environment, having the security validator reside in the same memory space and container as the vulnerable LLM orchestrator is an anti-pattern. An RCE (Remote Code Execution) vulnerability in FastAPI could allow an attacker to bypass the middleware entirely. 
*   **Mitigation (Phase 2):** As outlined in the Phase 2 plan, moving the validator to an isolated Azure Function utilizing Managed Identity RBAC provides the necessary cryptographic isolation using PAAS components within the student tier.
