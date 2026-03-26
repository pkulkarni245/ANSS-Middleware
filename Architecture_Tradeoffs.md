# Architectural Tradeoffs and Engineering Constraints: ANSS

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

Implementing formal mathematical verification natively into real-time LLM inference loops introduces significant architectural complexities. This document details the precise technical tradeoffs, latency penalties, and compute constraints managed in the ANSS stack.

## 1. Latency Penalties vs. Formal Safety Guarantees

Executing the Root of Trust intercepts the LLM orchestrator exactly at the tool-calling boundary. The model checking is performed via `stormpy`, a Python binding for the C++ Storm model-checking engine (`libz3-dev`, `libgomp1`).

**The Technical Tradeoff:** 
Formal Model Checking is computationally exorbitant compared to procedural validation. Parsing the `transfer_funds.prism` file, initializing the DTMC (Discrete-Time Markov Chain) sparse matrices, and executing the exhaustive state-space search takes an average of **25ms to 50ms** of synchronous overhead per tool.
If an agent executes 5 tools sequentially in a complex ReAct (Reasoning and Acting) loop, the cumulative latency overhead compounds (~250ms). 

**The Compromise:**
We accept the P99 latency penalty because it guarantees absolutely deterministic zero-trust blockades. To mitigate file I/O latency, the engine supports pre-loading and caching compiled `.prism` binary structures in memory, reducing individual validation times to <10ms for frequently accessed tools.

## 2. Memory Footprint: Monolithic Embedder vs. Network Edge

The ANSS pipeline requires high-dimensional vector embeddings across three separate lifecycle events:
1. **Ingress Layer:** Cosine similarity against jailbreak dictionaries.
2. **Context Layer:** Vector retrieval for Secure RAG.
3. **Egress Layer:** Semantic token evaluation to intercept data leakage.

**The Technical Tradeoff:**
Calling the `text-embedding-ada-002` API endpoint for every single check introduces catastrophic network latency (adding 300ms+ round trips before the prompt even reaches the primary LLM). Conversely, utilizing a local offline embedder (`sentence-transformers/all-MiniLM-L6-v2`) drops encoding latency to ~12ms.
However, `all-MiniLM-L6-v2` consumes roughly **90MB** of resident RAM. In a containerized scaling environment, maintaining duplicate models in VRAM/RAM across distributed Python workers severely limits concurrent connection scaling.

**The Compromise:**
We utilized a Singleton Dependency Injection pattern in FastAPI. A single global instance of `SentenceTransformer` is mounted securely at app startup and shared across all middleware interceptors. While this locks the event loop marginally during the 12ms embedding encoding, it preserves massive hardware overhead and completely neuters the Azure network outbound latency penalty.

## 3. Container Co-location vs. Cryptographic Enclaving

**The Technical Tradeoff:**
For ultra-secure environments, the validation engine (`stormpy`) and the generative layer (`Semantic Kernel`) must be air-gapped across process boundaries. However, running the mathematical validator over HTTPS API calls to an isolated Azure Function introduces JSON serialization costs and virtual network (VNet) hop latencies, severely degrading the UX of real-time multi-agent interactions.

**The Prototype Implementation (Hackathon Constraints):**
Due to the constraints of the Azure for Students tier, the prototype currently mounts the `stormpy` engine inside the identical FastAPI Docker container as the orchestrator. This optimizes the execution latency to near-zero but creates a theoretical vulnerability: a highly sophisticated Remote Code Execution (RCE) payload via the web framework could overwrite the DTMC matrix mappings in Python memory.

## 4. Egress Streaming Interruption Matrices

**The Technical Tradeoff:**
The Semantic Egress Router evaluates outbound tokens dynamically to halt sensitive data leakage. Processing every single token natively via the DTMC model checker would result in computational collapse, turning a 20 Tok/sec stream into a 1 Tok/sec crawl.

**The Compromise:**
Chunked batch analysis. The Egress Watcher buffers outbound generated text into sliding temporal windows (e.g., 5-token bursts). It runs a rapid, low-weight regex heuristic; only if a probabilistic threshold is crossed does it fully pause the stream, execute the computationally expensive formal PRISM leak-evaluation, and conditionally terminate the WebSocket connection. This ensures 99% of valid streams remain hardware-accelerated, while ensuring sensitive streams are reliably bricked.

## 5. Prototype MVP vs. Envisioned Production State: Accepted Hackathon Compromises

To deliver a functional, end-to-end mathematical proof of concept within the hackathon timeframe and Azure for Students constraints, specific infrastructural tradeoffs were accepted for the MVP.

### A. Vector State: Mocked Dictionary vs. Azure AI Search
* **Production Vision:** In an enterprise environment, Verifiable Context (Secure RAG) operates atop **Azure AI Search** using native HNSW vector indexes, with HMAC-SHA256 signatures generated securely during document ingestion via an Azure Function.
* **MVP Compromise:** To avoid provisioning delays and complex network configurations, the prototype uses an in-memory Python dictionary `[mock_vector_db.json]` containing pre-computed SentenceTransformer embeddings and static HMAC signatures. We chose this because it perfectly demonstrates the *verification cryptography* without the overhead of cloud indexing.

### B. Identity Management: Static Claims vs. Azure Entra ID Introspection
* **Production Vision:** The PCTL matrix dynamically populates user constraints by introspecting active **Azure Entra ID (Azure AD)** bearer tokens (e.g., verifying `User.Department == Finance` or `Authentication.Method == MFA`).
* **MVP Compromise:** The prototype relies on a mock `SessionControl` singleton holding hardcoded state (`session_state["user_authenticated"] = True`). We accepted this liberty to allow judges and developers to instantly toggle authentication states dynamically via terminal slash commands (`/auth`, `/admin`) during the live video demo, which would be impossible with strict, rigid OAuth token flows.

### C. Policy Distribution: Local Filesystem vs. Azure Blob/App Configuration
* **Production Vision:** The CISO Control Plane (React UI) writes compiled `.prism` rulesets to a highly secured **Azure Blob Storage** container. The Data Plane (Middleware) polls this read-only blob on a cron schedule.
* **MVP Compromise:** The prototype's CISO Portal writes the `.prism` file directly to the local `./policies` directory, and the FastAPI orchestrator hot-reloads it from disk. This was done to ensure a zero-setup, one-click `python main.py` execution experience for local evaluation.

### D. Single-Process Monolith vs. Distributed Decoupling
* **Production Vision:** The generative workload (Bot UI & Semantic Kernel) runs on Azure Container Apps, while the defensive engine (`stormpy` validation) is isolated to a locked-down Serverless Azure Function to prevent container escape exploits.
* **MVP Compromise:** Both the Bot UI and the defensive interceptors are hosted inside the same FastAPI `uvicorn` instance. This allows them to share the global `SentenceTransformer` embedder in local memory, dramatically reducing the Azure compute cost and cold-start latency to zero for demonstration purposes.
