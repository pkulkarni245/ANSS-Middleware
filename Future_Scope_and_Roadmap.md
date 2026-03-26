# ANSS: Current Scope and Future Enterprise Roadmap

## Comprehensive Feature List
1. **Ingress Shield (Deterministic Jailbreak Detection)**: Employs an offline, deterministic SentenceTransformer (`all-MiniLM-L6-v2`) to compute cosine similarity against 15 canonical attack templates. Immediate layer-1 blocking of prompt injection and jailbreaks.
2. **Secure RAG (Verifiable Context Integrity)**: Implements semantic vector search combined with strict HMAC-SHA256 cryptographic verification of every retrieved document to prevent data poisoning.
3. **PCTL Root of Trust (Markov Chain Execution Modeling)**: Models tool execution as a Discrete-Time Markov Chain (DTMC). Uses `stormpy` and PCTL formal verification to mathematically prove a tool's safety. Suspends and hard-blocks execution upon formal logic violation.
4. **Symbolic Bridge (NLP-to-PRISM Synthesis)**: Translates natural language security intents into formal PRISM mathematics via an Azure Copilot metadata mapping layer.
5. **Dynamic Intent Manifests (HMAC Signed Capabilities)**: Prevents Confused Deputy Attacks by issuing short-lived, cryptographically signed JSON Web Tokens (`X-Intent-Manifest`) that strictly bind downstream tool execution capabilities.
6. **Semantic Egress Router (Data Leakage Prevention)**: Continuously models outgoing text generation as a DTMC, actively comparing text against sensitivity thresholds to intercept data leakage.
7. **Verification Visualizer (Azure Portal CISO Mockup)**: Interactive dashboard with Mermaid.js state-space live rendering, enabling real-time visual auditing of formal safety proofs against dynamic session states.
8. **Interactive Zero-Trust Chat Terminal**: A responsive chat interface showcasing real-time interception telemetry and architectural visualization pipelines.

---

This document outlines the product evolution strategy for ANSS, differentiating between the features successfully implemented in the current hackathon MVP, and the infrastructural upgrades required for a fully managed, 1st-party Enterprise Azure API.

## 1. Current State: The MVP Scope

During development, we successfully brought several "Phase 2" roadmap items forward into the MVP. The current working prototype boasts the following capabilities:

* **Dynamic `.prism` File Loading**: Instead of hard-coding the Markov logic in Python, the system seamlessly hot-reloads formal PRISM specification files deployed via the Portal Mockup. Security logic is successfully treated as configuration.
* **Symbolic Bridge (Automated Synthesis)**: An NLP Copilot translates English CISO policies directly into mathematically perfect PRISM `.prism` constraints.
* **Cryptographic Intent Flow**: HMAC-SHA256 tokens strictly bind tool-call requests to pre-approved capability sets, mitigating Confused Deputy attacks.
* **Verifiable Context (Proof of Concept)**: The system computes and verifies HMAC-SHA256 signatures on retrieved context using a mock in-memory vector database.
* **Integrated Control/Data Plane**: For demonstration ease, the CISO Portal (Control Plane) and the Chatbot Middleware (Data Plane) are served from the same FastAPI container.

---

## 2. Future Scope: Enterprise Production Architecture

To scale ANSS from a hackathon prototype to an enterprise-grade cloud service, we must institute strict **Separation of Concerns**, **Cryptographic Isolation**, and **Managed Identity** integration.

### A. Serverless Cryptographic Isolation
**The Challenge:** The PCTL engine (`stormpy`) currently runs in the same container as the generative LLM orchestrator. If the orchestrator is compromised via a dependency vulnerability, the Root of Trust could be altered in memory.
**The Fix:** Move the formal verification logic into an isolated **Azure Function** (Serverless Enclave). Only the specific Azure Managed Identity assigned to the FastAPI app will have the cryptographic authorization to invoke the Azure Function validator. This guarantees impenetrable Defense-in-Depth.

### B. Decoupled Control Plane vs. Data Plane
**The Challenge:** Serving the Admin UI and the End-User API from the same monolithic app introduces a massive blast radius.
**The Fix:** 
1. **Control Plane (CISO Dashboard):** Hosted on an isolated Azure Static Web App (`admin.anss.company.com`). Policies are compiled and saved securely to **Azure Blob Storage**. Access is gated by Entra ID Privileged Identity Management (PIM).
2. **Data Plane (Middleware API):** Hosted on Azure Container Apps inside a highly restricted VNet. It periodically fetches the latest compiled `.prism` policies from Blob Storage (Read-Only). It **never** has API routes to modify its own security policies.
3. **Independent Scaling:** The middleware processing high-volume end-user messages scales completely independently of the static admin portal.

### C. Azure AI Search Native Vector Indexing
**The Challenge:** The MVP utilizes an in-memory dictionary to mock vector storage and HMAC signatures.
**The Fix:** Fully integrate **Azure AI Search** with native Vector HNSW (Hierarchical Navigable Small World) indexes. During ingestion, a dedicated Azure Function will compute the deterministic HMAC-SHA256 signature and append it to the document metadata before inserting it into Azure AI Search, providing planet-scale Verifiable Context Integrity.

### D. Azure Entra ID (Active Directory) Introspection
**The Challenge:** Session attributes (like `user_authenticated` or `is_admin`) are currently handled by a local `SessionControl` mock.
**The Fix:** Natively plug the PCTL middleware into Azure Entra ID. The system will dynamically extract bearer tokens and populate the PRISM Markov Chain matrix with live organizational context (e.g., `User.RequiresMFA == True`, `User.Department == Finance`).

---

## 3. Commercialization Timeline (The "Azure Native Security API" Vision)

In its final form, ANSS is not simply a codebase that software engineers augment. Like Azure API Management or Azure Policy, ANSS is envisioned as a **managed configuration-first cloud service**.

* **Q3 Implementation (Distributed Defense-in-Depth):** Splitting the datastore, control plane, and Azure Function validator into independent Azure resources as per the Enterprise Production Architecture defined above.
* **Q4 Validation Pilot:** Pilot with an Azure tenant requiring high regulatory burden (FinServ/Healthcare) to audit the dynamic PRISM state ingestion connected to real Entra ID policies.
* **General Availability (Azure 1st-Party Target):** AI Developers write unrestricted agents using `from azure.anss import with_sentinel`. Compliance officers drag-and-drop constraints in Microsoft Defender for Cloud, silently compiling to PCTL rules enforced globally via the middleware.
