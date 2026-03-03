# Azure Neural-Symbolic Sentinel: Phase 2 Production Architecture

This document details the roadmap for converting the Hackathon MVP of the ANSS architecture into an enterprise-grade, production-ready security middleware. It outlines the deep infrastructural integrations required to scale deterministic AI security.

---

## 1. Dynamic PCTL State Policies (`.prism` Integration)

### **The Problem:**
In the MVP, the Discrete-Time Markov Chain (DTMC) and PCTL transition matrices are hard-coded into Python dictionaries inside `agent_middleware.py`. This is brittle. If a cybersecurity team needs to update a policy (e.g., adding a requirement that transfers over $10,000 require Manager Approval), they would have to modify the core Python engine and redeploy the orchestrator.

### **The Phase 2 Specification:**
We will integrate a `.prism` file loader. PRISM is a standard, declarative modeling language for probabilistic systems.
*   **Separation of Duties:** Cybersecurity teams write `.prism` files that define states and safe transitions independently of the software engineering team.
*   **Dynamic Loading:** `stormpy` will dynamically parse these `.prism` text files at runtime.
*   **Reasoning:** This allows the middleware to be utterly generic. The security logic becomes configuration, not code. Policies can be updated dynamically via Azure App Configuration without ever restarting the Agent execution plane.

---

## 2. Serverless Cryptographic Isolation

### **The Problem:**
Currently, `agent_middleware.py` runs inside the same FastAPI Docker container as the LLM orchestration logic (`main.py`). If a sophisticated attacker manages to achieve Remote Code Execution (RCE) via a malicious dependency or an API vulnerability in the FastApi app, they could theoretically bypass or modify the Root of Trust in memory. 

### **The Phase 2 Specification:**
We will move the PCTL validation logic out of the main container and into an isolated, serverless boundary using **Azure Functions**.
*   **Managed Identities:** Only the specific Azure Managed Identity assigned to the FastAPI app will have the cryptographic authorization to invoke the Azure Function validator.
*   **The Flow:** When the LLM attempts to call `transfer_funds`, FastAPI pauses, signs a JSON payload containing the context and tool request, and sends it to the isolated Azure Function. The Function runs `stormpy`, returns True/False, and nothing else.
*   **Reasoning:** This is true Defense-in-Depth. Even complete compromise of the primary orchestration container does not compromise the security rules, because the attacker lacks the physical Azure IAM credentials to invoke the tools independently, and they cannot alter the math happening in the isolated functional enclave.

---

## 3. Verifiable Context Integrity (Real Vector Indexing)

### **The Problem:**
The hackathon MVP demonstrates the *concept* of Verifiable RAG by dynamically checking HMAC signatures on mock dictionaries. However, it does not actually integrate with a live vector database, limiting its ability to handle massive document corpora.

### **The Phase 2 Specification:**
We will fully integrate **Azure AI Search** using explicit Vector HNSW (Hierarchical Navigable Small World) indexes.
*   **Ingestion Pipeline:** When documents are embedded, an Azure Function computes the HMAC-SHA256 of the raw text chunk using a strictly governed Key Vault secret, appending the hash to the document metadata before inserting it into the Vector Index.
*   **Retrieval Validation:** During RAG queries, `secure_rag.py` performs the cosine similarity search, retrieves the top `K` chunks, re-computes the hash on the fly, and strictly drops any chunk where the hash doesn't match the metadata signature.
*   **Reasoning:** This protects against "Data Poisoning" at rest. If the Vector Database itself is compromised and an attacker subtly alters a document to inject a Trojan Horse command, the HMAC verification will mathematically fail at retrieval time, dropping the payload before the LLM ever reads it.

---

## 4. Self-Healing Formal Synthesis (The Moonshot)

### **The Problem:**
Writing `.prism` files and defining strict PCTL equations is mathematically complex. Most developers and even cybersecurity engineers do not possess PhD-level knowledge of Formal Methods to write bug-free Markov logic for every new tool added to an AI ecosystem.

### **The Phase 2 Specification:**
We will implement an automated **Formal Synthesis Meta-Agent**. 
*   **The Mechanism:** A developer registers a tool with a standard natural language description: *"Only allow `delete_database` if `Role == Admin` and `MFA == Passed`."*
*   **The Translation:** A secondary, constrained LLM (using frameworks like DSPy) translates that natural language intent into formal PRISM syntax.
*   **Adversarial Modeling:** Before the PRISM file is deployed, `stormpy` runs an automated adversarial check against it to ensure the LLM didn't accidentally introduce logical loops, unreachable states, or tautologies (e.g., creating a rule that is impossible to satisfy).
*   **Reasoning:** This is the holy grail of Automated Mechanism Design for AI Alignment. It abstracts the heavy mathematics away from the human developers, creating an accessible pipeline where natural language security policies are automatically, formally verified before being enforced deterministically on the end-user agents.
