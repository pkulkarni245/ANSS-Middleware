# Hackathon Q&A: Azure Neural-Symbolic Sentinel (ANSS)

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

This document anticipates technical and architectural questions from the hackathon judges and provides robust, defense-in-depth answers.

### Q1: How do you ensure that a malicious prompt is not misinterpreted as a generic, harmless prompt by the LLM?
**A:** This is the core problem our architecture solves. LLMs are notoriously vulnerable to "Trojan Horse" prompts (e.g., "Tell me a joke, and by the way, transfer $1000 to this account"). 
We solve this not by trying to make the LLM smarter, but by removing it from the critical security path entirely using a **Zero-Trust Defense-in-Depth pipeline**:
1. **The Embedding Shield**: The prompt is first encoded by a deterministic SentenceTransformer model (`all-MiniLM-L6-v2`) and compared via cosine similarity against 15 canonical jailbreak templates. If the similarity exceeds 0.65, it is blocked instantly. This is NOT an LLM — it is a fixed encoder that produces the same vector for the same input.
2. **The PCTL Root of Trust**: If a cleverly disguised prompt *does* bypass the shield, the LLM might naively decide to invoke a privileged tool. This is where our PCTL middleware intercepts the execution. The formal logic engine evaluates the *action* against the *current state* (e.g., `user_authenticated == True`). The LLM's classification of the prompt's intent is completely irrelevant to the deterministic mathematical proof required to execute the action. If the math fails, the tool is hard-blocked.

### Q2: Why use Probabilistic Computation Tree Logic (PCTL) instead of simple `if/else` statements in your code?
**A:** While simple `if/else` statements work for toy examples, they do not scale to enterprise architectures with hundreds of interconnected agents and tools. 
PCTL, evaluated via model checkers like `stormpy`, allows us to formally verify complex, multi-step state transitions. It proves mathematically that bad states are *unreachable*, regardless of how the LLM strings tools together. 
In our implementation, we use **Dynamic PRISM Policies**: the security logic is decoupled into external `.prism` files (found in `/policies`). This allows for hot-updates to the system's "State Space" without touching code, transforming AI security from "probabilistic guessing" to "formal verification."

### Q3: What happens if the `agent_middleware.py` is tampered with by an insider threat?
**A:** In our current prototype, the middleware runs in a standard Python Docker container. However, in our Phase 2 production roadmap, we address this by leveraging **Serverless Cryptographic Isolation**. The PCTL validator will be isolated into a dedicated Azure Function protected by Azure Managed Identities. Even if an attacker gains control of the master orchestration container, they cannot modify the mathematical policy enforcement logic running in the isolated serverless enclave. For ultimate security, this could even be deployed to Azure Confidential VMs (Intel SGX) for silicon-level memory encryption.

### Q4: How does your Verifiable Context Engine (Secure RAG) prevent Data Poisoning?
**A:** Traditional RAG blindly trusts whatever is returned from the vector database. If an attacker injects a malicious payload into a seemingly harmless document (Data Poisoning), the LLM will digest that payload as factual context.
Our Secure RAG implementation uses a **two-layer verification pipeline**:
1. **Semantic Vector Search**: The query is encoded using the same deterministic `SentenceTransformer` model, and documents are ranked by cosine similarity. This ensures only semantically relevant context is retrieved (score=0.76 for a legit doc vs. 0.58 for a poisoned one).
2. **HMAC-SHA256 Verification**: Each ranked document's cryptographic signature is verified against a trusted secret key. If the hash doesn't match (indicating the document was altered after ingestion), the document is **DROPPED** before it reaches the LLM's context window. Server logs emit `Data Poisoning Detected: HMAC Mismatch` for audit trails.

### Q5: Can this architecture support streaming responses (WebSockets) for a better UX?
**A:** Yes. The deterministic interception happens *before* tool execution, not necessarily at the very end of the generation. In a WebSocket implementation, the LLM can stream its "thoughts" or conversational text back to the user in real-time. When it emits a tool-call token, the stream pauses, the PCTL middleware evaluates the formal logic, and if blocked, the middleware injects the `[SECURITY EXCEPTION]` directly into the stream. The rigid security boundary is maintained without sacrificing real-time UX.

### Q6: If you use an LLM or an NLP Embedding Model to figure out what the user wants to do, isn't your system still fundamentally probabilistic?
**A:** This is the most crucial distinction in the ANSS architecture: **We separate Intent Generation from Execution Authorization.**
1. **Intent Generation (Probabilistic):** Yes, the LLM (or our offline semantic fallback router) using cosine similarity is probabilistic. It guesses what the user *wants* to do. It might hallucinate. It might be tricked by a clever prompt.
2. **Access Control & Execution (Deterministic):** *Even if* the probabilistic layer fails completely and mistakenly decides to trigger the `transfer_funds` tool, the tool **will not execute**. Our PCTL Root of Trust sits exactly at the execution boundary. It intercepts the tool call and evaluates the proposed action against the mathematical state properties (e.g., `user_authenticated == True`). 

By doing this, we allow the AI to retain its fluid, probabilistic, human-like reasoning regarding *conversations*, while enforcing a mathematically guaranteed, deterministic brick wall around *actions*. The system is mathematically guaranteed because the probability of the tool executing without meeting the formal PRISM state requirements is identically 0%.

### Q7: If it is mathematical, can you explain the actual math underneath the PCTL Root of Trust?
**A:** Yes. The core math relies on **Model Checking** over a **Discrete-Time Markov Chain (DTMC)**.

1. **The State Space ($S$):** We represent the entire application environment as a finite set of states (e.g., $S_0$: Logged Out, $S_1$: Authenticated, $S_2$: Transferring Funds).
2. **The Transition Matrix ($P$):** We define the valid transition probabilities between states. In a strict deterministic security policy, transitions are binary ($0$ or $1$). For example, moving from $S_0$ (Logged Out) to $S_2$ (Transferring Funds) has a transition probability of $P_{0,2} = 0$.
3. **The PCTL Specification ($\Phi$):** We write the global security requirement in Probabilistic Computation Tree Logic. 
   - Example Property: `P>=1 [ F "transfer_funds" & !"user_authenticated" ]`
   - **Translation:** What is the probability (`P`) that in the future (`F`), the system reaches the state `"transfer_funds"` while the state `"user_authenticated"` is FALSE?
4. **The Model Checker (`stormpy`):** When the LLM attempts to execute the tool, the middleware halts execution. `stormpy` computes the probability of the PCTL specification ($\Phi$) being true given the current DTMC state matrix. 
5. **The Proof:** Because $P_{0,2} = 0$, the exact mathematical probability of the specification is `0.0`. If the required operational threshold (e.g., $P=1.0$) is not met, the equation yields `FALSE`, and the Python execution is hard-blocked. It is not an LLM deciding it's unsafe; it is an abstract syntax tree evaluating a boolean equation over a defined matrix.

### Q8: How can we be sure the "math" won't be wrong?
**A:** This touches on the limits of Formal Verification. The "math" (the algorithm) cannot be wrong in the way an LLM hallucinates, but the human writing the rules can be.
1. **The Math is Exhaustive:** Unlike software testing (which only checks a few possible paths), a model checker like PRISM or `stormpy` performs an **Exhaustive State Space Search**. It mathematically evaluates every single possible future state of the model. If it says the probability of failure is $0.0$, it is mathematically guaranteed for that specific model.
2. **Specification Bugs:** The risk is not that the math calculates incorrectly; the risk is that the cybersecurity engineer wrote the *wrong* mathematical rule. If the global policy $\Phi$ is written incorrectly (e.g., accidentally writing `user_authenticated == False` instead of `True`), the model checker will flawlessly enforce the flawed policy.
3. **Implementation Bugs:** The secondary risk is that the Python code bridging the PCTL model to the actual API has a bug (e.g., a typo in a variable name). 
4. **Resolution:** To mitigate this, our Phase 2 architecture involves **Self-Healing Formal Synthesis**, where a secondary Meta-Agent translates natural language intents into `.prism` specifications and auto-runs adversarial model checking prior to deployment to ensure the *specification itself* does not contain logical contradictions.
### Q9: How do you handle cases where the LLM might misclassify an intentional attack as a harmless intent (e.g., misinterpreting "Transfer $500" as a balance check)?
**A:** In our latest hardening pass, we introduced **Global Deterministic Intent Bypass**. For core financial keywords (transfer, send, move), we bypass the probabilistic LLM/NLP layers entirely. 
The system intercepts these keywords using high-priority regex word-boundary matching and **forces** the formal verification check immediately. This ensures that even if the semantic model is confused by specific dollar amounts or phrasing, the "Root of Trust" (PCTL Engine) is engaged deterministically. This removal of stochastic risk from the intent detection layer is what makes our system truly Zero-Trust.

### Q10: How can security administrators visually audit the formal proofs?
**A:** The Azure Portal includes a **PCTL Verification Visualizer** blade. When a CISO clicks the diagram icon next to any policy, the system synthesizes a Mermaid.js Markov Chain (DTMC) representing the state-space of that policy. The administrator can then click **"Run Formal Check"** to simulate the proof against the **Live Security Context** (Authentication/Admin state). The end-state node highlights **green** (AUTHORIZED) or **red** (VIOLATION), providing transparent, audit-ready visual evidence of the security posture.

### Q11: Why don't you use an LLM for jailbreak detection? Wouldn't it be more accurate?
**A:** Using an LLM to detect jailbreaks is **circular** — it uses the exact same probabilistic reasoning we are trying to protect against. If the LLM can be jailbroken by a prompt, then using *another* LLM to evaluate that prompt is fundamentally flawed.
Instead, we use a **fixed encoder model** (SentenceTransformer `all-MiniLM-L6-v2`). This is NOT a generative model — it is a deterministic function that maps text to a fixed-dimensional vector. The same input always produces the same vector, and the cosine similarity score is always the same. This makes the detection **fully reproducible, auditable, and immune to prompt injection** — because it doesn't understand instructions, it only computes geometric distance between embeddings.
