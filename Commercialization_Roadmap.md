# Azure Neural-Symbolic Sentinel (ANSS): Commercialization Roadmap

This document outlines the product evolution strategy for ANSS, transitioning from a localized hackathon MVP to a fully managed, 1st-party Azure API.

## The Vision: Azure Native Security API
In its final form, ANSS is not simply a piece of code that software engineers embed into their applications. Like **Azure API Management** or **Azure Policy**, ANSS is envisioned as a distributed, configuration-first cloud service.

In the final state (Phase 3), the Enterprise CISO sets the organizational constraints ("No data deletions without MFA") in the Azure Portal. The AI Developer simply imports the `azure.anss` SDK, and the orchestration layer automatically inherits the global state constraints dynamically.

---

### Phase 1: Minimum Viable Concept (The Hackathon MVP)
**Status:** Completed
**Focus:** Proving the Mathematics 

*   **Architecture:** Monolithic integration. The Ingress API Firewall, the Verifiable RAG index, and the `stormpy` PCTL Model Checker are bundled locally alongside the LLM Orchestrator in a single Python execution environment.
*   **Configuration:** "Out-of-the-box" logic. Security logic and DTMC (Markov Chain) state mappings are hardcoded into Python dictionaries.
*   **Result:** Mathematically proves that Probabilistic AI can be deterministically constrained off-path.

### Phase 2: Distributed Defense-in-Depth
**Status:** In Development
**Focus:** Separation of Duties and Cryptographic Isolation

*   **Architecture:** Decentralized. The `stormpy` Model Checker is moved to a Serverless **Azure Function**. Let's refer to our existing `Phase2_Architecture.md` document for the mechanical breakdown. 
*   **Configuration:** The shift to **.prism file loading**. Instead of software engineers writing Python configurations, Cybersecurity Teams define mathematical policies in declarative text, and Azure App Configuration injects them into the Azure Function runtime.
*   **Result:** Physically isolates the validation engine from the generative engine. Compromising the LLM container provides zero access to the Security state machine.

### Phase 3: the Azure 1st-Party Target (General Availability)
**Status:** Future Product Vision
**Focus:** Cloud-Native Governance & Managed Service integration

*   **Architecture:** ANSS becomes an **Azure Control Plane API**. Customers provision an "ANSS Sentinel App" via Azure Resource Manager (ARM/Bicep).
*   **Azure AD (Entra ID) Introspection:** The PCTL engine natively plugs into Entra Identity. It extracts bearer tokens and dynamically populates the DTMC matrix with live tenant Context (e.g. `User.RequiresMFA == True`, `User.Department == Finance`).
*   **Configuration (The End User):** 
    1.  **AI Developers:** Write normal, unrestricted agents. They simply add a wrapper: `from azure.anss import with_sentinel`.
    2.  **Compliance / Admistrators:** Use a No-Code UI in the Azure Portal (or Microsoft Defender for Cloud) to set boundaries. By dragging and dropping logic blocks (e.g. "Operations tagged 'Financial' require 'MFA'"), the portal silently compiles the declarative Ruleset into PCTL rules distributed globally.
*   **Result:** Zero-Trust AI governance at hyper-scale. Total separation between the AI Engineering teams building the workflow and the Cyber Governance teams defining the boundaries.

---

### Timeline & Next Steps
1.  **Q3 Implementation:** Formal Synthesis Translation. Building an LLM Meta-Agent designed *solely* for translating English CISO compliance rules into flawless PRISM syntax.
2.  **Q4 Validation Trial:** Pilot with an Azure tenant requiring high regulatory burden (FinServ/Healthcare) to audit the dynamic PRISM state ingestion.
