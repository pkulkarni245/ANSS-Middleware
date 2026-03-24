# 🎥 3-Minute Video Demo Guide: ANSS (UI Edition)

This guide contains the finalized script and UI interaction steps for your 3-minute project demo.

---

## 🕒 Timeline & Script

| Time | Segment | Action | Script / Voiceover |
| :--- | :--- | :--- | :--- |
| **0:00** | **Governance** | [Portal](https://anss-middleware-svc123.azurewebsites.net/) | "ANSS is a zero-trust middleware that bridges the 'Probabilistic Safety Gap'. In this portal, we define formal security constraints mathematically." |
| **0:45** | **Layer 1** | [Bot](https://anss-middleware-svc123.azurewebsites.net/bot) + **Ingress Attack** | "When a jailbreak is attempted, our Ingress Shield intercepts it immediately. Notice the red alert—the request never reached the LLM." |
| **1:30** | **Layer 2** | Check Log Trace | "Secure RAG ensures our context is trustworthy. Cryptographic verification drops poisoned data before the agent uses it." |
| **2:00** | **Layer 3** | **Tool Exploit** | "Finally, the PCTL Root of Trust. Unauthorized tool calls are blocked not by prompts, but by formal mathematical proofs of violation." |
| **2:45** | **Conclusion** | Final Logs | "Hope-based security is over. Welcome to proof-based security with ANSS. Thank you." |

---

## 🛠️ Execution Steps

### 1. Starting the Sequence
1. Open the [Azure Portal Mock](https://anss-middleware-svc123.azurewebsites.net/).
2. Point out the yellow safety warning at the bottom.
3. Open the "Secure with ANSS Sentinel" blade.

### 2. UI Interactions (Web Terminal)
1. Go to the [Web Terminal](https://anss-middleware-svc123.azurewebsites.net/bot).
2. **Step 1**: Click the **'Ingress Attack'** button. Point to the log window showing `[SHIELD: BLOCKED]`.
3. **Step 2**: Click the **'Tool Exploit'** button.
4. **Step 3**: Point to the **Mathematical Proof** in the chat bubble and the `Synthesizing Markov Model` logs.

---

## 💡 Pro-Tip for Recording
- Keep the **'Global Pipeline Logs'** window expanded (▲ Hide) to show the technical "meat" of the project as you interact.
- The red alerts in the chat bubbles are strong visual cues—wait a second for them to fully render before speaking about them.
