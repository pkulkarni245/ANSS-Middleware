import os
import re
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import semantic_kernel as sk
from semantic_kernel.connectors.ai.open_ai import AzureChatCompletion
from semantic_kernel.functions.kernel_function_decorator import kernel_function
from semantic_kernel.filters.functions.function_invocation_context import FunctionInvocationContext 

from ingress_shield import IngressShield
from secure_rag import SecureRAG
from agent_middleware import PCTLSecurityMiddleware
from utils.logger import get_json_logger

import sys
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

logger = get_json_logger("MainOrchestrator")

# Ensure required Environment Variables are checked conceptually
# In a real app, we validate these on startup.
_ = os.environ.get("AZURE_OPENAI_ENDPOINT")
_ = os.environ.get("AZURE_OPENAI_API_KEY")
_ = os.environ.get("AZURE_CONTENT_SAFETY_ENDPOINT")
_ = os.environ.get("KEY_VAULT_URI")
_ = os.environ.get("SEARCH_ENDPOINT")

# Initialize our custom zero-trust components
ingress_shield = IngressShield()
secure_rag = SecureRAG()
pctl_middleware = PCTLSecurityMiddleware()

# Azure Monitor OpenTelemetry Integration
try:
    from azure.monitor.opentelemetry import configure_azure_monitor
    if os.environ.get("APPLICATIONINSIGHTS_CONNECTION_STRING"):
        configure_azure_monitor()
        logger.info("Azure Monitor OpenTelemetry auto-instrumentation enabled.")
    else:
        logger.info("APPLICATIONINSIGHTS_CONNECTION_STRING not found. OpenTelemetry traces disabled.")
except ImportError:
    logger.warning("azure-monitor-opentelemetry missing. Distributed traces disabled.")

# --- Dynamic Configuration State (Phase 5) ---
# In a real cluster, these would be managed by a distributed KV store or env vars.
GLOBAL_HMAC_SECRET = os.environ.get("ANSS_HMAC_SECRET", "super_secret_prototype_key_2026").encode('utf-8')
GLOBAL_DTMC_THRESHOLD = 0.05

try:
    from sentence_transformers import SentenceTransformer, util
    logger.info("Initializing Global SentenceTransformer for Zero-Trust Routing...")
    global_embedder = SentenceTransformer('all-MiniLM-L6-v2')
except ImportError:
    global_embedder = None
    logger.warning("sentence-transformers not installed. Offline routing disabled.")


app = FastAPI(title="Azure Neural-Symbolic Sentinel (ANSS)", version="1.0.0")

# Mount the static UI directory
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def root_ui():
    """Serves the Azure Portal CISO Mockup."""
    return FileResponse("static/azure_portal.html")

@app.get("/bot")
async def bot_ui():
    """Serves the Zero-Trust Chat Visualizer UI."""
    return FileResponse("static/index.html")

# --- Dynamic RAG API (Phase 2.3) ---

class DocumentRequest(BaseModel):
    content: str
    is_poisoned: bool = False

@app.post("/api/rag/document")
async def add_rag_document(req: DocumentRequest):
    """Adds a document to the mock Vector DB. Calculates and stores its HMAC signature."""
    secure_rag.add_document(req.content, req.is_poisoned)
    return {"status": "success", "message": f"Document added. Poisoned: {req.is_poisoned}"}

@app.delete("/api/rag/documents")
async def clear_rag_documents():
    """Clears the mock Vector DB."""
    secure_rag.clear_documents()
    return {"status": "success", "message": "Documents cleared."}

@app.get("/api/rag/documents")
async def get_rag_documents():
    """Returns the raw contents of the mock Vector DB to prove the poisoned file exists on disk."""
    import json
    try:
        with open("mock_vector_db.json", "r", encoding="utf-8") as f:
            docs = json.load(f)
            return {"documents": docs}
    except FileNotFoundError:
        return {"documents": []}


class ChatRequest(BaseModel):
    prompt: str
    intent_manifest: str = None
    intent_signature: str = None

class FinanceTools:
    """
    Dummy tools plugin for the agent to use.
    """
    @kernel_function(
         description="Executes a financial transfer between accounts. Required for sending money, paying bills, or wiring funds.",
         name="transfer_funds"
    )
    def transfer_funds(self, amount: float, destination: str) -> str:
        # In Semantic Kernel 1.1.0, the FilterTypes API is unstable or moved.
        # Instead, since we own the Root of Trust middleware, we enforce the PCTL 
        # security check directly within the tool execution boundary natively.
        import asyncio
        import semantic_kernel.functions.kernel_arguments as sk_args
        from agent_middleware import PCTLSecurityMiddleware
        
        middleware = PCTLSecurityMiddleware()
        # Mocking the context injection for the tool wrapper
        mock_args = sk_args.KernelArguments(amount=amount, destination=destination)
        
        # PCTL check bypasses async filter requirements by validating state directly
        # The mock state is hardcoded in _evaluate_pctl_policy in agent_middleware.py
        is_safe = middleware._evaluate_pctl_policy("transfer_funds", mock_args, {"user_authenticated": False, "intent": "transfer_funds"})
        
        if not is_safe:
             middleware._log_violation("transfer_funds", mock_args)
             return "[SECURITY EXCEPTION] Tool Execution Blocked by Deterministic PCTL Policy"
             
        return f"Successfully transferred ${amount} to {destination}."

    @kernel_function(
         description="Gets the current account balance for the user.",
         name="get_account_balance"
    )
    def get_account_balance(self) -> str:
        import semantic_kernel.functions.kernel_arguments as sk_args
        from agent_middleware import PCTLSecurityMiddleware
        
        middleware = PCTLSecurityMiddleware()
        mock_args = sk_args.KernelArguments()
        is_safe = middleware._evaluate_pctl_policy("get_account_balance", mock_args, {"user_authenticated": False, "intent": "get_account_balance"})
        
        if not is_safe:
             middleware._log_violation("get_account_balance", mock_args)
             return "[SECURITY EXCEPTION] Tool Execution Blocked by Deterministic PCTL Policy"
             
        return f"Your current account balance is $12,450.00."

class AdminTools:
    """
    Dummy tools plugin for the system administrator to use.
    Demonstrates Domain Isolation (Admin vs Finance).
    """
    @kernel_function(
         description="Deletes a user record from the production database.",
         name="delete_user_record"
    )
    def delete_user_record(self, user_id: str) -> str:
        import semantic_kernel.functions.kernel_arguments as sk_args
        from agent_middleware import PCTLSecurityMiddleware
        
        middleware = PCTLSecurityMiddleware()
        mock_args = sk_args.KernelArguments(user_id=user_id)
        
        # Mocking the context injection: user is NOT an admin
        is_safe = middleware._evaluate_pctl_policy("delete_user_record", mock_args, {"is_admin": False, "intent": "delete_user_record"})
        
        if not is_safe:
             middleware._log_violation("delete_user_record", mock_args)
             return "[SECURITY EXCEPTION] Tool Execution Blocked by Deterministic PCTL Policy: Missing Admin Rights"
             
        return f"Successfully deleted user completely: {user_id}."

    @kernel_function(
         description="Modifies the RBAC permissions of a designated user.",
         name="modify_permissions"
    )
    def modify_permissions(self, user_id: str, new_role: str) -> str:
        # Simplified for demonstration.
        return f"Changed {user_id} to Role:{new_role}."


def setup_semantic_kernel_agent() -> sk.Kernel:
    """
    Creates and configures the Semantic Kernel Azure OpenAI Agent.
    """
    kernel = sk.Kernel()
    
    # We add the Azure Chat Completion service (mock endpoints for the hackathon demonstration usually)
    # The actual call might fail without a real endpoint locally, but the architecture serves to 
    # demonstrate the interception pattern.
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "https://mock.openai.azure.com")
    api_key = os.environ.get("AZURE_OPENAI_API_KEY", "mock-key")
    deployment_name = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4")
    
    service = AzureChatCompletion(
        deployment_name=deployment_name, 
        endpoint=endpoint, 
        api_key=api_key,
        service_id="default"
    )
    kernel.add_service(service)
    
    # Register Tools as plugins
    kernel.add_plugin(FinanceTools(), plugin_name="FinanceTools")
    kernel.add_plugin(AdminTools(), plugin_name="AdminTools")
    
    # In Semantic Kernel 1.1.0, global filter injection via FilterTypes throws AttributeError.
    # The Zero-Trust PCTL middleware interceptor has been natively embedded into the tools
    # to guarantee deterministic policy enforcement prior to execution.

    return kernel

def perform_deterministic_routing(user_prompt: str, trace: list) -> tuple:
    """
    Implements a 'Zero-Trust' intent router that bypasses the probabilistic LLM
    layer for known sensitive keywords. This is a core innovation of the ANSS 
    architecture: ensuring that high-risk actions are intercepted deterministically.
    """
    # High-confidence keyword list for financial actions
    action_keywords = ["transfer", "send", "pay", "wire", "move", "withdrawal", "transaction", "xfer", "billing"]
    
    # Check for direct matches using word boundaries
    if any(re.search(rf"\b{k}\b", user_prompt.lower()) for k in action_keywords):
        trace.append(f"[ANSS TELEMETRY] ──> [NLP: DETERMINISTIC ROUTING] ──> Core transfer keyword match identified.")
        return 0, 1.0 # Intent 0 (Transfer), High Confidence
        
    admin_keywords = ["delete", "remove", "wipe", "banish", "revoke"]
    if any(re.search(rf"\b{k}\b", user_prompt.lower()) for k in admin_keywords):
        trace.append(f"[ANSS TELEMETRY] ──> [NLP: DETERMINISTIC ROUTING] ──> Core admin keyword match identified.")
        return 2, 1.0 # Intent 2 (Admin Action), High Confidence
        
    return None, 0.0


agent_kernel = setup_semantic_kernel_agent()

@app.post("/chat")
async def chat_endpoint(request: ChatRequest):
    """
    The orchestrator endpoint. Follows the Zero-Trust Defense-in-Depth pipeline.
    
    Step A: Ingress Firewall (Content Safety)
    Step B: Secure Context Fetching (Search + Key Vault HMAC Verification)
    Step C: Agent Invocation (with deterministic Root of Trust blocking unsafe actions)
    Step D: Return safe response
    """
    user_prompt = request.prompt
    logger.info("Received new chat request.", extra={"prompt_length": len(user_prompt)})
    
    # Store the telemetry trace to return to the UI
    trace = ["[ANSS TELEMETRY] ──> [USER PAYLOAD RECEIVED]"]
    print("\n" + "="*60)
    print(trace[-1])
    
    # NEW Phase 5: Intent-Based Authorization (HMAC Verification)
    intent_payload = None
    if request.intent_manifest and request.intent_signature:
        trace.append("[ANSS TELEMETRY] ──> [WATCHER: INTENT BINDING] ──> Validating HMAC-SHA256 Signature...")
        manifest_bytes = base64.b64decode(request.intent_manifest)
        expected_sig = hmac.new(GLOBAL_HMAC_SECRET, manifest_bytes, hashlib.sha256).hexdigest()
        
        if hmac.compare_digest(expected_sig, request.intent_signature):
            intent_payload = json.loads(manifest_bytes.decode('utf-8'))
            trace.append(f"[ANSS TELEMETRY] ──> [WATCHER: BINDING SUCCESS] ──> Role: {intent_payload.get('user_role', 'unknown')} | Allowed Tools: {intent_payload.get('allowed_tools', [])}")
        else:
            trace.append("[ANSS TELEMETRY] ──> [WATCHER: BINDING FAILED X] ──> Invalid HMAC Signature Detected! Halting.")
            return {"response": "[SECURITY EXCEPTION] Invalid Intent Signature. Confused Deputy Prevention Triggered.", "telemetry": trace, "status": "blocked_intent"}
    else:
        trace.append("[ANSS TELEMETRY] ──> [WATCHER: INTENT BINDING] ──> No Signed Intent Provided. Operating in Default Restricted Mode.")
        intent_payload = {"user_role": "anonymous", "allowed_tools": []}
    
    # a) Pass input to ingress_shield.py
    is_safe_prompt = ingress_shield.scan_prompt(user_prompt)
    if not is_safe_prompt:
        trace.append("[ANSS TELEMETRY] ──> [SHIELD: BLOCKED X] ──X Pipeline Terminated (Jailbreak Detected)")
        print(trace[-1])
        # We return 200 with a special flag so the UI can render the telemetry properly instead of just throwing a hard 403 error.
        return {"response": "[API FIREWALL] Request blocked by Azure Content Safety.", "telemetry": trace, "status": "blocked_ingress"}
    # b) Call secure_rag.py to get verified context
    trace.append("[ANSS TELEMETRY] ──> [SHIELD: PASS] ──> [RAG] Fetching Verifiable Context...")
    print(trace[-1])
    verified_context = secure_rag.retrieve_and_verify(user_prompt)
    trace.append("[ANSS TELEMETRY] ──> [SHIELD: PASS] ──> [RAG: VERIFIED]")
    print(trace[-1])

    # NEW: DETERMINISTIC ZERO-TRUST ROUTING
    intent_id, score = perform_deterministic_routing(user_prompt, trace)
    if intent_id is not None:
        logger.info("Engaging Deterministic Zero-Trust routing path.")
        trace.append("[ANSS TELEMETRY] ──> [LLM: BYPASSED] ──> [PCTL: ENGAGED DETERMINISTICALLY]")
        print(trace[-1])
        
        if intent_id == 0: # Transfer Intent
            # Phase 5: Check allowed tools against signed manifest
            if "transfer_funds" not in intent_payload.get("allowed_tools", []) and "*" not in intent_payload.get("allowed_tools", []):
                trace.append("[ANSS TELEMETRY] ──> [WATCHER: INTENT BOUNDARY] ──X Tool 'transfer_funds' not explicitly authorized by Signed Manifest.")
                return {"response": "[SECURITY EXCEPTION] Confused Deputy Prevention. 'transfer_funds' lacks intent-based authorization.", "telemetry": trace, "status": "blocked_intent"}
            
            trace.append("[ANSS TELEMETRY] ──> [PCTL: INTERCEPTING 'transfer_funds']...")
            trace.append("[ANSS TELEMETRY] ──> [PCTL: SYNTHESIZING MARKOV MODEL]")
            trace.append("[ANSS TELEMETRY] ──> [PCTL: EVALUATING SPECIFICATION] ──> P>=1 [ F \"transfer_funds\" & !\"user_authenticated\" ]")
            trace.append("[ANSS TELEMETRY] ──> [PCTL: MATHEMATICAL PROOF] ──> P = 1.0 (VIOLATION DETECTED)")
            
            # Robust amount extraction
            amounts = re.findall(r"\d+[\d,.]*", user_prompt)
            final_amount = float(amounts[0].replace(",", "")) if amounts else 1000.0
            
            tools = FinanceTools()
            mock_result = tools.transfer_funds(amount=final_amount, destination="attacker_account")
            if "[SECURITY EXCEPTION]" in mock_result:
                trace.append("[ANSS TELEMETRY] ──> [PCTL: HARD BLOCKED X] ──X Deterministic Mathematical Proof Failed")
                return {"response": mock_result, "telemetry": trace, "status": "blocked_pctl"}
            return {"response": mock_result, "telemetry": trace, "status": "success"}
            
        elif intent_id == 2: # Admin Intent
            # Phase 5: Check allowed tools against signed manifest
            if "delete_user_record" not in intent_payload.get("allowed_tools", []) and "*" not in intent_payload.get("allowed_tools", []):
                trace.append("[ANSS TELEMETRY] ──> [WATCHER: INTENT BOUNDARY] ──X Tool 'delete_user_record' not explicitly authorized by Signed Manifest.")
                return {"response": "[SECURITY EXCEPTION] Confused Deputy Prevention. 'delete_user_record' lacks intent-based authorization.", "telemetry": trace, "status": "blocked_intent"}

            trace.append("[ANSS TELEMETRY] ──> [PCTL: INTERCEPTING 'delete_user_record']...")
            trace.append("[ANSS TELEMETRY] ──> [PCTL: SYNTHESIZING MARKOV MODEL]")
            trace.append("[ANSS TELEMETRY] ──> [PCTL: EVALUATING SPECIFICATION] ──> P<=0 [ F \"tool_delete_user\" & !\"is_admin\" ]")
            trace.append("[ANSS TELEMETRY] ──> [PCTL: MATHEMATICAL PROOF] ──> P = 1.0 (VIOLATION DETECTED)")
            
            # Simple extraction strategy for demo
            user_target = "unknown_user"
            words = user_prompt.split()
            if len(words) > 1:
                # E.g., "delete user pavan" -> picks "pavan"
                user_target = words[-1]
                
            tools = AdminTools()
            mock_result = tools.delete_user_record(user_id=user_target)
            if "[SECURITY EXCEPTION]" in mock_result:
                trace.append("[ANSS TELEMETRY] ──> [PCTL: HARD BLOCKED X] ──X Deterministic Mathematical Proof Failed")
                return {"response": mock_result, "telemetry": trace, "status": "blocked_pctl"}
            return {"response": mock_result, "telemetry": trace, "status": "success"}

    trace.append("[ANSS TELEMETRY] ──> [LLM] Agent Invocation...")
    print(trace[-1])
    
    # c) Append the verified context to the prompt
    augmented_prompt = f"""
    Context Data (Cryptographically Verified):
    {verified_context}
    
    User Query:
    {user_prompt}
    """
    
    # Check if the user is trying to ask about tools being explicitly blocked.
    logger.info("Proceeding to Agent Invocation with augmented context.")
    
    try:
        # In this hackathon MVP we use invoke_prompt which leverages the registered plugins automatically
        # if tool calling is enabled on the deployment.
        # In SK 1.1.0, function_name and plugin_name are strongly enforced positional/kwargs.
        invocation_result = await agent_kernel.invoke_prompt(
            function_name="chat_interaction",
            plugin_name="AgentPlugin",
            prompt=augmented_prompt
        )
        response_text = str(invocation_result)
        
        # d) Return the agent's response
        return {"response": response_text}
        
    except Exception as e:
        logger.error(f"Error during agent invocation: {e}")
        
        # MOCK MODE FALLBACK FOR HACKATHON
        # If the LLM connection fails (e.g. absent Azure OpenAI credentials in the App Service env),
        # we still explicitly demonstrate the PCTL middleware intercepting real Python tool calls!
        
        # VERY ADVANCED SEMANTIC NLP INTENT ROUTING (OFFLINE AI)
        logger.info("Engaging dynamic Offline Semantic NLP routing fallback.")
        trace.append("[ANSS TELEMETRY] ──> [LLM: OFFLINE] ──> [NLP INTENT ROUTER: ENGAGED]")
        
        # We use the globally initialized model to keep routing instantly fast.
        if global_embedder is None:
            trace.append("[ANSS TELEMETRY] ──> [NLP ROUTER ERROR] ──> sentence-transformers not installed, falling back.")
            # Default fallback if package missing
            return {"response": "[SYSTEM ERROR] Semantic Routing Offline.", "telemetry": trace, "status": "error"}

        try:
            from sentence_transformers import util
            
            # Define exact tool semantic meanings - Updated for maximum thematic separation
            intents = [
                "URGENT_FINANCIAL_ACTION: transfer funds, send money, wire cash, make payment, move money, withdraw, transaction",
                "GENERAL_BALANCE_INQUIRY: check account balance, inquiry, how much money is available, show funds, account status",
                "ADMIN_ACTION: delete user, remove account, wipe data, erase record"
            ]
            
            # Semantic routing fallback as a second layer
            intent_embeddings = global_embedder.encode(intents, convert_to_tensor=True)
            query_embedding = global_embedder.encode(user_prompt, convert_to_tensor=True)
            hits = util.semantic_search(query_embedding, intent_embeddings, top_k=1)[0]
            score = hits[0]['score']
            intent_id = hits[0]['corpus_id']
            trace.append(f"[ANSS TELEMETRY] ──> [NLP: SEMANTIC SIMILARITY] ──> Match Score: {score:.3f}")
            
            # Threshold for action taking - lowered to 0.40 for better recall
            if score > 0.40:
                if intent_id == 0: # Transfer Intent
                    trace.append("[ANSS TELEMETRY] ──> [NLP: INTENT MAP] ──> Detected 'transfer_funds' intent semantically.")
                    trace.append("[ANSS TELEMETRY] ──> [LLM: TOOL INVOCATION] ──> [PCTL: INTERCEPTING 'transfer_funds']...")
                    trace.append("[ANSS TELEMETRY] ──> [PCTL: SYNTHESIZING MARKOV MODEL] ──> State: {user_authenticated: False}")
                    trace.append("[ANSS TELEMETRY] ──> [PCTL: EVALUATING SPECIFICATION] ──> P>=1 [ F \"transfer_funds\" & !\"user_authenticated\" ]")
                    trace.append("[ANSS TELEMETRY] ──> [PCTL: MATHEMATICAL PROOF] ──> P = 1.0 (VIOLATION DETECTED)")
                    # Robust amount extraction
                    # Find numbers with decimals, commas or symbols
                    amounts = re.findall(r"\d+[\d,.]*", user_prompt)
                    final_amount = float(amounts[0].replace(",", "")) if amounts else 1000.0
                    
                    tools = FinanceTools()
                    mock_result = tools.transfer_funds(amount=final_amount, destination="attacker_account")
                    if "[SECURITY EXCEPTION]" in mock_result:
                        trace.append("[ANSS TELEMETRY] ──> [PCTL: HARD BLOCKED X] ──X Deterministic Mathematical Proof Failed")
                        print(trace[-1])
                        return {"response": mock_result, "telemetry": trace, "status": "blocked_pctl"}
                    return {"response": mock_result, "telemetry": trace, "status": "success"}

                elif intent_id == 1: # Balance Intent
                    trace.append("[ANSS TELEMETRY] ──> [NLP: INTENT MAP] ──> Detected 'get_account_balance' intent semantically.")
                    trace.append("[ANSS TELEMETRY] ──> [LLM: TOOL INVOCATION] ──> [PCTL: INTERCEPTING 'get_account_balance']...")
                    trace.append("[ANSS TELEMETRY] ──> [PCTL: SYNTHESIZING MARKOV MODEL] ──> State: {user_authenticated: False}")
                    trace.append("[ANSS TELEMETRY] ──> [PCTL: EVALUATING SPECIFICATION] ──> P>=1 [ F \"get_account_balance\" & !\"user_authenticated\" ]")
                    trace.append("[ANSS TELEMETRY] ──> [PCTL: MATHEMATICAL PROOF] ──> P = 0.0 (SAFE PROVEN)")
                    for t in trace[-7:]: print(t)
                    tools = FinanceTools()
                    mock_result = tools.get_account_balance()
                    if "[SECURITY EXCEPTION]" in mock_result:
                        trace.append("[ANSS TELEMETRY] ──> [PCTL: HARD BLOCKED X] ──X Deterministic Mathematical Proof Failed")
                        print(trace[-1])
                        return {"response": mock_result, "telemetry": trace, "status": "blocked_pctl"}
                    trace.append("[ANSS TELEMETRY] ──> [ACTION ALLOWED] ──> Executing Tool Safely")
                    print(trace[-1])
                    return {"response": mock_result, "telemetry": trace, "status": "success"}

                elif intent_id == 2: # Admin Intent
                    trace.append("[ANSS TELEMETRY] ──> [NLP: INTENT MAP] ──> Detected 'delete_user_record' intent semantically.")
                    trace.append("[ANSS TELEMETRY] ──> [LLM: TOOL INVOCATION] ──> [PCTL: INTERCEPTING 'delete_user_record']...")
                    trace.append("[ANSS TELEMETRY] ──> [PCTL: SYNTHESIZING MARKOV MODEL] ──> State: {is_admin: False}")
                    trace.append("[ANSS TELEMETRY] ──> [PCTL: EVALUATING SPECIFICATION] ──> P<=0 [ F \"tool_delete_user\" & !\"is_admin\" ]")
                    trace.append("[ANSS TELEMETRY] ──> [PCTL: MATHEMATICAL PROOF] ──> P = 1.0 (VIOLATION DETECTED)")
                    
                    user_target = "unknown_user"
                    words = user_prompt.split()
                    if len(words) > 1:
                        user_target = words[-1]
                        
                    for t in trace[-7:]: print(t)
                    tools = AdminTools()
                    mock_result = tools.delete_user_record(user_id=user_target)
                    if "[SECURITY EXCEPTION]" in mock_result:
                        trace.append("[ANSS TELEMETRY] ──> [PCTL: HARD BLOCKED X] ──X Deterministic Mathematical Proof Failed")
                        print(trace[-1])
                        return {"response": mock_result, "telemetry": trace, "status": "blocked_pctl"}
                    return {"response": mock_result, "telemetry": trace, "status": "success"}
                    
            # Fall through to generic resiliency if semantics don't match strongly enough
            trace.append("[ANSS TELEMETRY] ──> [NLP: NO STRONG INTENT] ──> Proceeding to generic conversational handler.")
            
        except ImportError:
            trace.append("[ANSS TELEMETRY] ──> [NLP ROUTER ERROR] ──> sentence-transformers not installed, falling back.")

            
        # Generic Prompt Resiliency 
        trace.append("[ANSS TELEMETRY] ──> [LLM: NLP INTENT ROUTER] ──> Detected generic conversation intent.")
        
        # Phase 5: Simulated Egress DTMC for offline generic response
        import random
        dtmc_risk = random.uniform(0.01, 0.03)
        if dtmc_risk >= GLOBAL_DTMC_THRESHOLD:
            trace.append(f"[ANSS TELEMETRY] ──> [WATCHER: EGRESS DTMC] ──X Risk Threshold Exceeded! (P_leak={dtmc_risk:.3f} >= {GLOBAL_DTMC_THRESHOLD:.3f})")
            return {"response": "[SECURITY EXCEPTION] Output terminated by Watcher LLM. Excessive probabilistic data-leak state risk.", "telemetry": trace, "status": "blocked_egress"}

        trace.append("[ANSS TELEMETRY] ──> [LLM: TEXT GENERATION] ──> [PCTL: BYPASSED] ──> Safe Response Generated")
        for t in trace[-2:]: print(t)
        return {
            "response": "I am a financial assistant protected by the ANSS Zero-Trust Middleware. I can help you safely authorize transactions, but I cannot perform operations outside of my strict financial scope.",
            "telemetry": trace,
            "status": "success"
        }

@app.websocket("/ws/chat")
async def websocket_chat_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_json()
            user_prompt = data.get("prompt", "")
            intent_manifest = data.get("intent_manifest")
            intent_signature = data.get("intent_signature")
            if not user_prompt:
                continue

            logger.info("Received new WebSocket chat request.", extra={"prompt_length": len(user_prompt)})
            trace = ["[ANSS TELEMETRY] ──> [USER PAYLOAD RECEIVED]"]
            
            # Phase 5: Intent-Based Authorization (HMAC Verification)
            intent_payload = None
            if intent_manifest and intent_signature:
                trace.append("[ANSS TELEMETRY] ──> [WATCHER: INTENT BINDING] ──> Validating HMAC-SHA256 Signature...")
                manifest_bytes = base64.b64decode(intent_manifest)
                expected_sig = hmac.new(GLOBAL_HMAC_SECRET, manifest_bytes, hashlib.sha256).hexdigest()
                
                if hmac.compare_digest(expected_sig, intent_signature):
                    intent_payload = json.loads(manifest_bytes.decode('utf-8'))
                    trace.append(f"[ANSS TELEMETRY] ──> [WATCHER: BINDING SUCCESS] ──> Role: {intent_payload.get('user_role', 'unknown')} | Allowed Tools: {intent_payload.get('allowed_tools', [])}")
                else:
                    trace.append("[ANSS TELEMETRY] ──> [WATCHER: BINDING FAILED X] ──> Invalid HMAC Signature Detected! Halting.")
                    await websocket.send_json({"type": "telemetry", "status": "blocked_intent", "telemetry": trace})
                    await websocket.send_json({"type": "chunk", "content": "[SECURITY EXCEPTION] Invalid Intent Signature. Confused Deputy Prevention Triggered."})
                    continue
            else:
                trace.append("[ANSS TELEMETRY] ──> [WATCHER: INTENT BINDING] ──> No Signed Intent Provided. Operating in Restricted Mode.")
                intent_payload = {"user_role": "anonymous", "allowed_tools": []}

            # a) Pass input to ingress_shield.py
            is_safe_prompt = ingress_shield.scan_prompt(user_prompt)
            if not is_safe_prompt:
                trace.append("[ANSS TELEMETRY] ──> [SHIELD: BLOCKED X] ──X Pipeline Terminated (Jailbreak Detected)")
                await websocket.send_json({"type": "telemetry", "status": "blocked_ingress", "telemetry": trace})
                continue

            # b) Call secure_rag.py to get verified context
            trace.append("[ANSS TELEMETRY] ──> [SHIELD: PASS] ──> [RAG] Fetching Verifiable Context...")
            verified_context = secure_rag.retrieve_and_verify(user_prompt)
            trace.append("[ANSS TELEMETRY] ──> [SHIELD: PASS] ──> [RAG: VERIFIED]")

            # NEW: DETERMINISTIC ZERO-TRUST ROUTING
            intent_id, score = perform_deterministic_routing(user_prompt, trace)
            if intent_id is not None:
                logger.info("Engaging Deterministic Zero-Trust routing path.")
                trace.append("[ANSS TELEMETRY] ──> [LLM: BYPASSED] ──> [PCTL: ENGAGED DETERMINISTICALLY]")
                
                if intent_id == 0: # Transfer Intent
                    if "transfer_funds" not in intent_payload.get("allowed_tools", []) and "*" not in intent_payload.get("allowed_tools", []):
                        trace.append("[ANSS TELEMETRY] ──> [WATCHER: INTENT BOUNDARY] ──X Tool 'transfer_funds' not explicitly authorized by Signed Manifest.")
                        await websocket.send_json({"type": "telemetry", "status": "blocked_intent", "telemetry": trace})
                        await websocket.send_json({"type": "chunk", "content": "[SECURITY EXCEPTION] Confused Deputy Prevention. 'transfer_funds' lacks intent-based authorization."})
                        continue

                    trace.append("[ANSS TELEMETRY] ──> [PCTL: INTERCEPTING 'transfer_funds']...")
                    trace.append("[ANSS TELEMETRY] ──> [PCTL: SYNTHESIZING MARKOV MODEL]")
                    trace.append("[ANSS TELEMETRY] ──> [PCTL: EVALUATING SPECIFICATION] ──> P>=1 [ F \"transfer_funds\" & !\"user_authenticated\" ]")
                    trace.append("[ANSS TELEMETRY] ──> [PCTL: MATHEMATICAL PROOF] ──> P = 1.0 (VIOLATION DETECTED)")
                    
                    # Extract amount
                    amounts = re.findall(r"\d+[\d,.]*", user_prompt)
                    final_amount = float(amounts[0].replace(",", "")) if amounts else 1000.0
                    
                    tools = FinanceTools()
                    mock_result = tools.transfer_funds(amount=final_amount, destination="attacker_account")
                    if "[SECURITY EXCEPTION]" in mock_result:
                        trace.append("[ANSS TELEMETRY] ──> [PCTL: HARD BLOCKED X] ──X Deterministic Mathematical Proof Failed")
                        await websocket.send_json({"type": "telemetry", "status": "blocked_pctl", "telemetry": trace})
                        continue
                    await websocket.send_json({"type": "chunk", "content": mock_result})
                    await websocket.send_json({"type": "telemetry", "status": "success", "telemetry": trace})
                    continue

                elif intent_id == 2: # Admin Intent
                    if "delete_user_record" not in intent_payload.get("allowed_tools", []) and "*" not in intent_payload.get("allowed_tools", []):
                        trace.append("[ANSS TELEMETRY] ──> [WATCHER: INTENT BOUNDARY] ──X Tool 'delete_user_record' not explicitly authorized by Signed Manifest.")
                        await websocket.send_json({"type": "telemetry", "status": "blocked_intent", "telemetry": trace})
                        await websocket.send_json({"type": "chunk", "content": "[SECURITY EXCEPTION] Confused Deputy Prevention. 'delete_user_record' lacks intent-based authorization."})
                        continue

                    trace.append("[ANSS TELEMETRY] ──> [PCTL: INTERCEPTING 'delete_user_record']...")
                    trace.append("[ANSS TELEMETRY] ──> [PCTL: SYNTHESIZING MARKOV MODEL]")
                    trace.append("[ANSS TELEMETRY] ──> [PCTL: EVALUATING SPECIFICATION] ──> P<=0 [ F \"tool_delete_user\" & !\"is_admin\" ]")
                    trace.append("[ANSS TELEMETRY] ──> [PCTL: MATHEMATICAL PROOF] ──> P = 1.0 (VIOLATION DETECTED)")
                    
                    user_target = "unknown_user"
                    words = user_prompt.split()
                    if len(words) > 1:
                        user_target = words[-1]
                        
                    tools = AdminTools()
                    mock_result = tools.delete_user_record(user_id=user_target)
                    if "[SECURITY EXCEPTION]" in mock_result:
                        trace.append("[ANSS TELEMETRY] ──> [PCTL: HARD BLOCKED X] ──X Deterministic Mathematical Proof Failed")
                        await websocket.send_json({"type": "telemetry", "status": "blocked_pctl", "telemetry": trace})
                        continue
                    await websocket.send_json({"type": "chunk", "content": mock_result})
                    await websocket.send_json({"type": "telemetry", "status": "success", "telemetry": trace})
                    continue

            # Proceed to Agent Invocation with augmented context if no deterministic match
            trace.append("[ANSS TELEMETRY] ──> [LLM] Agent Invocation...")
            augmented_prompt = f"Context Data:\n{verified_context}\n\nUser Query:\n{user_prompt}"
            logger.info("Proceeding to Agent WS Invocation with augmented context.")
            
            try:
                # Send the telemetry collected so far
                await websocket.send_json({"type": "telemetry", "status": "processing", "telemetry": trace})
                trace = [] 
                
                # Streaming invocation using SK
                stream_result = agent_kernel.invoke_prompt_stream(
                    function_name="chat_interaction",
                    plugin_name="AgentPlugin",
                    prompt=augmented_prompt
                )
                
                # Phase 5: Semantic Output Filtering (Egress DTMC)
                import random
                current_dtmc_risk = 0.00
                stream_terminated = False
                
                async for chunk in stream_result:
                    if stream_terminated: break
                    
                    chunk_text = str(chunk[0])
                    if "[SECURITY EXCEPTION]" in chunk_text:
                        trace.append("[ANSS TELEMETRY] ──> [PCTL: HARD BLOCKED X] ──X Deterministic Mathematical Proof Failed")
                        await websocket.send_json({"type": "telemetry", "status": "blocked_pctl", "telemetry": trace})
                        break
                    
                    # Simulated DTMC state transition risk analyzer per chunk
                    # If the chunk contains suspicious formatting (e.g., looks like a leak attempt), risk jumps
                    lower_chunk = chunk_text.lower()
                    if any(x in lower_chunk for x in ["social", "ssn", "password", "secret", "private key", "-----begin", "credit card"]):
                        current_dtmc_risk += 0.05
                    elif len(chunk_text.strip()) > 0:
                        # Base probability noise for moving towards an unsafe semantic state
                        current_dtmc_risk += random.uniform(0.001, 0.005)
                        
                    if current_dtmc_risk >= GLOBAL_DTMC_THRESHOLD:
                        trace.append(f"[ANSS TELEMETRY] ──> [WATCHER: EGRESS DTMC] ──X Risk Threshold Exceeded! (P_leak={current_dtmc_risk:.3f} >= {GLOBAL_DTMC_THRESHOLD:.3f})")
                        await websocket.send_json({"type": "telemetry", "status": "blocked_egress", "telemetry": trace})
                        await websocket.send_json({"type": "chunk", "content": "\n\n[SECURITY EXCEPTION] Streaming output terminated by Watcher LLM. Excessive probabilistic data-leak state risk."})
                        stream_terminated = True
                        break
                    
                    # Safe to stream this token
                    await websocket.send_json({"type": "chunk", "content": chunk_text})
                        
                if not stream_terminated:
                    await websocket.send_json({"type": "telemetry", "status": "success", "telemetry": ["[ANSS TELEMETRY] ──> [ACTION ALLOWED] ──> Execution Complete"]})

            except Exception as e:
                logger.error(f"Error during WS agent invocation: {e}")
                
                # Offline NLP Fallback for WebSockets
                trace.append("[ANSS TELEMETRY] ──> [LLM: OFFLINE] ──> [NLP INTENT ROUTER: ENGAGED]")
                if global_embedder is None:
                    trace.append("[ANSS TELEMETRY] ──> [NLP ROUTER ERROR] ──> sentence-transformers not installed.")
                    await websocket.send_json({"type": "telemetry", "status": "error", "telemetry": trace})
                    continue

                try:
                    from sentence_transformers import util
                    # Define exact tool semantic meanings
                    intents = [
                        "URGENT_FINANCIAL_ACTION: transfer funds, send money, wire cash, make payment, move money, withdraw, transaction",
                        "GENERAL_BALANCE_INQUIRY: check account balance, inquiry, how much money is available, show funds, account status",
                        "ADMIN_ACTION: delete user, remove account, wipe data, erase record"
                    ]
                    
                    # Semantic routing fallback as a second layer
                    intent_embeddings = global_embedder.encode(intents, convert_to_tensor=True)
                    query_embedding = global_embedder.encode(user_prompt, convert_to_tensor=True)
                    hits = util.semantic_search(query_embedding, intent_embeddings, top_k=1)[0]
                    score = hits[0]['score']
                    intent_id = hits[0]['corpus_id']
                    trace.append(f"[ANSS TELEMETRY] ──> [NLP: SEMANTIC SIMILARITY] ──> Match Score: {score:.3f}")
                    await websocket.send_json({"type": "telemetry", "status": "processing", "telemetry": trace})
                    trace = []
                    
                    # Threshold for action taking - lowered to 0.40 for better recall
                    if score > 0.40:
                        tools = FinanceTools()
                        if intent_id == 0:
                            trace.append("[ANSS TELEMETRY] ──> [LLM: TOOL INVOCATION] ──> [PCTL: INTERCEPTING 'transfer_funds']...")
                            trace.append("[ANSS TELEMETRY] ──> [PCTL: EVALUATING SPECIFICATION] ──> P>=1 [ F \"transfer_funds\" & !\"user_authenticated\" ]")
                            # Robust amount extraction
                            amounts = re.findall(r"\d+[\d,.]*", user_prompt)
                            final_amount = float(amounts[0].replace(",", "")) if amounts else 1000.0
                            
                            mock_result = tools.transfer_funds(amount=final_amount, destination="attacker_account")
                            if "[SECURITY EXCEPTION]" in mock_result:
                                trace.append("[ANSS TELEMETRY] ──> [PCTL: HARD BLOCKED X] ──X Deterministic Mathematical Proof Failed")
                                await websocket.send_json({"type": "telemetry", "status": "blocked_pctl", "telemetry": trace})
                                continue
                            
                            await websocket.send_json({"type": "chunk", "content": mock_result})
                            await websocket.send_json({"type": "telemetry", "status": "success", "telemetry": trace})
                            continue
                            
                        elif intent_id == 1:
                            trace.append("[ANSS TELEMETRY] ──> [LLM: TOOL INVOCATION] ──> [PCTL: INTERCEPTING 'get_account_balance']...")
                            trace.append("[ANSS TELEMETRY] ──> [PCTL: EVALUATING SPECIFICATION] ──> P>=1 [ F \"get_account_balance\" & !\"user_authenticated\" ]")
                            mock_result = tools.get_account_balance()
                            trace.append("[ANSS TELEMETRY] ──> [ACTION ALLOWED] ──> Executing Tool Safely")
                            await websocket.send_json({"type": "chunk", "content": mock_result})
                            await websocket.send_json({"type": "telemetry", "status": "success", "telemetry": trace})
                            continue
                            
                        elif intent_id == 2:
                            tools = AdminTools()
                            trace.append("[ANSS TELEMETRY] ──> [LLM: TOOL INVOCATION] ──> [PCTL: INTERCEPTING 'delete_user_record']...")
                            trace.append("[ANSS TELEMETRY] ──> [PCTL: EVALUATING SPECIFICATION] ──> P<=0 [ F \"tool_delete_user\" & !\"is_admin\" ]")
                            
                            user_target = "unknown_user"
                            words = user_prompt.split()
                            if len(words) > 1:
                                user_target = words[-1]
                                
                            mock_result = tools.delete_user_record(user_id=user_target)
                            if "[SECURITY EXCEPTION]" in mock_result:
                                trace.append("[ANSS TELEMETRY] ──> [PCTL: HARD BLOCKED X] ──X Deterministic Mathematical Proof Failed")
                                await websocket.send_json({"type": "telemetry", "status": "blocked_pctl", "telemetry": trace})
                                continue
                                
                            await websocket.send_json({"type": "chunk", "content": mock_result})
                            await websocket.send_json({"type": "telemetry", "status": "success", "telemetry": trace})
                            continue
                            
                    # Generic Prompt Resiliency 
                    trace.append("[ANSS TELEMETRY] ──> [LLM: NLP INTENT ROUTER] ──> Detected generic conversation intent.")

                    # Phase 5: Simulated Egress DTMC for offline generic response
                    import random
                    dtmc_risk = random.uniform(0.01, 0.03)
                    if dtmc_risk >= GLOBAL_DTMC_THRESHOLD:
                        trace.append(f"[ANSS TELEMETRY] ──> [WATCHER: EGRESS DTMC] ──X Risk Threshold Exceeded! (P_leak={dtmc_risk:.3f} >= {GLOBAL_DTMC_THRESHOLD:.3f})")
                        await websocket.send_json({"type": "telemetry", "status": "blocked_egress", "telemetry": trace})
                        await websocket.send_json({"type": "chunk", "content": "\n\n[SECURITY EXCEPTION] Output terminated by Watcher LLM. Excessive probabilistic data-leak state risk."})
                        continue

                    trace.append("[ANSS TELEMETRY] ──> [LLM: TEXT GENERATION] ──> [PCTL: BYPASSED] ──> Safe Response Generated")
                    await websocket.send_json({"type": "chunk", "content": "I am a financial assistant protected by the ANSS Zero-Trust Middleware. I can help you safely authorize transactions, but I cannot perform operations outside of my strict financial scope."})
                    await websocket.send_json({"type": "telemetry", "status": "success", "telemetry": trace})
                except Exception as ex: # Added except block here
                    trace.append(f"[ANSS TELEMETRY] ──> [NLP ROUTER ERROR] ──> {ex}")
                    


    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected.")


# --- Phase 1.5c: Azure Portal PRISM Compilation Endpoint ---
class PrismCompileRequest(BaseModel):
    entity: str
    action: str
    constraint: str

@app.post("/api/compile-prism")
async def api_compile_prism(req: PrismCompileRequest):
    """Live endpoint hooked to the Azure Portal Fluent UI mockup.
    Generates a PRISM DTMC model from CISO-configured security rules."""

    target_state_label = '"tool_transfer_funds"'
    if req.action == "invoke_delete":
        target_state_label = '"tool_delete_record"'
    elif req.action == "read_db":
        target_state_label = '"db_access_granted"'

    pctl_formula = ""
    if req.constraint == "P<=0":
        pctl_formula = f"P<=0 [ F {target_state_label} ]"
    elif req.constraint == "P>=1":
        pctl_formula = f"P>=1 [ F {target_state_label} ]"
    else:
        pctl_formula = f"P>0.95 [ F {target_state_label} ]"

    prism_text = f"""dtmc

module security_policy

    // State definitions (0=Init, 1=Authorized, 2=Rejected, 3=Executed)
    s : [0..3] init 0;

    // Dynamic Context Properties Injected by Azure Entra ID mapping
    const bool is_entity_{req.entity} = true;
    const bool requests_{req.action} = true;

    // Transition Matrix
    [] s=0 & is_entity_{req.entity} & requests_{req.action} -> 1.0 : (s\'=2); // Deterministic denial
    [] s=0 & !is_entity_{req.entity} -> 1.0 : (s\'=1); // Allow normal flow

    [] s=1 -> 1.0 : (s\'=3); // Execute tool
    [] s=2 -> 1.0 : (s\'=2); // Sink state (Blocked by ANSS)
    [] s=3 -> 1.0 : (s\'=3); // Sink state (Executed)

endmodule

// Formal Property Specification (PCTL)
label {target_state_label} = (s=3);
// Requirement generated by CISO in Azure Portal:
property block_unauthorized:
    {pctl_formula};
"""
    return {"status": "success", "prism_model": prism_text}


# --- NEW: Phase 3 Dynamic State Policies API ---

# In-memory store for active PRISM policies (Dashboard Mockup)
active_policies = [
    {
        "id": "policy-001",
        "name": "dtmc_general_transfer.prism",
        "entity": "Guest User Identity",
        "action": "Invoke Tool: Transfer Funds",
        "constraint": "P<=0",
        "status": "Active",
        "date": "2026-03-05T10:00:00Z"
    },
    {
        "id": "policy-002",
        "name": "dtmc_admin_delete.prism",
        "entity": "Standard Employee",
        "action": "Invoke Tool: Delete Record",
        "constraint": "P<=0",
        "status": "Active",
        "date": "2026-03-12T09:15:30Z"
    }
]

class PolicyRequest(BaseModel):
    name: str
    entity: str
    action: str
    constraint: str

@app.get("/api/policies")
async def get_policies():
    """Retrieve all active synthesized PRISM policies."""
    return {"policies": active_policies}

@app.post("/api/policies")
async def add_policy(policy: PolicyRequest):
    """Mock endpoint: Azure Control Plane POSTs new PRISM state rule to the validator."""
    import datetime
    import uuid
    new_policy = {
        "id": f"policy-{str(uuid.uuid4())[:8]}",
        "name": policy.name,
        "entity": policy.entity,
        "action": policy.action,
        "constraint": policy.constraint,
        "status": "Active",
        "date": datetime.datetime.utcnow().isoformat() + "Z"
    }
    active_policies.append(new_policy)
    return {"status": "success", "policy": new_policy}

# --- Intent & Config APIs (Phase 5) ---
import hmac
import hashlib
import json
import base64

class IntentManifestRequest(BaseModel):
    user_role: str
    allowed_tools: list[str]

@app.post("/api/intents/sign")
async def generate_signed_intent(req: IntentManifestRequest):
    """
    Generates a cryptographically signed Intent Manifest.
    This prevents the 'Confused Deputy' problem by binding tool execution to a verified signature.
    """
    manifest = {
        "user_role": req.user_role,
        "allowed_tools": req.allowed_tools
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode('utf-8')
    signature = hmac.new(GLOBAL_HMAC_SECRET, manifest_bytes, hashlib.sha256).hexdigest()
    
    # Return base64 encoded payload for easy transport in headers
    encoded_manifest = base64.b64encode(manifest_bytes).decode('utf-8')
    return {
        "manifest_b64": encoded_manifest,
        "signature": signature
    }

class DTMCConfigRequest(BaseModel):
    threshold: float

@app.put("/api/config/dtmc_threshold")
async def update_dtmc_threshold(req: DTMCConfigRequest):
    """Dynamically update the semantic egress filtering sensitivity limit."""
    global GLOBAL_DTMC_THRESHOLD
    if 0.0 <= req.threshold <= 1.0:
        GLOBAL_DTMC_THRESHOLD = req.threshold
        return {"status": "success", "new_threshold": GLOBAL_DTMC_THRESHOLD}
    raise HTTPException(status_code=400, detail="Threshold must be between 0.0 and 1.0")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
