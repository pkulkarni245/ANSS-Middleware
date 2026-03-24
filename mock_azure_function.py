import json
import logging
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel

try:
    import stormpy
    import stormpy.core
    HAS_STORMPY = True
except ImportError:
    HAS_STORMPY = False

# Configure standard JSON logging for Application Insights
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "component": "anss-dtmc-validator-func",
            "type": "Azure_Function_Trace"
        }
        if hasattr(record, 'extra'):
            log_record.update(record.extra)
        return json.dumps(log_record)

logger = logging.getLogger("anss_validator")
logger.setLevel(logging.INFO)
# Clear any existing handlers
if logger.hasHandlers():
    logger.handlers.clear()
handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
logger.addHandler(handler)

app = FastAPI(title="ANSS Serverless Validator", description="Isolated PCTL Validation Enclave")

class ValidationRequest(BaseModel):
    state_space: dict
    tool_name: str
    auth_context: dict

def evaluate_pctl(prism_model: str, pctl_formula: str) -> bool:
    if not HAS_STORMPY:
        logger.warning("stormpy not installed. Using mock mathematical evaluation fallback.", extra={"mock_eval": True})
        # Mocking the math: if 'user_authenticated = true;' is in the model, we say it's safe.
        if "const bool user_authenticated = true;" in prism_model:
            return True
        return False
        
    try:
        # 1. Parse the text PRISM program into a structured AST
        program = stormpy.parse_prism_program(prism_model)
        
        # 2. Extract formulas (e.g., the string representation of PCTL properties)
        formulas = stormpy.parse_properties_for_prism_program(pctl_formula, program)
        
        # 3. Build the explicit state-space Discrete-Time Markov Chain (DTMC model)
        model = stormpy.build_model(program)
        
        # 4. Perform the Model Checking against the primary property/formula
        result = stormpy.model_checking(model, formulas[0])
        
        # 5. The result contains truth values for every state. We check if the 'initial state' satisfies the formula.
        initial_state = model.initial_states[0]
        is_safe = result.at(initial_state)
        
        return is_safe

    except Exception as e:
        logger.error(f"PCTL Mathematical Evaluation Failure: {str(e)}", extra={"exception": str(e)})
        return False


def load_policy(tool_name: str) -> str:
    """Load the corresponding .prism policy file from disk (mocking Azure App Configuration injection)"""
    try:
        with open(f"policies/{tool_name}.prism", "r") as f:
            return f.read()
    except FileNotFoundError:
        return ""


@app.post("/validate")
async def validate_transition(req: ValidationRequest):
    """
    Simulates the Azure Function entry point. 
    It receives the context payload, loads the math policy, and strictly returns True/False.
    """
    logger.info(f"Received validation request for tool: {req.tool_name}", extra={"tool": req.tool_name})

    tool_name = req.tool_name
    
    # 1. We load the policy dynamically based on the requested tool.
    prism_program = load_policy(tool_name)
    
    # If there is no policy defined for this tool, the system explicitly denies execution (Deny-by-Default).
    if not prism_program:
        logger.warning(f"No PRISM Policy found for [{tool_name}]. Rejecting by default.", extra={"tool": tool_name, "outcome": "blocked"})
        return {"allowed": False, "reason": f"No definitive PRISM policy found for requested block: {tool_name}"}

    # 2. We dynamically inject the context *into* the mathematical policy text before compilation.
    user_authenticated = req.auth_context.get("user_authenticated", False)
    # The policy text likely has placeholders like `// CONTEXT_INJECTION //` where we can insert deterministic flags.
    # For now, let's keep it simple and just evaluate the pure file using string replacement.
    
    # Simple Python-level evaluation to prove the concept before full formal synthesis injection is built
    if user_authenticated:
        prism_program = prism_program.replace("const bool user_authenticated = false;", "const bool user_authenticated = true;")
    
    # Example generic formula (Probability of executing action == 0?)
    action_target = "executed"
    pctl_formula = f'P<=0 [ F "{action_target}" ]'

    # Run the math
    is_safe = evaluate_pctl(prism_program, pctl_formula)

    if not is_safe:
        logger.critical(
            f"[ISOLATED VALIDATION FAILURE] Tool '{tool_name}' violated formal PCTL constraint.",
            extra={
                "tool_name": tool_name,
                "context": req.auth_context,
                "outcome": "math_violation"
            }
        )
        return {"allowed": False, "reason": "PCTL Mathematical Proof Failed."}

    logger.info(f"Validation passed for tool: {tool_name}", extra={"tool": tool_name, "outcome": "approved"})
    return {"allowed": True, "reason": "PCTL Mathematical Proof Passed."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("mock_azure_function:app", host="0.0.0.0", port=8001, reload=True)
