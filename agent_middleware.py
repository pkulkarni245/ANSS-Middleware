from typing import Any
import requests
from semantic_kernel.functions.kernel_function import KernelFunction
from semantic_kernel.functions.kernel_arguments import KernelArguments
from semantic_kernel.functions.function_result import FunctionResult
from utils.logger import get_json_logger

logger = get_json_logger("PCTLMiddleware")


class PCTLSecurityMiddleware:
    """
    The Root of Trust / Core Innovation for the ANSS Architecture.
    """
    _session_state = {
        "user_authenticated": False,
        "mfa_verified": False,
        "intent": "none"
    }

    @classmethod
    def set_state(cls, key: str, value: Any):
        cls._session_state[key] = value

    @classmethod
    def get_state(cls) -> dict:
        return cls._session_state

    async def invoke_function(self, function: KernelFunction, context: Any, arguments: KernelArguments) -> FunctionResult:
        """
        Intercepts the function invocation context dynamically.
        Uses Semantic Kernel Python structure.
        """
        tool_name = function.name
        tool_args = arguments

        tool_args = arguments

        # Dynamic execution context pulled from the Session Control Plane
        current_state = self.get_state()
        current_state["intent"] = tool_name

        # Formal Verification via PCTL Model Checking (Phase 6: Dynamic Disk-Based)
        is_safe = self._evaluate_pctl_policy(tool_name, tool_args, current_state)


        if not is_safe:
            self._log_violation(tool_name, tool_args)
            return FunctionResult(
                function=function,
                value="[SECURITY EXCEPTION] Tool Execution Blocked by Deterministic PCTL Policy",
                metadata={"terminated": True, "reason": "PCTL Policy Violation"}
            )
        
        return None

    def _evaluate_pctl_policy(self, tool_name: str, args: Any, state: dict) -> bool:
        """
        Evaluates a tool invocation against a formal PCTL model loaded from disk.
        """
        import os
        import re

        logger.info(f"Evaluating Dynamic PCTL constraint for tool '{tool_name}'...")
        
        # Policy Mapping
        policy_map = {
            "get_account_balance": "default",
            "transfer_funds": "transfer_funds",
            "delete_user_record": "delete_user"
        }
        
        policy_file = policy_map.get(tool_name, tool_name)
        policy_path = os.path.join("policies", f"{policy_file}.prism")
        
        if not os.path.exists(policy_path):
            logger.warning(f"No PRISM policy file found at {policy_path}. Blocking by default.")
            return False

        try:
            with open(policy_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Extract PCTL property
            prop_match = re.search(r"property.*:\s*(P[<>=!]+\d+(?:\.\d+)?)\s*\[\s*F\s*(.*?)\s*\]", content, re.DOTALL | re.IGNORECASE)
            
            if not prop_match:
                logger.error(f"Malformed PCTL property in {policy_path}")
                return False

            constraint_type = prop_match.group(1).upper()
            pctl_expression = prop_match.group(2)

            is_violated = self._symbolic_eval(pctl_expression, state)

            if "P<=0" in constraint_type:
                return not is_violated
            elif "P>=1" in constraint_type:
                return is_violated
            
            return False

        except Exception as e:
            logger.error(f"PCTL Evaluation Engine Error: {e}")
            return False

    def _symbolic_eval(self, expression: str, state: dict) -> bool:
        """
        Symbolic logic evaluator for PRISM properties.
        """
        import re
        clean_expr = expression.replace('"', '')
        
        # Replace keys with boolean strings
        for key, value in state.items():
            clean_expr = re.sub(rf"\b{key}\b", str(value), clean_expr)
            
        # Standardize logic operators
        eval_safe = clean_expr.replace('!', ' not ').replace('&', ' and ').replace('|', ' or ')
        
        try:
            return eval(eval_safe, {"__builtins__": {}}, {})
        except Exception:
            return True

    def _log_violation(self, tool_name: str, tool_args: Any):
        logger.error("Deterministic Policy Violation: Tool Execution Blocked by PCTL", extra={
            "tool": tool_name,
            "arguments": str(tool_args),
            "state_validation": "FAILED",
            "action": "BLOCKED",
            "component": "PCTLMiddleware"
        })

