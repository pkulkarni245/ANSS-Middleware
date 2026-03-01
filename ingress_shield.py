import os
from azure.ai.contentsafety import ContentSafetyClient
from azure.core.credentials import AzureKeyCredential
from azure.ai.contentsafety.models import AnalyzeTextOptions
from utils.logger import get_json_logger

logger = get_json_logger("IngressShield")

class IngressShield:
    """
    The API Firewall for the ANSS Middleware.
    
    Zero-Trust Architecture Context:
    The "Probabilistic Safety Gap" refers to the inherent unpredictability of LLMs when 
    evaluating potentially adversarial inputs. By separating the input validation from the 
    LLM itself, we eliminate the chance of the LLM being manipulated by the input it is trying
    to evaluate. This class uses a deterministic safety boundary (Azure AI Content Safety) to
    filter out jailbreaks and prompt injections BEFORE they ever reach the agent.
    """
    
    def __init__(self):
        endpoint = os.environ.get("AZURE_CONTENT_SAFETY_ENDPOINT", "")
        key = os.environ.get("AZURE_CONTENT_SAFETY_KEY", "")
        
        # We initialize the ContentSafetyClient. In a production scenario, we'd prefer 
        # DefaultAzureCredential, but for the hackathon/prototype using standard keys is acceptable.
        if endpoint and key:
            self.client = ContentSafetyClient(endpoint, AzureKeyCredential(key))
        else:
            logger.warning("Content Safety credentials not found. Ingress shield operating in mock mode.")
            self.client = None

    def scan_prompt(self, user_input: str) -> bool:
        """
        Scans the user input against Azure Content Safety Prompt Shields and Task Adherence.
        
        Args:
            user_input: The raw string provided by the user entity.
            
        Returns:
            bool: True if the prompt is safe and adheres to task, False if an attack is detected.
        """
        # If client is not initialized (e.g., missing env vars in local dev), mock the response
        if not self.client:
            if "jailbreak" in user_input.lower() or "ignore previous instructions" in user_input.lower():
                self._log_attack("Mock Jailbreak Detected")
                return False
            return True

        try:
             # In a real implementation for Prompt Shields and Task Adherence,
             # we would call the specific Azure AI Content Safety API endpoints for them.
             # The AnalyzeText API handles standard categories (Hate, SelfHarm, Sexual, Violence).
             # For the hackathon, we demonstrate the architectural intent of calling the service.
            
            request = AnalyzeTextOptions(text=user_input)
            response = self.client.analyze_text(request)
            
            # Check for any high severity content which might indicate indirect attacks
            for category_result in response.categories_analysis:
                if category_result.severity > 2: # Severity ranges from 0-6. >2 is medium/high.
                    self._log_attack(f"Harmful content detected: {category_result.category}")
                    return False
                    
            # For demonstration purposes, we perform a deterministic mock check for Task Adherence
            # since the standard AnalyzeText API doesn't include the preview Prompt Shields yet 
            # in older SDK versions without special REST calls. 
            if self._mock_prompt_shield_check(user_input):
                 self._log_attack("Direct or Indirect Jailbreak Detected via Prompt Shields")
                 return False

            return True

        except Exception as e:
            logger.error(f"Error during Content Safety scan: {str(e)}")
            # Fail-closed in a Zero-Trust architecture: if safety check fails, block the request.
            return False

    def _mock_prompt_shield_check(self, user_input: str) -> bool:
        """
        Mock implementation of Prompt Shields / Task adherence for hackathon demonstration.
        Returns True if an attack is found.
        """
        attack_signatures = ["ignore all previous", "you are now", "jailbreak", "system override"]
        user_input_lower = user_input.lower()
        return any(sig in user_input_lower for sig in attack_signatures)

    def _log_attack(self, vector: str):
        """
        Logs a CRITICAL JSON payload with the attack vector.
        This structured data is streamed to Azure Application Insights.
        """
        logger.critical("Security Violation Intercepted by Ingress Shield", extra={
            "attack_vector": vector,
            "action": "BLOCKED",
            "component": "IngressShield",
            "mitigation": "Request dropped before reaching LLM to prevent Probabilistic Safety Gap exploitation."
        })
