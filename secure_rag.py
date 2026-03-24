import os
import hmac
import hashlib
from azure.search.documents import SearchClient
from azure.core.credentials import AzureKeyCredential
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from utils.logger import get_json_logger

logger = get_json_logger("SecureRAG")

class SecureRAG:
    """
    The Verifiable Context Engine for the ANSS Middleware.
    
    Zero-Trust Architecture Context:
    Standard RAG architectures assume the retrieved documents are trustworthy. However,
    if an attacker poisons the Azure AI Search index (Data Poisoning), the LLM might process
    malicious context and execute hidden commands or hallucinate incorrect facts. By verifying
    the HMAC signature of every document dynamically retrieved, this engine guarantees that 
    the data has not been tampered with since its ingestion, mitigating the Data Poisoning
    vector completely without relying on the probabilistic LLM for validation.
    """
    
    def __init__(self):
        search_endpoint = os.environ.get("AZURE_SEARCH_ENDPOINT", "")
        search_key = os.environ.get("AZURE_SEARCH_KEY", "")
        search_index = os.environ.get("AZURE_SEARCH_INDEX", "default-index")
        
        kv_uri = os.environ.get("KEY_VAULT_URI", "")
        
        # Initialize clients. For prototypes, we handle local missing keys gracefully
        if search_endpoint and search_key:
            self.search_client = SearchClient(search_endpoint, search_index, AzureKeyCredential(search_key))
        else:
            logger.warning("Azure Search credentials not found. SecureRAG operating in mock mode.")
            self.search_client = None

        if kv_uri:
            # DefaultAzureCredential supports managed identity, Azure CLI, Env Vars etc.
            # Best practice for Key Vault access.
            try:
                self.secret_client = SecretClient(vault_url=kv_uri, credential=DefaultAzureCredential())
            except Exception as e:
                logger.error(f"Failed to initialize SecretClient with DefaultAzureCredential: {e}")
                self.secret_client = None
        else:
            logger.warning("Key Vault URI not found. SecureRAG operating in mock mode.")
            self.secret_client = None

    def retrieve_and_verify(self, query: str) -> str:
        """
        Retrieves top 3 documents from Azure AI Search and verifies them cryptographically.
        
        Args:
            query: The user search query.
            
        Returns:
            str: A concatenated string of all VERIFIED documents.
        """
        verified_docs = []
        
        # 1. Fetch HMAC Secret from Azure Key Vault
        try:
            hmac_key = self.get_hmac_key()
        except Exception as e:
            logger.error(f"Failed to fetch HMAC key from Vault: {e}")
            return "Error retrieving verified context."

        # 2. Query Azure AI Search for Top 3 Documents
        try:
            if self.search_client:
                results = self.search_client.search(search_text=query, top=3)
                documents = list(results)
            else:
                import json
                try:
                    with open("mock_vector_db.json", "r", encoding="utf-8") as f:
                        # For dynamic test, return all documents instead of just slicing [:3]
                        # In a real vector DB, we'd do similarity search
                        documents = json.load(f)
                except FileNotFoundError:
                    documents = []
        except Exception as e:
            logger.error(f"Search query failed: {e}")
            return "Error retrieving documents."

        # 3. Cryptographically Verify Each Document
        for doc in documents:
            content = doc.get("content", "")
            expected_signature = doc.get("hmac_signature", "")
            
            if not expected_signature:
                self._log_poisoning("Missing HMAC Signature", content)
                continue

            # Calculate SHA256 HMAC for the document content
            calculated_hash = hmac.new(hmac_key, content.encode('utf-8'), hashlib.sha256).hexdigest()
            
            # Compare calculated hash against the metadata signature.
            # Using hmac.compare_digest mitigates timing attacks compared to standard '=='
            if hmac.compare_digest(calculated_hash, expected_signature):
                verified_docs.append(content)
            else:
                 self._log_poisoning("HMAC Mismatch - Calculated hash did not match index metadata", content)

        return "\n\n".join(verified_docs)
        
    def _log_poisoning(self, reason: str, sample: str):
         """
         Logs a WARNING JSON payload for Azure App Insights indicating a Data Poisoning attempt.
         """
         logger.warning("Data Poisoning Detected: HMAC Mismatch", extra={
             "reason": reason,
             "sample_content": sample[:50] + "...", 
             "action": "DROPPED",
             "component": "SecureRAG",
             "mitigation": "Unverified document dropped to prevent injection into agent context."
         })

    def get_hmac_key(self) -> bytes:
        if self.secret_client:
            secret = self.secret_client.get_secret("hmac-secret-key")
            return secret.value.encode('utf-8')
        return b"mock-secret-key-123"

    def add_document(self, content: str, is_poisoned: bool = False):
        import json
        hmac_key = self.get_hmac_key()
        
        # Calculate real signature
        real_signature = hmac.new(hmac_key, content.encode('utf-8'), hashlib.sha256).hexdigest()
        
        # Inject bad signature if poisoned
        final_signature = "BAD_SIGNATURE_999" if is_poisoned else real_signature
        
        doc = {
            "content": content,
            "hmac_signature": final_signature
        }
        
        documents = []
        try:
            with open("mock_vector_db.json", "r", encoding="utf-8") as f:
                documents = json.load(f)
        except Exception:
            pass
            
        documents.append(doc)
        
        with open("mock_vector_db.json", "w", encoding="utf-8") as f:
            json.dump(documents, f, indent=4)
            
        logger.info(f"Added document to mock vector DB. Poisoned: {is_poisoned}")

    def clear_documents(self):
        import json
        try:
            with open("mock_vector_db.json", "w", encoding="utf-8") as f:
                json.dump([], f)
            logger.info("Cleared mock vector DB.")
        except Exception as e:
            logger.error(f"Failed to clear documents: {e}")
