import os
import hmac
import hashlib
import json
from utils.logger import get_json_logger

logger = get_json_logger("SecureRAG")

class SecureRAG:
    """
    The Verifiable Context Engine for the ANSS Middleware.
    
    Zero-Trust Architecture Context:
    Standard RAG architectures assume the retrieved documents are trustworthy. However,
    if an attacker poisons the knowledge index (Data Poisoning), the LLM might process
    malicious context and execute hidden commands or hallucinate incorrect facts.
    
    This engine provides TWO layers of defense:
    1. SEMANTIC VECTOR SEARCH: Uses a deterministic SentenceTransformer embedding model
       (NOT an LLM) to perform real cosine-similarity retrieval against the knowledge base.
       Same query always returns the same ranked results — fully deterministic.
    2. HMAC VERIFICATION: Every retrieved document's HMAC-SHA256 signature is verified
       against a secret key stored in Azure Key Vault, guaranteeing data integrity.
    """
    
    def __init__(self):
        self._embedder = None
        self._doc_embeddings = None
        self._documents = []

        # Try Azure AI Search (production path)
        try:
            from azure.search.documents import SearchClient
            from azure.core.credentials import AzureKeyCredential

            search_endpoint = os.environ.get("AZURE_SEARCH_ENDPOINT", "")
            search_key = os.environ.get("AZURE_SEARCH_KEY", "")
            search_index = os.environ.get("AZURE_SEARCH_INDEX", "default-index")
            
            if search_endpoint and search_key:
                self.search_client = SearchClient(search_endpoint, search_index, AzureKeyCredential(search_key))
            else:
                logger.warning("Azure Search credentials not found. SecureRAG operating in local vector mode.")
                self.search_client = None
        except ImportError:
            logger.warning("Azure Search SDK not installed. Using local vector search.")
            self.search_client = None

        # Try Azure Key Vault (production path)
        try:
            from azure.keyvault.secrets import SecretClient
            from azure.identity import DefaultAzureCredential

            kv_uri = os.environ.get("KEY_VAULT_URI", "")
            if kv_uri:
                try:
                    self.secret_client = SecretClient(vault_url=kv_uri, credential=DefaultAzureCredential())
                except Exception as e:
                    logger.error(f"Failed to initialize SecretClient: {e}")
                    self.secret_client = None
            else:
                logger.warning("Key Vault URI not found. SecureRAG using local HMAC key.")
                self.secret_client = None
        except ImportError:
            logger.warning("Azure Key Vault SDK not installed. Using local HMAC key.")
            self.secret_client = None

    def set_embedder(self, embedder):
        """Inject the shared SentenceTransformer model from main.py (Dependency Injection)."""
        self._embedder = embedder
        if embedder is not None:
            self._index_documents()

    def _index_documents(self):
        """Load documents from the local vector DB and pre-compute embeddings."""
        try:
            with open("mock_vector_db.json", "r", encoding="utf-8") as f:
                self._documents = json.load(f)
        except FileNotFoundError:
            self._documents = []
            logger.warning("mock_vector_db.json not found. Knowledge base is empty.")
            return

        if not self._documents:
            return

        contents = [doc.get("content", "") for doc in self._documents]
        logger.info(f"Indexing {len(contents)} documents into local vector store...")
        self._doc_embeddings = self._embedder.encode(contents, convert_to_tensor=True)
        logger.info("Document embeddings ready for semantic retrieval.")

    def retrieve_and_verify(self, query: str) -> str:
        """
        Retrieves top-K documents using semantic vector search and verifies them cryptographically.
        
        Pipeline:
        1. Encode the query using SentenceTransformer.
        2. Compute cosine similarity against all document embeddings.
        3. Rank and select the top-3 most relevant documents.
        4. Verify each document's HMAC-SHA256 signature.
        5. Return only VERIFIED documents as context.
        
        Args:
            query: The user search query.
            
        Returns:
            str: A concatenated string of all VERIFIED documents.
        """
        verified_docs = []
        
        # 1. Fetch HMAC Secret
        try:
            hmac_key = self.get_hmac_key()
        except Exception as e:
            logger.error(f"Failed to fetch HMAC key: {e}")
            return "Error retrieving verified context."

        # 2. Retrieve documents
        try:
            if self.search_client:
                # Production path: Azure AI Search
                results = self.search_client.search(search_text=query, top=3)
                documents = list(results)
            else:
                # Local vector search path
                documents = self._vector_search(query, top_k=3)
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

            calculated_hash = hmac.new(hmac_key, content.encode('utf-8'), hashlib.sha256).hexdigest()
            
            if hmac.compare_digest(calculated_hash, expected_signature):
                verified_docs.append(content)
                logger.info(f"Document HMAC verified: '{content[:40]}...'")
            else:
                self._log_poisoning("HMAC Mismatch - Data Poisoning Detected", content)

        if not verified_docs:
            return "No verified context available for this query."

        return "\n\n".join(verified_docs)

    def _vector_search(self, query: str, top_k: int = 3) -> list:
        """
        Performs local cosine similarity search using the shared SentenceTransformer.
        This is deterministic: same query always returns the same ranked results.
        """
        if self._embedder is None or self._doc_embeddings is None:
            logger.warning("Embedder not available. Returning all documents (unranked fallback).")
            return self._documents[:top_k]

        try:
            from sentence_transformers import util

            query_embedding = self._embedder.encode(query, convert_to_tensor=True)
            similarities = util.cos_sim(query_embedding, self._doc_embeddings)[0]
            
            # Get top-K indices sorted by similarity (descending)
            top_indices = similarities.argsort(descending=True)[:top_k]
            
            results = []
            for idx in top_indices:
                idx_int = int(idx)
                score = float(similarities[idx_int])
                doc = self._documents[idx_int].copy()
                doc["_relevance_score"] = score
                results.append(doc)
                logger.info(f"Vector match (score={score:.4f}): '{doc.get('content', '')[:40]}...'")
            
            return results
        except Exception as e:
            logger.error(f"Vector search failed: {e}")
            return self._documents[:top_k]

    def _log_poisoning(self, reason: str, sample: str):
        """Logs a WARNING JSON payload for Azure App Insights indicating a Data Poisoning attempt."""
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
        hmac_key = self.get_hmac_key()
        real_signature = hmac.new(hmac_key, content.encode('utf-8'), hashlib.sha256).hexdigest()
        final_signature = "BAD_SIGNATURE_999" if is_poisoned else real_signature
        
        doc = {
            "content": content,
            "hmac_signature": final_signature
        }
        
        try:
            with open("mock_vector_db.json", "r", encoding="utf-8") as f:
                documents = json.load(f)
        except Exception:
            documents = []
            
        documents.append(doc)
        
        with open("mock_vector_db.json", "w", encoding="utf-8") as f:
            json.dump(documents, f, indent=4)
            
        logger.info(f"Added document to vector DB. Poisoned: {is_poisoned}")
        
        # Re-index if embedder is available
        if self._embedder:
            self._index_documents()

    def clear_documents(self):
        try:
            with open("mock_vector_db.json", "w", encoding="utf-8") as f:
                json.dump([], f)
            self._documents = []
            self._doc_embeddings = None
            logger.info("Cleared vector DB and embeddings.")
        except Exception as e:
            logger.error(f"Failed to clear documents: {e}")
