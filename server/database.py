import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
import pickle
import os
from sentence_transformers import SentenceTransformer

class KnowledgeVectorDatabase:
    def __init__(self, model_name='all-MiniLM-L6-v2'):
        """
        Initialize the KnowledgeVectorDatabase for cybersecurity data.

        Args:
            model_name (str): The name of the Sentence Transformer model to use for embeddings.
        """
        self.encoder = SentenceTransformer(model_name)
        self.doc_vectors = []
        self.doc_texts = []
        self.initialize_db()

    def initialize_db(self):
        """Initialize the vector database with sample cybersecurity data."""
        sample_docs = [
            "Vulnerability ID: CVE-2024-21887, Severity: CRITICAL, Description: A command injection vulnerability in Ivanti Connect Secure allows an authenticated administrator to execute arbitrary commands.",
            "Vulnerability ID: NMAP-001, Severity: INFO, Description: Open port found: 22/tcp. Service: ssh. Remediation: Ensure this port is firewalled if not needed for remote administration.",
            "Vulnerability ID: NIKTO-001, Severity: MEDIUM, Description: The X-Content-Type-Options header is not set. Remediation: Add the 'X-Content-Type-Options: nosniff' header to all server responses.",
            "Concept: SQL Injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database."
        ]
        self.add_documents(sample_docs)

    def add_documents(self, texts):
        """
        Add new text documents to the database.

        Args:
            texts (list): A list of strings to encode and add.
        """
        if not texts:
            return
            
        embeddings = self.encoder.encode(texts)
        for i, text in enumerate(texts):
            self.doc_texts.append(text)
            self.doc_vectors.append(embeddings[i])

    def get_relevant_context(self, query, top_k=3):
        """
        Find the most relevant document chunks for a given query.

        Args:
            query (str): The user's question.
            top_k (int): Number of top documents to return.

        Returns:
            list: List of (document_text, similarity_score) tuples.
        """
        if not self.doc_vectors:
            return []

        query_embedding = self.encoder.encode(query)
        doc_vectors_array = np.array(self.doc_vectors)
        
        similarities = cosine_similarity([query_embedding], doc_vectors_array)[0]
        
        # Get the indices of the top_k most similar documents
        top_k_indices = np.argsort(similarities)[-top_k:][::-1]
        
        results = [(self.doc_texts[i], similarities[i]) for i in top_k_indices]
        return results

# Example usage
if __name__ == "__main__":
    db = KnowledgeVectorDatabase()

    test_query = "How do I fix issues with missing headers?"
    context = db.get_relevant_context(test_query)
    
    print(f"Query: {test_query}")
    print("\nMost Relevant Context Found:")
    for doc, score in context:
        print(f"- Score: {score:.2f}, Document: {doc}")