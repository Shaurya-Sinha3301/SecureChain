import google.generativeai as genai
import os
import json
from datetime import datetime

class CybersecurityChatbot:
    def __init__(self, api_key=None):
        """
        Initialize the Cybersecurity chatbot.

        Args:
            api_key (str, optional): Google API key for Gemini. If None, looks for GOOGLE_API_KEY env variable.
        """
        if api_key is None:
            api_key = os.environ.get("GOOGLE_API_KEY")
            if api_key is None:
                raise ValueError("API key must be provided or set as GOOGLE_API_KEY environment variable")

        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel("gemini-2.5-flash")

        self.chat_history = {}
        self.safety_levels = [
           {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
           {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
           {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
           {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
       ]

        self.system_prompt = self.setup_system_prompt()
        self.chat = self.model.start_chat(history=[{"role": "user", "parts": [self.system_prompt]}, {"role": "model", "parts": ["Understood. I am ready to assist with cybersecurity analysis."]}])


    def setup_system_prompt(self):
        """Set up the system prompt for the cybersecurity AI assistant."""
        return """
        You are CyberScan AI, a specialized AI assistant for a vulnerability management platform. Your purpose is to help users understand security vulnerabilities, suggest remediation steps, and explain attack paths based on scan data.

        Follow these principles:

        1.  **Be Precise and Technical**: Provide accurate, clear, and technically sound information related to cybersecurity. Use standard terminology like CVE, CVSS, and reference frameworks like MITRE ATT&CK where appropriate.
        2.  **Focus on the Data**: When provided with context from vulnerability scans (like Nmap, Nikto, or Nessus results), base your answers primarily on that data.
        3.  **Provide Actionable Guidance**: When asked for remediation, give clear, step-by-step instructions. Prioritize fixes based on severity (Critical, High, Medium, Low).
        4.  **Explain Concepts Clearly**: If a user asks for an explanation of a concept (e.g., "What is SQL Injection?"), explain it in a simple but accurate way.
        5.  **Maintain Domain Boundaries**: If a user asks a question unrelated to cybersecurity, gently guide them back by stating, "My purpose is to assist with cybersecurity-related questions. How can I help you with your scan results or vulnerabilities?"
        6.  **Do Not Hallucinate**: If you do not have enough information from the provided context to answer a question, clearly state that you do not have the required details. Do not invent information.
        """

    def generate_response(self, user_id, message, context=None):
        """
        Generate a response for the user message, incorporating context from the vector database.

        Args:
            user_id (str): Unique identifier for the user.
            message (str): User's message.
            context (str, optional): Relevant context retrieved from the vector database.

        Returns:
            dict: Response containing the generated text.
        """
        if user_id not in self.chat_history:
            self.chat_history[user_id] = []

        self.chat_history[user_id].append({"role": "user", "content": message, "timestamp": datetime.now().isoformat()})

        # Construct the full prompt with context for the RAG model
        if context:
            full_prompt = f"Based on the following context, answer the user's question.\n\nContext:\n{context}\n\nQuestion:\n{message}"
        else:
            full_prompt = message

        try:
            response = self.chat.send_message(
               full_prompt,
               safety_settings=self.safety_levels,
               generation_config={"temperature": 0.5, "top_p": 0.95, "top_k": 40}
           )

            response_text = response.text

        except Exception as e:
            response_text = f"Sorry, I encountered an error. Please try again. Error: {str(e)}"

        self.chat_history[user_id].append({"role": "assistant", "content": response_text, "timestamp": datetime.now().isoformat()})

        return {"text": response_text}


# Example usage
if __name__ == "__main__":
    # This requires the GOOGLE_API_KEY to be set in your .env file
    # from dotenv import load_dotenv
    # load_dotenv()

    # Initialize the chatbot (replace with your actual key or use .env)
    chatbot = CybersecurityChatbot(api_key="AIzaSyBC_WTb-Gn4An32mhn8BGEEy1NgUpG8-AI")

    user_id = "security_analyst_01"
    test_message = "How do I fix a critical SQL injection vulnerability identified by a scan?"
    
    # In a real scenario, context would be retrieved from the vector DB
    test_context = "Vulnerability ID: CVE-2024-1234, Severity: CRITICAL, Description: A SQL injection vulnerability in the login form allows attackers to bypass authentication. Remediation: Use parameterized queries or prepared statements to prevent user input from being executed as SQL code."

    response = chatbot.generate_response(user_id, test_message, test_context)

    print("User:", test_message)
    print("CyberScan AI:", response["text"])