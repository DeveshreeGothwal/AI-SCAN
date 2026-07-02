from langchain_community.llms import Ollama
from langchain_community.embeddings import OllamaEmbeddings
from langchain_community.vectorstores import Chroma
from langchain.prompts import PromptTemplate

print("[*] Initializing Master Bug Hunter Pipeline...")

# 1. Load the Brain and the Memory
llm = Ollama(model="llama3")
embeddings = OllamaEmbeddings(model="nomic-embed-text")

# Connect to the database we built in Phase 3
vectorstore = Chroma(
    persist_directory="./bug_bounty_db", 
    embedding_function=embeddings
)

# 2. Define the WAF (from Phase 2)
def simulate_target_waf(payload):
    print(f"\n[->] Firing Payload: {payload}")
    forbidden_signatures = ["<script>", "alert(", "document.cookie"]
    
    for sig in forbidden_signatures:
        if sig in payload.lower():
            return False, f"403 Forbidden: Blocked by WAF rule matching '{sig}'"
            
    if "fetch(" in payload or "img src=x" in payload.lower() or "\\u003c" in payload.lower():
        return True, "200 OK: Execution successful. Check server logs."
        
    return False, "200 OK: Payload reflected safely. No execution."

# 3. Define the Prompts

# Prompt A: Generate initial payload based on Memory (RAG)
generator_template = """
You are an expert bug bounty hunter. 
Target Scenario: {scenario}
Past Writeup from Memory: {memory}

Based ONLY on the bypass technique described in the past writeup, generate an initial payload to attack the target.
Output ONLY the raw payload string. No markdown, no quotes, no explanations.

Initial Payload:
"""
generator_prompt = PromptTemplate(input_variables=["scenario", "memory"], template=generator_template)

# Prompt B: Mutate payload if WAF blocks it (Critic Loop)
mutator_template = """
You are an expert bug bounty hunter trying to bypass a Web Application Firewall (WAF). 
Original Target Scenario: {scenario}

The WAF explicitly blocked this payload: {current_payload}
Because of this error: {waf_error}

CRITICAL INSTRUCTIONS:
1. Retain the core bypass technique required for the scenario (e.g., unicode escapes).
2. ONLY change the execution payload (e.g., if alert() is blocked, switch to fetch() or console.log()).
3. Output ONLY the raw, newly mutated payload string. No markdown, no quotes.

New Payload:
"""
mutator_prompt = PromptTemplate(input_variables=["scenario", "current_payload", "waf_error"], template=mutator_template)


# 4. The Master Execution Engine
def run_autonomous_hunt(scenario, max_attempts=4):
    print(f"\n[*] Target Scenario: {scenario}")
    
    # Step A: Query Memory
    print("[*] Searching memory for relevant exploits...")
    results = vectorstore.similarity_search(scenario, k=1)
    retrieved_memory = results[0].page_content
    print(f"[*] Memory Retrieved: {retrieved_memory}")
    
    # Step B: Generate Initial Payload
    print("[*] Generating initial payload based on memory...")
    formatted_gen_prompt = generator_prompt.format(scenario=scenario, memory=retrieved_memory)
    current_payload = llm.invoke(formatted_gen_prompt).strip()
    
    # Step C: The Critic Loop
    for attempt in range(1, max_attempts + 1):
        print(f"\n--- Attempt {attempt} of {max_attempts} ---")
        
        success, waf_response = simulate_target_waf(current_payload)
        print(f"[<-] Server Response: {waf_response}")
        
        if success:
            print("\n[+] SUCCESS! Target exploited successfully.")
            break
            
        if attempt == max_attempts:
            print("\n[-] FAILED. Exhausted all attempts.")
            break
            
        print("[!] WAF triggered. Mutating payload...")
        formatted_mut_prompt = mutator_prompt.format(
            scenario=scenario,                # <-- Add this line
            current_payload=current_payload, 
            waf_error=waf_response
        )

# 5. Kick off the hunt!
attack_scenario = "I need to bypass a strict WAF filtering angle brackets to get XSS in a JSON body."
run_autonomous_hunt(attack_scenario)
