from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import OllamaEmbeddings
from langchain.schema import Document

print("Initializing embedding model...")

# Set up the embedding model
embeddings = OllamaEmbeddings(model="nomic-embed-text")

# Create dummy vulnerability writeups
writeups = [
    Document(
        page_content="Target uses a strict WAF filtering angle brackets. Bypassed the WAF to achieve XSS by using unicode escapes like \\u003cscript\\u003e inside the JSON body.", 
        metadata={"source": "HackerOne", "type": "XSS"}
    ),
    Document(
        page_content="Found an IDOR in the /api/v1/profile endpoint. Changing the user_id parameter from an integer to an array like ?user_id[]=1&user_id[]=2 bypassed the authorization check.", 
        metadata={"source": "BugCrowd", "type": "IDOR"}
    )
]

print("Building the local knowledge base...")

# Initialize ChromaDB and store the writeups
vectorstore = Chroma.from_documents(
    documents=writeups,
    embedding=embeddings,
    persist_directory="./bug_bounty_db"
)

# Define a simulated target scenario
target_scenario = "I am attacking an API endpoint that checks user authorization via a user_id parameter."

print(f"\n[+] Searching memory for scenario: {target_scenario}\n")

# Search the database for the most relevant writeup
results = vectorstore.similarity_search(target_scenario, k=1)

print("--- Retrieved Intelligence ---")
print(f"Content: {results[0].page_content}")
print(f"Metadata: {results[0].metadata}")
