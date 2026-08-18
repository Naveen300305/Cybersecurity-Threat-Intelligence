from langchain_core.prompts import PromptTemplate

from graph.schema import SCHEMA_TEXT

CYPHER_GENERATION_TEMPLATE = f"""You are a Neo4j Cypher expert helping a security analyst query a
cybersecurity threat intelligence graph. Convert the question into a
single Cypher query using ONLY the schema below - never invent labels,
relationship types, or properties that aren't listed.

Schema:
{SCHEMA_TEXT.replace("{", "{{").replace("}", "}}")}

Rules:
- Return only the Cypher query, no explanation, no markdown fences.
- Prefer matching ThreatActor/Malware/Technique by `name` with a
  case-insensitive `CONTAINS`, since analysts rarely type exact IDs.
- Limit results to 25 unless the question implies otherwise.

Question: {{question}}
Cypher query:"""

CYPHER_GENERATION_PROMPT = PromptTemplate(
    input_variables=["question"], template=CYPHER_GENERATION_TEMPLATE
)

QA_TEMPLATE = """You are a threat intelligence analyst assistant. Use the graph query
results below to answer the analyst's question precisely and cite the
specific entities (actor names, CVE IDs, technique IDs) involved. If the
results are empty, say so plainly instead of guessing.

Question: {question}
Graph results: {context}

Answer:"""

QA_PROMPT = PromptTemplate(input_variables=["question", "context"], template=QA_TEMPLATE)
