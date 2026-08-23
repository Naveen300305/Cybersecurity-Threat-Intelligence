from langchain_core.prompts import PromptTemplate

from graph.schema import SCHEMA_TEXT

CYPHER_GENERATION_TEMPLATE = f"""You are a Neo4j 5 Cypher expert. Generate ONE valid Cypher query for the
cybersecurity threat intelligence graph described below.

Schema:
{SCHEMA_TEXT.replace("{", "{{").replace("}", "}}")}

STRICT RULES — violating any rule makes the query invalid:
1. Output ONLY the raw Cypher query. No markdown, no code fences, no explanation.
2. Write a SINGLE query — do NOT chain multiple MATCH/RETURN blocks.
3. WHERE must come IMMEDIATELY after MATCH or WITH, never after RETURN.
4. Use only labels, relationship types, and properties listed in the schema above.
5. Always use case-insensitive CONTAINS for name matching: toLower(n.name) CONTAINS toLower('value')
6. End with exactly one RETURN clause. Never put WHERE after RETURN.
7. Limit results: add LIMIT 25 at the end unless the question asks for more.

CORRECT example for "What techniques does APT29 use?":
MATCH (ta:ThreatActor)-[:USES]->(tech:Technique)
WHERE toLower(ta.name) CONTAINS toLower('APT29')
RETURN tech.name, tech.id
LIMIT 25

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
