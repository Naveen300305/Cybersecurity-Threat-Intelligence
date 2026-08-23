"""Graph RAG query engine (spec Module 2).

MVP scope: Cypher-generation retrieval only (LLM-generated Cypher over
the graph, synthesized into a natural-language answer). Vector/hybrid
retrieval is planned but not yet wired up - see rag/retrievers.py TODO.
"""

from __future__ import annotations

import os
import re

from langchain_openai import ChatOpenAI
from langchain_neo4j import GraphCypherQAChain, Neo4jGraph

from rag.prompts import CYPHER_GENERATION_PROMPT, QA_PROMPT


def _sanitize_cypher(cypher: str) -> str:
    """Strip common LLM artifacts that produce invalid Cypher.

    - Removes markdown code fences (```cypher ... ```)
    - Truncates anything after the first RETURN clause that starts a new
      WHERE/ORDER/LIMIT/SKIP on its own line (the WHERE-after-RETURN bug)
    """
    # Remove markdown fences
    cypher = re.sub(r"```(?:cypher)?", "", cypher, flags=re.IGNORECASE).strip("`").strip()

    # Find the first RETURN keyword position
    return_match = re.search(r"\bRETURN\b", cypher, flags=re.IGNORECASE)
    if return_match:
        after_return = cypher[return_match.start():]
        # A WHERE appearing on its own line after RETURN is the bug — cut it
        bad_where = re.search(r"\n\s*WHERE\b", after_return, flags=re.IGNORECASE)
        if bad_where:
            cypher = cypher[: return_match.start() + bad_where.start()]

    return cypher.strip()


def build_graph() -> Neo4jGraph:
    return Neo4jGraph(
        url=os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        username=os.environ.get("NEO4J_USERNAME", "neo4j"),
        password=os.environ["NEO4J_PASSWORD"],
    )


def build_chain(graph: Neo4jGraph | None = None) -> GraphCypherQAChain:
    graph = graph or build_graph()
    llm = ChatOpenAI(
        model=os.environ.get("NVIDIA_MODEL", "meta/llama-3.1-8b-instruct"),
        temperature=0,
        openai_api_key=os.environ.get("NVIDIA_API_KEY"),
        openai_api_base="https://integrate.api.nvidia.com/v1",
        request_timeout=30,
        max_retries=1,
    )
    return GraphCypherQAChain.from_llm(
        llm=llm,
        graph=graph,
        cypher_prompt=CYPHER_GENERATION_PROMPT,
        qa_prompt=QA_PROMPT,
        verbose=False,
        allow_dangerous_requests=True,  # read-heavy analyst queries; no write intent
        return_intermediate_steps=True,
        top_k=25,
    )


class GraphRAGEngine:
    """Thin wrapper used by the API layer so the chain is built once per process."""

    def __init__(self) -> None:
        self._chain = build_chain()

    def query(self, question: str) -> dict:
        result = self._chain.invoke({"query": question})
        steps = result.get("intermediate_steps", [])
        cypher = steps[0].get("query") if steps else None
        if cypher:
            cypher = _sanitize_cypher(cypher)
        return {
            "answer": result.get("result", ""),
            "cypher_query": cypher,
        }

