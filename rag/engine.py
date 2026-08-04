"""Graph RAG query engine (spec Module 2).

MVP scope: Cypher-generation retrieval only (LLM-generated Cypher over
the graph, synthesized into a natural-language answer). Vector/hybrid
retrieval is planned but not yet wired up - see rag/retrievers.py TODO.
"""

from __future__ import annotations

import os

from langchain_anthropic import ChatAnthropic
from langchain_neo4j import GraphCypherQAChain, Neo4jGraph

from rag.prompts import CYPHER_GENERATION_PROMPT, QA_PROMPT


def build_graph() -> Neo4jGraph:
    return Neo4jGraph(
        url=os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        username=os.environ.get("NEO4J_USERNAME", "neo4j"),
        password=os.environ["NEO4J_PASSWORD"],
    )


def build_chain(graph: Neo4jGraph | None = None) -> GraphCypherQAChain:
    graph = graph or build_graph()
    llm = ChatAnthropic(
        model=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5"), temperature=0
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
        return {
            "answer": result.get("result", ""),
            "cypher_query": cypher,
        }
