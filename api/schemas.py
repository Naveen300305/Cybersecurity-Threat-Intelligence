from pydantic import BaseModel


class QueryRequest(BaseModel):
    question: str


class QueryResponse(BaseModel):
    answer: str
    cypher_query: str | None = None


class ActorSummary(BaseModel):
    id: str
    name: str
    aliases: list[str] = []


class ActorProfile(ActorSummary):
    description: str = ""
    techniques: list[str] = []
    malware: list[str] = []


class CVESummary(BaseModel):
    id: str
    description: str = ""
    cvss_v3_score: float | None = None
    severity: str | None = None
    is_kev: bool = False
