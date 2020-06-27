from dataclasses import dataclass


@dataclass
class CandidateConstructionFailure(Exception):
    message: str
