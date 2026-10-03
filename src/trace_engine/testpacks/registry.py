"""Test pack registry for looking up available security packs."""

from typing import Dict, List, Optional
from trace_engine.testpacks.base import TestPack
from trace_engine.testpacks.bola import BolaTestPack
from trace_engine.testpacks.bfla import BflaTestPack
from trace_engine.testpacks.authentication import AuthenticationTestPack
from trace_engine.testpacks.ssrf import SsrfTestPack
from trace_engine.testpacks.mass_assignment import MassAssignmentTestPack
from trace_engine.testpacks.injection import InjectionTestPack
from trace_engine.testpacks.path_traversal import PathTraversalTestPack
from trace_engine.testpacks.ssti import SstiTestPack
from trace_engine.testpacks.cors import CorsTestPack
from trace_engine.testpacks.deserialization import DeserializationTestPack


class TestPackRegistry:
    """Central registry of registered test packs."""

    def __init__(self):
        self._packs: Dict[str, TestPack] = {
            "bola": BolaTestPack(),
            "bfla": BflaTestPack(),
            "authentication": AuthenticationTestPack(),
            "ssrf": SsrfTestPack(),
            "mass_assignment": MassAssignmentTestPack(),
            "injection": InjectionTestPack(),
            "path_traversal": PathTraversalTestPack(),
            "ssti": SstiTestPack(),
            "cors": CorsTestPack(),
            "deserialization": DeserializationTestPack(),
        }

    def get(self, name: str) -> Optional[TestPack]:
        return self._packs.get(name.lower())

    def list_all(self) -> List[TestPack]:
        return list(self._packs.values())

    def register(self, pack: TestPack) -> None:
        self._packs[pack.name.lower()] = pack


default_registry = TestPackRegistry()
