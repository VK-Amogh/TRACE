"""Constructs the Attack-Path Model from parsed files and discovered endpoints."""

from pathlib import Path
from typing import List, Dict, Optional
from trace_engine.ingest.files import SourceFile
from trace_engine.parsing.parser import ParsedFile
from trace_engine.framework.base import Endpoint
from trace_engine.apm.model import AttackPathModel
from trace_engine.apm.nodes import APMNode, NodeType
from trace_engine.apm.edges import APMEdge, EdgeType


class APMBuilder:
    """Orchestrates building an Attack-Path Model graph from static analysis artifacts."""

    def __init__(self, project_name: str = "project"):
        self.project_name = project_name

    def build(
        self,
        repo_path: Path,
        source_files: List[SourceFile],
        parsed_files: List[ParsedFile],
        endpoints: List[Endpoint],
    ) -> AttackPathModel:
        apm = AttackPathModel(name=self.project_name)

        # 1. Root Repository Node
        repo_node_id = "repo_root"
        apm.add_node(
            APMNode(
                id=repo_node_id,
                node_type=NodeType.REPOSITORY,
                label=self.project_name,
                properties={"path": str(repo_path.resolve())},
            )
        )

        # 2. File Nodes
        file_node_map: Dict[str, str] = {}
        for sf in source_files:
            file_id = f"file_{sf.path.replace('/', '_').replace('.', '_')}"
            file_node_map[sf.path] = file_id
            apm.add_node(
                APMNode(
                    id=file_id,
                    node_type=NodeType.FILE,
                    label=sf.path,
                    properties={
                        "language": sf.language,
                        "line_count": sf.line_count,
                        "sha256": sf.sha256,
                    },
                )
            )
            apm.add_edge(
                APMEdge(
                    source_id=repo_node_id,
                    target_id=file_id,
                    edge_type=EdgeType.CONTAINS,
                )
            )

        # 3. Function Nodes
        func_node_map: Dict[str, str] = {}
        for pf in parsed_files:
            file_id = file_node_map.get(pf.file_path, repo_node_id)
            for fn in pf.functions:
                fn_id = f"fn_{pf.file_path}_{fn.qualified_name}".replace("/", "_").replace(".", "_")
                func_node_map[fn.qualified_name] = fn_id
                apm.add_node(
                    APMNode(
                        id=fn_id,
                        node_type=NodeType.FUNCTION,
                        label=fn.qualified_name,
                        location=fn.location,
                        properties={"is_async": fn.is_async},
                    )
                )
                apm.add_edge(
                    APMEdge(
                        source_id=file_id,
                        target_id=fn_id,
                        edge_type=EdgeType.CONTAINS,
                    )
                )

        # 4. Endpoints & Parameters
        for ep in endpoints:
            ep_node_id = ep.id
            apm.add_node(
                APMNode(
                    id=ep_node_id,
                    node_type=NodeType.ENDPOINT,
                    label=ep.display_name(),
                    location=ep.source,
                    properties={
                        "method": ep.method,
                        "path": ep.path,
                        "auth_required": ep.auth_required,
                        "roles": ep.roles,
                        "object_identifier": ep.object_identifier,
                        "state_changing": ep.state_changing,
                        "sensitive_data": ep.sensitive_data,
                    },
                )
            )

            # Connect File -> Endpoint
            file_id = file_node_map.get(ep.source.file, repo_node_id)
            apm.add_edge(
                APMEdge(
                    source_id=file_id,
                    target_id=ep_node_id,
                    edge_type=EdgeType.EXPOSES,
                )
            )

            # Connect Endpoint -> Handler Function
            if ep.handler_name in func_node_map:
                apm.add_edge(
                    APMEdge(
                        source_id=ep_node_id,
                        target_id=func_node_map[ep.handler_name],
                        edge_type=EdgeType.ROUTES_TO,
                    )
                )

            # Parameters
            for param in ep.parameters:
                param_id = f"param_{ep.id}_{param.name}"
                apm.add_node(
                    APMNode(
                        id=param_id,
                        node_type=NodeType.PARAMETER,
                        label=param.name,
                        properties={
                            "location": param.location,
                            "type": param.param_type,
                            "user_controlled": param.user_controlled,
                        },
                    )
                )
                apm.add_edge(
                    APMEdge(
                        source_id=ep_node_id,
                        target_id=param_id,
                        edge_type=EdgeType.RECEIVES,
                    )
                )

            # Auth Gate Node
            if ep.auth_required:
                auth_id = f"auth_{ep.id}"
                apm.add_node(
                    APMNode(
                        id=auth_id,
                        node_type=NodeType.AUTH_CHECK,
                        label="AuthGate" if not ep.roles else f"RoleGate({','.join(ep.roles)})",
                        properties={"roles": ep.roles},
                    )
                )
                apm.add_edge(
                    APMEdge(
                        source_id=auth_id,
                        target_id=ep_node_id,
                        edge_type=EdgeType.PROTECTS,
                    )
                )

            # Sinks / Database Nodes
            if ep.database_access:
                db_id = f"db_{ep.id}"
                apm.add_node(
                    APMNode(
                        id=db_id,
                        node_type=NodeType.DATABASE,
                        label="DatabaseAccess",
                        properties={"operation": "lookup" if ep.object_identifier else "query"},
                    )
                )
                apm.add_edge(
                    APMEdge(
                        source_id=ep_node_id,
                        target_id=db_id,
                        edge_type=EdgeType.ACCESSES,
                    )
                )

            if ep.external_network:
                ext_id = f"ext_{ep.id}"
                apm.add_node(
                    APMNode(
                        id=ext_id,
                        node_type=NodeType.EXTERNAL_SERVICE,
                        label="OutboundHTTPClient",
                        properties={"risk": "SSRF"},
                    )
                )
                apm.add_edge(
                    APMEdge(
                        source_id=ep_node_id,
                        target_id=ext_id,
                        edge_type=EdgeType.CONNECTS_TO,
                    )
                )

        return apm
