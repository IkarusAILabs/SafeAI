"""Static delegation graph (v2.10, ROADMAP B2, plan item 2.11-1).

Which agent can hand work to which other agent, read from configuration
and literal source structure only. Three sources have explicit edges:

* **Claude Code**: the main session delegates to each subagent in
  ``.claude/agents/``. A subagent's ``tools:`` list *restricts* the
  session's tools and the same permission rules apply to both, so a
  subagent cannot hold authority its session lacks; ``exceeds`` is not
  evaluated for these edges.
* **OpenAI Agents SDK**: ``Agent(name=..., tools=[...], handoffs=[...])``;
  each handoff target is an edge. Each agent has its own tools, so a
  delegate can hold tools its delegator does not.
* **CrewAI**: an ``Agent(..., allow_delegation=True)`` in a
  ``Crew(agents=[...])`` can delegate to every other agent of that crew;
  a hierarchical crew's manager delegates to all of them.
* **LangGraph** (v2.14): ``create_supervisor([...])`` delegates to each
  agent it is given (a compiled supervisor can itself be a member);
  ``create_handoff_tool(agent_name=...)`` in an agent's ``tools`` (swarm)
  is an edge to the named agent. Agents are ``create_react_agent(...,
  tools=[...], name=...)``.
* **AutoGen** (v2.14): ``AssistantAgent(name, tools=[...],
  handoffs=[...])``, each handoff (a name or ``Handoff(target=...)``) an
  edge; ``RoundRobinGroupChat``, ``SelectorGroupChat`` and
  ``MagenticOneGroupChat`` teams, and a 0.2 ``GroupChat`` with its
  ``GroupChatManager``, are a manager that hands work to every
  participant. A ``Swarm`` team adds no edges of its own: its members
  hand off through ``handoffs``.

Agents and tools are matched by the names bound in the same file. A
handoff target that is not a literal reference (a factory call, a
variable built at run time) is recorded as ``unresolved``, never
guessed. Authority for OpenAI and CrewAI agents is compared by tool
*name*: capability detection in Python source is not yet attributed to
tool functions, so the tool is the finest grain available.
"""

import ast
import os

from safeai.frameworks.claude_code import commands as cc_commands
from safeai.frameworks.claude_code import settings as cc_settings
from safeai.kya.util import redact_secrets

_MAX_FILE_BYTES = 512 * 1024
_MAX_FILES = 2000
_MAX_NODES = 500

#: Claude Code settings files that hold the session's allow rules.
_SESSION_SETTINGS = (".claude/settings.json", ".claude/settings.local.json")

#: Frameworks with an ``Agent`` class, by the module it is imported from.
_AGENT_MODULES = {"agents": "openai_agents", "crewai": "crewai"}

#: v2.14: LangGraph and AutoGen constructors, by ``(module, name)`` of the
#: ``from`` import, as ``(framework, role)``. Roles: ``agent`` builds an
#: agent; ``team`` is a manager handing work to every participant;
#: ``supervisor`` is a LangGraph supervisor (an agent with members);
#: ``swarm`` groups agents that hand off among themselves;
#: ``handoff-tool`` / ``handoff`` name a handoff target; ``group-chat`` and
#: ``group-chat-manager`` are AutoGen 0.2's two halves of a team.
_CONSTRUCTORS = {
    ("langgraph.prebuilt", "create_react_agent"): ("langgraph", "agent"),
    ("langgraph_supervisor", "create_supervisor"): ("langgraph", "supervisor"),
    ("langgraph_supervisor", "create_handoff_tool"): ("langgraph", "handoff-tool"),
    ("langgraph_swarm", "create_swarm"): ("langgraph", "swarm"),
    ("langgraph_swarm", "create_handoff_tool"): ("langgraph", "handoff-tool"),
    ("autogen_agentchat.agents", "AssistantAgent"): ("autogen", "agent"),
    ("autogen_agentchat.agents", "CodeExecutorAgent"): ("autogen", "agent"),
    ("autogen_agentchat.teams", "RoundRobinGroupChat"): ("autogen", "team"),
    ("autogen_agentchat.teams", "SelectorGroupChat"): ("autogen", "team"),
    ("autogen_agentchat.teams", "MagenticOneGroupChat"): ("autogen", "team"),
    ("autogen_agentchat.teams", "Swarm"): ("autogen", "swarm"),
    ("autogen_agentchat.base", "Handoff"): ("autogen", "handoff"),
    ("autogen", "AssistantAgent"): ("autogen", "agent"),
    ("autogen", "ConversableAgent"): ("autogen", "agent"),
    ("autogen", "GroupChat"): ("autogen", "group-chat"),
    ("autogen", "GroupChatManager"): ("autogen", "group-chat-manager"),
}
#: Agent frameworks whose agents hold their own tools (compared by name).
PYTHON_FRAMEWORKS = ("openai_agents", "crewai", "langgraph", "autogen")
_PYTHON_MARKERS = ("Agent(", "agent(", "GroupChat(", "Swarm(", "create_supervisor(")


def empty_graph():
    return {"lane": "B", "nodes": [], "edges": [], "unresolved": [],
            "counts": {"nodes": 0, "edges": 0, "unresolved": 0, "max_depth": 0},
            "cycles": False, "notes": []}


# --- file walk ---------------------------------------------------------------

def _excluded(rel, excluded_paths):
    for marker in excluded_paths or []:
        clean = str(marker).replace("\\", "/").strip("/")
        if rel == clean or rel.startswith(clean + "/"):
            return True
    return False


def _read(root, rel):
    full = os.path.join(root, rel)
    try:
        if os.path.getsize(full) > _MAX_FILE_BYTES:
            return None
        with open(full, encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError):
        return None


def _candidate_files(root, excluded_paths):
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in (".git", "node_modules", ".venv", "venv"))
        for filename in sorted(filenames):
            try:
                rel = os.path.relpath(os.path.join(dirpath, filename), root)
            except ValueError:
                continue
            rel = rel.replace("\\", "/")
            if rel.startswith("..") or _excluded(rel, excluded_paths):
                continue
            if (rel in _SESSION_SETTINGS
                    or (rel.startswith(cc_commands.AGENTS_PREFIX) and rel.endswith(".md"))
                    or rel.endswith(".py")):
                seen += 1
                if seen > _MAX_FILES:
                    return
                yield rel


# --- Claude Code ---------------------------------------------------------------

def _claude_code(root, files):
    nodes, edges = [], []
    allow = []
    settings_files = []
    for rel in _SESSION_SETTINGS:
        if rel not in files:
            continue
        text = _read(root, rel)
        data, error = cc_settings.loads_lenient(text or "")
        if error is not None or not isinstance(data, dict):
            continue
        settings_files.append(rel)
        # Entries are redacted as the permissions parser redacts them: a
        # secret inside a rule (``Bash(API_KEY=...)``) never reaches a report.
        allow.extend(redact_secrets(str(entry), full_mask=True)
                     for decision, entry in cc_settings.extract_permission_entries(data)
                     if decision == "allow")
    subagents = []
    for rel in sorted(f for f in files if f.startswith(cc_commands.AGENTS_PREFIX)):
        text = _read(root, rel)
        if text is None:
            continue
        subagents.append(cc_commands.parse_subagent(rel, text))
    if not subagents and not settings_files:
        return nodes, edges
    # The session is a node whenever its permissions are configured, so other
    # analyses (Separation of Duties) can read its authority; it is a
    # delegator only when subagents exist.
    session = {
        "id": "claude_code:session", "framework": "claude_code", "kind": "session",
        "name": "session", "source_file": settings_files[0] if settings_files else "",
        "line": 1, "authority": sorted(set(allow)), "authority_basis": "permission-allow",
        "inherits": False,
    }
    nodes.append(session)
    for sub in sorted(subagents, key=lambda s: s["name"]):
        node_id = f"claude_code:subagent:{sub['name']}"
        inherits = not sub["tools"]
        nodes.append({
            "id": node_id, "framework": "claude_code", "kind": "subagent",
            "name": sub["name"], "source_file": sub["path"], "line": 1,
            "authority": sorted({redact_secrets(str(t), full_mask=True) for t in sub["tools"]}),
            "authority_basis": "subagent-tools",
            "inherits": inherits,
        })
        edges.append({
            "from": session["id"], "to": node_id, "framework": "claude_code",
            "kind": "subagent", "evidence": [{"file": sub["path"], "line": 1}],
            "exceeds": None,
            "exceeds_note": "subagent tools restrict the session's; permission rules "
                            "apply to both",
        })
    return nodes, edges


# --- Python (OpenAI Agents SDK, CrewAI) --------------------------------------

def _call_name(node):
    func = node.func if isinstance(node, ast.Call) else node
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _kwarg(call, key):
    for keyword in call.keywords:
        if keyword.arg == key:
            return keyword.value
    return None


def _literal_str(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _ref_name(node):
    """A tool or agent reference: ``name``, ``mod.name`` or ``name(...)``."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _frameworks_imported(tree):
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                constructor = _CONSTRUCTORS.get((node.module, alias.name))
                if constructor:
                    found[alias.asname or alias.name] = ":".join(constructor)
            top = node.module.split(".", 1)[0]
            if top in _AGENT_MODULES:
                for alias in node.names:
                    if alias.name == "Agent":
                        found[alias.asname or "Agent"] = _AGENT_MODULES[top]
                    if alias.name == "Crew" and top == "crewai":
                        found[alias.asname or "Crew"] = "crewai:crew"
                    if alias.name == "handoff" and top == "agents":
                        found[alias.asname or "handoff"] = "openai_agents:handoff"
    return found


def _tool_names(value, skip=()):
    names = []
    if isinstance(value, (ast.List, ast.Tuple)):
        for element in value.elts:
            if isinstance(element, ast.Call) and _call_name(element) in skip:
                continue
            name = _ref_name(element) or (_call_name(element) if isinstance(element, ast.Call)
                                          else None)
            if name:
                names.append(name)
    return sorted(set(names))


def _uncompiled(call):
    """``create_supervisor(...)`` behind ``create_supervisor(...).compile(...)``."""
    while (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
           and call.func.attr == "compile" and isinstance(call.func.value, ast.Call)):
        call = call.func.value
    return call


def _named_handoffs(call, framework, roles):
    """``[(target name or None, node)]`` for handoffs named rather than bound."""
    found = []
    if framework == "autogen":
        value = _kwarg(call, "handoffs")
        for element in getattr(value, "elts", None) or []:
            if isinstance(element, ast.Call) and roles.get(_call_name(element)) == "handoff":
                target = _kwarg(element, "target")
                found.append((_literal_str(target) if target is not None else None, element))
            else:
                found.append((_literal_str(element), element))
    elif framework == "langgraph":
        for element in getattr(_kwarg(call, "tools"), "elts", None) or []:
            if isinstance(element, ast.Call) and roles.get(_call_name(element)) == "handoff-tool":
                target = _kwarg(element, "agent_name") or (element.args[0] if element.args
                                                           else None)
                found.append((_literal_str(target) if target is not None else None, element))
    return found


def _python_file(rel, text):
    """Agents, crews, teams and handoffs bound in one Python file."""
    if not any(marker in text for marker in _PYTHON_MARKERS):
        return None
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    imported = _frameworks_imported(tree)
    agent_names = {alias: fw for alias, fw in imported.items() if fw in ("openai_agents", "crewai")}
    agent_names.update({alias: fw.split(":", 1)[0] for alias, fw in imported.items()
                        if fw in ("langgraph:agent", "autogen:agent")})
    roles = {alias: fw.split(":", 1)[1] for alias, fw in imported.items()
             if fw.startswith(("langgraph:", "autogen:"))}
    team_names = {alias for alias, role in roles.items()
                  if role in ("team", "supervisor", "swarm", "group-chat", "group-chat-manager")}
    if not agent_names and not team_names:
        return None
    crew_names = {a for a, fw in imported.items() if fw == "crewai:crew"}
    handoff_names = {a for a, fw in imported.items() if fw == "openai_agents:handoff"}
    handoff_tools = {a for a, role in roles.items() if role == "handoff-tool"}

    agents = {}  # binding -> agent record
    crews = []
    teams = []  # (call, binding)

    def agent_record(call, binding):
        framework = agent_names[_call_name(call)]
        label = (_literal_str(_kwarg(call, "name")) or _literal_str(_kwarg(call, "role"))
                 or (_literal_str(call.args[0]) if framework == "autogen" and call.args
                     else None)
                 or binding or f"agent@{call.lineno}")
        delegation = _kwarg(call, "allow_delegation")
        return {
            "binding": binding, "framework": framework, "name": label,
            "line": call.lineno, "tools": _tool_names(_kwarg(call, "tools"), handoff_tools),
            "handoffs": _kwarg(call, "handoffs") if framework == "openai_agents" else None,
            "named_handoffs": _named_handoffs(call, framework, roles),
            "allow_delegation": isinstance(delegation, ast.Constant) and delegation.value is True,
        }

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            value = _uncompiled(node.value)
            name = _call_name(value)
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if name in agent_names and targets:
                agents[targets[0]] = agent_record(value, targets[0])
            elif name in crew_names:
                crews.append(node.value)
            elif name in team_names:
                teams.append((value, targets[0] if targets else None))
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) \
                and _call_name(node.value) in crew_names:
            crews.append(node.value)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node) in crew_names \
                and node not in crews:
            crews.append(node)

    bound = {id(call) for call, _ in teams}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node) in team_names \
                and id(node) not in bound:
            teams.append((node, None))
            bound.add(id(node))
    teams.sort(key=lambda item: (item[0].lineno, item[0].col_offset))

    return {"rel": rel, "agents": agents, "crews": crews, "teams": teams, "roles": roles,
            "agent_names": agent_names, "handoff_names": handoff_names,
            "handoff_tools": handoff_tools, "record": agent_record}


def _node_for(rel, record):
    return {
        "id": f"{record['framework']}:{rel}:{record['name']}",
        "framework": record["framework"], "kind": "agent", "name": record["name"],
        "source_file": rel, "line": record["line"], "authority": record["tools"],
        "authority_basis": "tool-name", "inherits": False,
    }


def _python_edges(parsed):
    rel = parsed["rel"]
    nodes, edges, unresolved = {}, [], []
    for record in parsed["agents"].values():
        node = _node_for(rel, record)
        nodes[node["id"]] = node

    def resolve(element, source):
        """Node for one handoff element, or None (recorded as unresolved)."""
        if isinstance(element, ast.Call) and _call_name(element) in parsed["handoff_names"]:
            target = element.args[0] if element.args else _kwarg(element, "agent")
            return resolve(target, source) if target is not None else None
        if isinstance(element, ast.Call) and _call_name(element) in parsed["agent_names"]:
            record = parsed["record"](element, None)
            node = _node_for(rel, record)
            nodes.setdefault(node["id"], node)
            return node
        name = _ref_name(element)
        if name and name in parsed["agents"]:
            return nodes[_node_for(rel, parsed["agents"][name])["id"]]
        unresolved.append({
            "from": source["id"],
            "target": name or (_call_name(element) + "()" if isinstance(element, ast.Call)
                               else type(element).__name__),
            "reason": ("handoff target is not an agent bound in this file"
                       if name else "handoff target is built at run time"),
            "evidence": [{"file": rel, "line": getattr(element, "lineno", source["line"])}],
        })
        return None

    for record in list(parsed["agents"].values()):
        source = nodes[_node_for(rel, record)["id"]]
        handoffs = record["handoffs"]
        if handoffs is None:
            continue
        if not isinstance(handoffs, (ast.List, ast.Tuple)):
            unresolved.append({"from": source["id"], "target": "handoffs",
                               "reason": "handoffs list is not a literal",
                               "evidence": [{"file": rel, "line": record["line"]}]})
            continue
        for element in handoffs.elts:
            target = resolve(element, source)
            if target is not None:
                edges.append(_edge(source, target, "handoff", rel, record["line"]))

    by_label = {}
    for record in parsed["agents"].values():
        by_label.setdefault(record["name"], record)
    for record in list(parsed["agents"].values()):
        source = nodes[_node_for(rel, record)["id"]]
        for target_name, element in record["named_handoffs"]:
            target = by_label.get(target_name) if target_name else None
            if target is None:
                unresolved.append({
                    "from": source["id"], "target": target_name or "handoff",
                    "reason": ("handoff target is not an agent named in this file"
                               if target_name else "handoff target is built at run time"),
                    "evidence": [{"file": rel, "line": getattr(element, "lineno",
                                                               record["line"])}]})
                continue
            edges.append(_edge(source, nodes[_node_for(rel, target)["id"]], "handoff", rel,
                               getattr(element, "lineno", record["line"])))

    _team_edges(parsed, nodes, edges, unresolved)

    for crew in parsed["crews"]:
        members = []
        for element in getattr(_kwarg(crew, "agents"), "elts", []) or []:
            name = _ref_name(element)
            if name in parsed["agents"]:
                members.append(nodes[_node_for(rel, parsed["agents"][name])["id"]])
        process = _kwarg(crew, "process")
        hierarchical = isinstance(process, ast.Attribute) and process.attr == "hierarchical"
        manager = _ref_name(_kwarg(crew, "manager_agent")) if _kwarg(crew, "manager_agent") \
            else None
        if hierarchical:
            if manager in parsed["agents"]:
                boss = nodes[_node_for(rel, parsed["agents"][manager])["id"]]
            else:
                boss = {"id": f"crewai:{rel}:manager@{crew.lineno}", "framework": "crewai",
                        "kind": "manager", "name": "manager", "source_file": rel,
                        "line": crew.lineno, "authority": [], "authority_basis": "tool-name",
                        "inherits": False}
                nodes.setdefault(boss["id"], boss)
            for member in members:
                if member["id"] != boss["id"]:
                    edges.append(_edge(boss, member, "crew-manager", rel, crew.lineno))
        for member in members:
            record = next(r for r in parsed["agents"].values()
                          if _node_for(rel, r)["id"] == member["id"])
            if not record["allow_delegation"]:
                continue
            for other in members:
                if other["id"] != member["id"]:
                    edges.append(_edge(member, other, "crew-delegation", rel, crew.lineno))
    return list(nodes.values()), edges, unresolved


def _team_members(parsed, call, supervisors):
    """Member nodes of a team call, and the elements that could not be resolved."""
    value = call.args[0] if call.args else (_kwarg(call, "participants")
                                            or _kwarg(call, "agents"))
    members, missing = [], []
    for element in getattr(value, "elts", None) or []:
        name = _ref_name(element)
        if name in parsed["agents"]:
            members.append(_node_for(parsed["rel"], parsed["agents"][name]))
        elif name in supervisors:
            members.append(supervisors[name])
        else:
            missing.append((name, element))
    if value is not None and not isinstance(value, (ast.List, ast.Tuple)):
        missing.append((None, value))
    return members, missing


def _team_edges(parsed, nodes, edges, unresolved):
    """LangGraph supervisors and AutoGen teams (v2.14): manager -> each member."""
    rel, roles = parsed["rel"], parsed["roles"]
    managers = {}  # 0.2 GroupChat binding -> manager name
    for call, binding in parsed["teams"]:
        if roles.get(_call_name(call)) == "group-chat-manager":
            chat = _ref_name(_kwarg(call, "groupchat"))
            if chat:
                managers[chat] = _literal_str(_kwarg(call, "name")) or binding or "chat_manager"
    supervisors = {}  # binding -> supervisor node (a compiled supervisor can be a member)
    for call, binding in parsed["teams"]:
        role = roles.get(_call_name(call))
        if role in ("swarm", "group-chat-manager"):
            continue
        if role == "supervisor":
            framework, kind = "langgraph", "supervisor"
            name = _literal_str(_kwarg(call, "supervisor_name")) or "supervisor"
            authority = _tool_names(_kwarg(call, "tools"), parsed["handoff_tools"])
        else:
            framework, kind, authority = "autogen", "group-chat-manager", []
            name = (managers.get(binding, "chat_manager") if role == "group-chat"
                    else binding or _call_name(call))
        manager = {"id": f"{framework}:{rel}:{name}", "framework": framework, "kind": kind,
                   "name": name, "source_file": rel, "line": call.lineno,
                   "authority": authority, "authority_basis": "tool-name", "inherits": False}
        manager = nodes.setdefault(manager["id"], manager)
        if binding and role == "supervisor":
            supervisors[binding] = manager
        members, missing = _team_members(parsed, call, supervisors)
        for member in members:
            member = nodes.setdefault(member["id"], member)
            if member["id"] != manager["id"]:
                edges.append(_edge(manager, member, kind, rel, call.lineno))
        for name_or_none, element in missing:
            unresolved.append({
                "from": manager["id"], "target": name_or_none or "members",
                "reason": ("team member is not an agent bound in this file" if name_or_none
                           else "team members are built at run time"),
                "evidence": [{"file": rel, "line": getattr(element, "lineno", call.lineno)}]})


def _edge(source, target, kind, rel, line):
    exceeds = sorted(set(target["authority"]) - set(source["authority"]))
    return {"from": source["id"], "to": target["id"], "framework": source["framework"],
            "kind": kind, "evidence": [{"file": rel, "line": int(line or 1)}],
            "exceeds": exceeds, "exceeds_note": ""}


# --- graph metrics ---------------------------------------------------------------

def _depth_and_cycles(nodes, edges):
    """Longest delegation chain (edges) from any root, and whether a cycle exists."""
    adjacency = {}
    for edge in edges:
        adjacency.setdefault(edge["from"], set()).add(edge["to"])
    cycles = False
    best = {}

    def longest(node, path):
        nonlocal cycles
        if node in best:
            return best[node]
        depth = 0
        for nxt in sorted(adjacency.get(node, ())):
            if nxt in path:
                cycles = True
                continue
            depth = max(depth, 1 + longest(nxt, path | {nxt}))
        best[node] = depth
        return depth

    roots = sorted({n["id"] for n in nodes} - {e["to"] for e in edges}) or \
        sorted(n["id"] for n in nodes)
    max_depth = 0
    for root in roots:
        max_depth = max(max_depth, longest(root, {root}))
    return max_depth, cycles


def build_delegation_graph(root, excluded_paths=None):
    """Scan ``root`` for static delegation edges. Never raises."""
    try:
        files = sorted(_candidate_files(root, excluded_paths))
    except OSError:
        return empty_graph()
    nodes, edges = _claude_code(root, set(files))
    unresolved = []
    for rel in files:
        if not rel.endswith(".py"):
            continue
        text = _read(root, rel)
        if not text:
            continue
        try:
            parsed = _python_file(rel, text)
        except RecursionError:
            continue
        if parsed is None:
            continue
        file_nodes, file_edges, file_unresolved = _python_edges(parsed)
        nodes.extend(file_nodes)
        edges.extend(file_edges)
        unresolved.extend(file_unresolved)

    graph = empty_graph()
    if len(nodes) > _MAX_NODES:
        graph["notes"].append(f"more than {_MAX_NODES} agents; graph truncated")
        nodes = nodes[:_MAX_NODES]
        kept = {n["id"] for n in nodes}
        edges = [e for e in edges if e["from"] in kept and e["to"] in kept]
    unique_edges = {}
    for edge in edges:
        unique_edges.setdefault((edge["from"], edge["to"]), edge)
    edges = sorted(unique_edges.values(), key=lambda e: (e["from"], e["to"]))
    nodes = sorted({n["id"]: n for n in nodes}.values(), key=lambda n: n["id"])
    unresolved.sort(key=lambda u: (u["from"], u["target"]))
    max_depth, cycles = _depth_and_cycles(nodes, edges)
    breadth = {}
    for edge in edges:
        breadth[edge["from"]] = breadth.get(edge["from"], 0) + 1
    graph.update({
        "nodes": nodes, "edges": edges, "unresolved": unresolved, "cycles": cycles,
        "counts": {"nodes": len(nodes), "edges": len(edges), "unresolved": len(unresolved),
                   "max_depth": max_depth,
                   "max_breadth": max(breadth.values()) if breadth else 0,
                   "edges_exceeding_delegator": sum(1 for e in edges if e["exceeds"])},
    })
    return graph


# --- change types (baseline vs current) ---------------------------------------

#: Delegation change types (all on the ``delegation`` dimension, review-only).
DELEGATION_CHANGE_TYPES = (
    "DELEGATE_ADDED",
    "DELEGATION_BREADTH_INCREASED",
    "DELEGATION_DEPTH_INCREASED",
    "DELEGATE_EXCEEDS_DELEGATOR",
    "SUBAGENT_TOOLS_WIDENED",
)


def _label(node):
    """Stable identity across scans: framework and agent name, not file path
    (moving a file is not a delegation change)."""
    return f"{node['framework']}:{node['name']}"


def _graph_of(report):
    graph = (report or {}).get("delegation_graph")
    return graph if isinstance(graph, dict) else None


def _views(graph):
    by_id = {n["id"]: n for n in graph.get("nodes") or [] if isinstance(n, dict)}
    edges, exceeds, breadth = {}, set(), {}
    for edge in graph.get("edges") or []:
        if edge.get("from") not in by_id or edge.get("to") not in by_id:
            continue
        key = (_label(by_id[edge["from"]]), _label(by_id[edge["to"]]))
        edges[key] = edge
        breadth[key[0]] = breadth.get(key[0], 0) + 1
        for tool in edge.get("exceeds") or []:
            exceeds.add((key[0], key[1], tool))
    subagents = {_label(n): n for n in by_id.values() if n.get("kind") == "subagent"}
    return edges, exceeds, breadth, subagents


def _delegation_change(change_type, subject, detail, evidence=None):
    return {"type": change_type, "dimension": "delegation", "subject": subject,
            "detail": detail, "evidence": list(evidence or []),
            "provenance_class": "detected", "gateability": "review-only"}


def compute_delegation_changes(current_report, baseline_report):
    """Delegation changes from the baseline scan to the current one (Lane B)."""
    after, before = _graph_of(current_report), _graph_of(baseline_report)
    if after is None or before is None:
        return {"lane": "B", "baseline_available": False, "changes": [], "counts": {},
                "notes": [("baseline report has no delegation_graph (scanned before "
                           "v2.10): delegation changes not assessed")]}
    old_edges, old_exceeds, old_breadth, old_subs = _views(before)
    new_edges, new_exceeds, new_breadth, new_subs = _views(after)
    changes = []
    for key in sorted(set(new_edges) - set(old_edges)):
        changes.append(_delegation_change(
            "DELEGATE_ADDED", f"{key[0]} -> {key[1]}",
            f"{key[0]} can now delegate to {key[1]} ({new_edges[key]['kind']})",
            new_edges[key].get("evidence")))
    for delegator in sorted(new_breadth):
        if new_breadth[delegator] > old_breadth.get(delegator, 0) and old_breadth.get(delegator):
            changes.append(_delegation_change(
                "DELEGATION_BREADTH_INCREASED", delegator,
                f"delegates to {new_breadth[delegator]} agents (was {old_breadth[delegator]})"))
    old_depth = int((before.get("counts") or {}).get("max_depth") or 0)
    new_depth = int((after.get("counts") or {}).get("max_depth") or 0)
    if new_depth > old_depth:
        changes.append(_delegation_change(
            "DELEGATION_DEPTH_INCREASED", "max_depth",
            f"longest delegation chain is {new_depth} hops (was {old_depth})"))
    for delegator, delegate, tool in sorted(new_exceeds - old_exceeds):
        changes.append(_delegation_change(
            "DELEGATE_EXCEEDS_DELEGATOR", f"{delegator} -> {delegate}: {tool}",
            f"{delegate} holds {tool}, which {delegator} does not",
            new_edges[(delegator, delegate)].get("evidence")))
    for label in sorted(set(new_subs) & set(old_subs)):
        old, new = old_subs[label], new_subs[label]
        if old.get("inherits"):
            continue
        if new.get("inherits"):
            detail = "tools: removed, so the subagent now has every session tool"
        else:
            gained = sorted(set(new.get("authority") or []) - set(old.get("authority") or []))
            if not gained:
                continue
            detail = "tools gained: " + ", ".join(gained)
        changes.append(_delegation_change(
            "SUBAGENT_TOOLS_WIDENED", label, detail,
            [{"file": new.get("source_file"), "line": 1}]))
    changes.sort(key=lambda c: (c["type"], c["subject"]))
    counts = {}
    for change in changes:
        counts[change["type"]] = counts.get(change["type"], 0) + 1
    return {"lane": "B", "baseline_available": True, "changes": changes,
            "counts": dict(sorted(counts.items())), "notes": []}
