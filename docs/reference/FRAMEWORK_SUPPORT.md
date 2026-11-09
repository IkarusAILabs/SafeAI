# SafeAI — Framework Support Reference

> **Current release: v2.3.0** (2026-09-16) — plugin SDK and rule
> ecosystem (analyzer registry, per-scan pack versions, component
> lockfile, `safeai rules check`), OpenClaw and GitHub Copilot
> config-file adapters.

This document details the detection approach, discovered artifacts, capabilities, and limitations for each supported AI agent framework.

## Maturity Categories

| Category | Meaning |
|----------|---------|
| **Supported** | Full detection, discovery, capability, and risk analysis with regression tests |
| **Partial** | Reliable detection and discovery; capability/risk analysis covers common patterns |
| **Experimental** | Detection and basic artifact discovery; framework-specific analysis is limited |
| **Detection-only** | Presence detection only; no meaningful artifact extraction yet |
| **Planned** | Not yet implemented |

No framework is currently rated **Supported** — SafeAI is in early preview and
we deliberately do not overclaim coverage.

---

## Framework Support Summary

| Framework | Detection Method | Discovery Depth | Capability Analysis | Risk Analysis | Maturity |
|-----------|-----------------|----------------|---------------------|---------------|----------|
| LangGraph | AST + regex | Nodes, edges, tools, models, memory | Shell, filesystem, memory, planner | Partial | Partial |
| CrewAI | AST + regex | Agents, tasks, tools, models, memory | Shell, memory, delegations | Partial | Partial |
| LangChain | AST + metadata + regex | Agents, chains, tools, memory, models | Shell, memory, planner | Partial | Partial |
| Semantic Kernel | AST + metadata + regex | Workflows, plugins, memory, models, skills | Shell, memory, planner | Partial | Partial |
| OpenAI Agents SDK | AST + metadata + regex | Agents, tools, handoffs, MCP | Multi-agent, delegation, MCP | Partial | Partial |
| Microsoft Agent Framework | AST + config + deps + regex | Agents, workflows, tools, memory, models | Cloud, memory | Minimal | Experimental |
| Azure AI Foundry | Configuration | Tools, models from YAML | Cloud | Minimal | Experimental |
| Bedrock Agent | JSON agent definitions (Bedrock API keys, `AWS::Bedrock::Agent` in CloudFormation JSON, or an `actions` list in a config named for Bedrock) | Agent names; tools from `actions` and action groups | (minimal) | Minimal | Experimental |
| Claude Code | CLAUDE.md + .claude config (deep) | Settings, permissions, MCP config, slash commands, subagents, hooks | Shell, filesystem, MCP, delegation | Partial | Partial |
| Google ADK | AST + imports | Agents, workflows, tools, models | External APIs | Minimal | Experimental |
| Mastra | AST + imports | Agents, workflows, tools, models | Multi-agent, RAG, external APIs | Minimal | Experimental |
| Haystack | AST + imports | Pipelines, agents, tools, generators | RAG, external APIs, browser | Minimal | Experimental |
| LlamaIndex | AST + imports | Agents, tools, indexes, models | RAG, databases, external APIs | Minimal | Experimental |
| Dify | YAML/JSON + references | Workflows, agents, tools, models | Shell, databases, external APIs | Minimal | Experimental |
| n8n | Workflow JSON (n8n node types) + Python references outside comments | Workflows, nodes, connections | Shell, databases, email, external APIs | Minimal | Experimental |
| Cursor (.cursorrules) | Filename + JSON/YAML/free text | Declared tools, model | Shell, filesystem, external APIs, databases | Minimal | Experimental |
| Windsurf (.windsurfrules) | Filename + JSON/YAML/free text | Declared tools, model | Shell, filesystem, external APIs, databases | Minimal | Experimental |
| OpenClaw config | Filename + JSON/YAML/free text | Declared tools, model, MCP servers | Shell, filesystem, external APIs, databases, MCP | Minimal | Experimental |
| GitHub Copilot instructions | Filename + Markdown/frontmatter/YAML | Declared tools, model, MCP servers | Shell, filesystem, external APIs, databases, MCP | Minimal | Experimental |

---

## LangGraph

### Detection Approach

**Priority:** AST → regex fallback

- **Imports:** Detects `langgraph` in Python import statements
- **AST:** Parses `StateGraph`, `add_edge`, `add_node`, and function definitions
- **Dependencies:** `langgraph` in `requirements.txt`, `pyproject.toml`, etc.
- **Regex fallback:** `StateGraph`, `Graph(`, `add_edge` patterns

### Artifacts Discovered

| Artifact | Detection | Confidence | Description |
|----------|-----------|-----------|-------------|
| Graph nodes | AST function definitions | 0.89 | Agent workflow node functions |
| Workflow edges | AST `add_edge` calls | 0.89 | Graph connection edges |
| Tools | AST `bind_tools`, `tool` calls | 0.85 | Tools bound to graph nodes |
| Models | AST model constructor calls | 0.80 | LLM provider references |
| Memory / Checkpointer | AST `memory`, `checkpointer` keywords | 0.85 | State persistence mechanisms |
| Prompts | AST call names containing "prompt" | 0.75 | Prompt template usage |

### Capabilities Discovered

- **Planner** — Graph execution planning via `add_edge` calls
- **Memory** — Checkpointer and memory objects
- **Shell** — Tool definitions with `subprocess`, `os.system`, `popen`
- **Filesystem** — Tool definitions with `open()`, `os.remove`, `os.write`
- **External APIs** — Model references (`ChatOpenAI`, `AzureChatOpenAI`, `Bedrock`)

### Detection Example

```python
from langgraph import Graph

def node_a(state):
    return state

g = Graph()
g.add_node(node_a)
```

SafeAI detects:
- Framework: `langgraph`
- Node: `node_a`
- Graph construction with `add_node`
- Edge relationships from `add_edge`

---

## CrewAI

### Detection Approach

**Priority:** AST → regex fallback

- **Imports:** Detects `crewai` in Python import statements
- **AST:** Parses `Agent()`, `Task()`, tool references
- **Dependencies:** `crewai` in manifest files
- **Regex fallback:** `Agent(`, `Task(`, `tools=`, `tool=` patterns

### Artifacts Discovered

| Artifact | Detection | Confidence | Description |
|----------|-----------|-----------|-------------|
| Agents | AST `Agent()` calls | 0.86 | CrewAI agent definitions |
| Tasks | AST `Task()` calls | 0.86 | Task definitions with assignments |
| Tools | AST tool references | 0.80 | Tool bindings in agents/tasks |
| Models | AST model references | 0.80 | LLM provider references |
| Memory | AST "memory" keyword | 0.85 | Memory configuration |

### Capabilities Discovered

- **Multi-Agent** — Multiple `Agent()` instances
- **Planner** — Task-based workflow orchestration
- **Memory** — Memory objects in agent definitions
- **Shell** — Tool definitions with shell operations
- **External APIs** — Model references

### Detection Example

```python
from crewai import Agent, Task

agent = Agent(role="developer")
task = Task(description="analyze code", agent=agent)
```

SafeAI detects:
- Framework: `crewai`
- Agent: `agent`
- Task: `task` with description and agent assignment

---

## AutoGen

### Detection Approach

**Priority:** AST → regex fallback (`safeai/frameworks/autogen/parser.py`)

- **Python only:** non-`.py` paths are ignored
- **Imports:** import paths that start with `autogen` (for example `from autogen import AssistantAgent`)
- **Class usage:** `AssistantAgent(` / `UserProxyAgent(` instantiations (word-boundary; not a bare `"autogen"` substring)
- **Registration:** `register_for_llm` or `register_function` in file content
- **AST:** parses `AssistantAgent()`, `UserProxyAgent()`, `register_for_llm()`, and `register_function()` calls
- **Regex fallback:** `AssistantAgent(`, `UserProxyAgent(`, `register_for_llm(`, `register_function(` when AST found no agents or tools
- **Parse gate:** `parse()` returns no framework result unless at least one agent or registered tool is found — an import-only file is not advertised as an AutoGen project

Detection evidence recorded on a successful parse: `imports:autogen`, `ast:calls`. Parser confidence is 0.85 (`discovery_method: ast+regex_fallback`).

### Artifacts Discovered

| Artifact | Detection | Confidence | Description |
|----------|-----------|-----------|-------------|
| Agents | AST `AssistantAgent()`, `UserProxyAgent()` | 0.85 | AutoGen agent definitions |
| Tools | AST `register_for_llm()`, `register_function()`; functions passed as `AssistantAgent(tools=[...])`, `FunctionTool(f)`, `register_function(f, ...)` or decorated with `register_for_llm` / `register_for_execution` | 0.80 | Tool registrations |
| Models | AST calls whose names include `openai`, `azure`, `bedrock`, or `anthropic` | 0.80 | LLM provider references |

### Capabilities Discovered

- **External APIs** — model constructor calls matching OpenAI, Azure, Bedrock, or Anthropic (`confidence=0.8`)
- **Shell** — resolved call names containing `subprocess`, `os.system`, or `popen` (`confidence=0.9`)
- **Filesystem** — calls to `open` itself (`open`, `io.open`) or names containing `pathlib`, `os.remove`, or `os.write` (`confidence=0.85`). `OpenAI…` and `urlopen` are not file access.

**Tool attribution.** A capability is attributed to a tool when the call
that confers it is in the body of a function the same file registers as
a tool (any of the forms under *Tools*). Calls at module level, and
calls in a helper that a tool calls, stay unattributed: SafeAI does not
follow calls between functions.

The adapter does not emit first-class Multi-Agent or Delegation capabilities. `GroupChat` / `GroupChatManager`, `code_execution_config`, and AutoGen 0.4+ `autogen-agentchat` APIs are not extracted as dedicated artifacts.

### Detection Example

```python
from autogen import AssistantAgent, UserProxyAgent

assistant = AssistantAgent("assistant", llm_config=llm_config)
user_proxy = UserProxyAgent("user_proxy", code_execution_config=False)
```

SafeAI detects:
- Framework: `autogen`
- Agents: `AssistantAgent`, `UserProxyAgent` (names taken from the call)

### Limitations

- Detection is Python-only and does not read `requirements.txt` / `pyproject.toml` for an `autogen` dependency
- A file that only imports AutoGen (no agent instantiation or tool registration) is not reported as an AutoGen project
- `ConversableAgent`, `GroupChat`, `GroupChatManager`, Swarm, and `autogen_agentchat` AgentChat 0.4+ types have no dedicated matchers (a class still named `AssistantAgent` / `UserProxyAgent` will match)
- `code_execution_config` is not interpreted; code-execution risk is only inferred if shell or filesystem call names appear
- Shell and filesystem capabilities are heuristic name matches on resolved call identifiers, not AutoGen tool-schema analysis
- `register_for_llm` / `register_function` detection uses a content substring and can fire on comments or unrelated identifiers
- Framework-specific risk analysis is minimal (Experimental maturity), consistent with the README Supported Frameworks table

---

## LangChain

### Detection Approach

**Priority:** AST → metadata → regex fallback

- **Imports:** Detects `langchain` in Python import statements
- **Dependencies:** `langchain` in manifest files
- **AST:** Parses `AgentExecutor`, `Chain`, `Tool`, `PromptTemplate`, model constructors
- **Regex fallback:** `Tool(`, `PromptTemplate`, `ChatPromptTemplate`

### Artifacts Discovered

| Artifact | Detection | Confidence | Description |
|----------|-----------|-----------|-------------|
| Agents | AST `AgentExecutor`, agent patterns | 0.88 | Agent executor definitions |
| Workflows | AST Chain, Runnable patterns | 0.75 | Execution chain definitions |
| Tools | AST `Tool()`, tool patterns | 0.80 | Tool registrations |
| Prompts | AST `PromptTemplate` | 0.75 | Prompt template definitions |
| Memory | AST "memory" keyword | 0.90 | Conversation memory objects |
| Models | AST model constructor calls | 0.85 | LLM provider references |
| External Services | AST integration patterns | 0.75 | GitHub, Slack, email, DB integrations |

### Capabilities Discovered

- **Planner** — Chain-based workflow orchestration
- **Delegation** — Agent executor delegation patterns
- **Memory** — Conversation memory objects
- **External APIs** — Model integrations, HTTP tools
- **Shell** — Tool definitions with shell operations
- **Filesystem** — Tool definitions with file operations

### Detection Example

```python
from langchain.agents import AgentExecutor
from langchain.chains import LLMChain

agent = AgentExecutor(agent="zero-shot-react-description", tools=[...])
```

SafeAI detects:
- Framework: `langchain`
- Agent: `AgentExecutor` with tool references
- Chain relationships from constructor arguments

---

## Semantic Kernel

### Detection Approach

**Priority:** AST → metadata → regex fallback

- **Imports:** Detects `semantic_kernel` in Python imports
- **Dependencies:** `semantic-kernel` in manifest files
- **AST:** Parses `Kernel.invoke`, plugins, functions, memory, skill references
- **Regex fallback:** `skill` keyword

### Artifacts Discovered

| Artifact | Detection | Confidence | Description |
|----------|-----------|-----------|-------------|
| Workflows | AST `kernel.invoke` patterns | 0.86 | Kernel invocation chains |
| Tools | AST function, plugin patterns | 0.80 | Plugin and function references |
| Prompts | AST "prompt" in calls | 0.75 | Prompt references |
| Memory | AST "memory" keyword | 0.90 | Semantic memory references |
| Skills | AST "skill" patterns | 0.80 | Skill definitions |
| Models | AST model constructor calls | 0.85 | OpenAI, Azure, Anthropic references |

### Capabilities Discovered

- **Planner** — Kernel-based orchestration
- **Memory** — Semantic memory connections
- **External APIs** — Model provider integrations

### Detection Example

```python
from semantic_kernel import Kernel

kernel = Kernel()
await kernel.invoke(function, plugin)
```

SafeAI detects:
- Framework: `semantic_kernel`
- Workflow: `kernel.invoke` with function and plugin arguments
- Skills, plugins, and memory from call arguments

---

## OpenAI Agents SDK

### Detection Approach

**Priority:** AST → metadata → regex fallback

- **Imports:** Detects `agents`, `openai` imports with agent patterns
- **Dependencies:** `openai-agents` in manifest files
- **AST:** Parses `Agent()`, tool calls, handoffs, MCP references
- **Regex fallback:** `Agent(` pattern

### Artifacts Discovered

| Artifact | Detection | Confidence | Description |
|----------|-----------|-----------|-------------|
| Agents | AST `Agent()` calls | 0.87 | Agent definitions |
| Tools | AST tool pattern | 0.80 | Tool registrations |
| Workflows | AST handoff patterns | 0.80 | Agent handoff workflows |
| Memory | AST "memory" keyword | 0.85 | Memory configuration |
| MCP Assets | AST "mcp" keyword | 0.90 | MCP tool references |
| Models | AST model references | 0.85 | GPT, responses, chat.completions |

### Capabilities Discovered

- **Multi-Agent** — Multiple agent instances
- **Delegation** — Handoff-based agent delegation
- **MCP** — MCP tool integration
- **Memory** — Agent memory
- **External APIs** — Model calls

### Detection Example

```python
from agents import Agent, Runner

agent = Agent(name="assistant", instructions="Be helpful")
result = Runner.run(agent, "Hello")
```

SafeAI detects:
- Framework: `openai_agents`
- Agent: with name and instructions
- Runner workflow

---

## Microsoft Agent Framework

### Detection Approach

**Priority:** AST → configuration → dependencies → regex fallback

- **Imports:** Detects `azure.ai.agents`, `microsoft.agent`
- **Dependencies:** `azure-ai-agents`, `azure-ai-projects`
- **AST:** Parses `AgentClient`, tool, run, workflow patterns
- **Configuration:** YAML/JSON files with agent references
- **Regex fallback:** `AgentClient`, `agent` keywords

### Artifacts Discovered

| Artifact | Detection | Confidence | Description |
|----------|-----------|-----------|-------------|
| Agents | AST agent patterns | 0.85 | Agent client definitions |
| Workflows | AST run, workflow patterns | 0.80 | Agent execution workflows |
| Tools | AST tool, function patterns | 0.80 | Tool/function definitions |
| Prompts | AST "prompt" keyword | 0.75 | Prompt references |
| Memory | AST "memory" keyword | 0.80 | Memory configuration |
| Models | AST model references | 0.85 | Azure OpenAI, GPT references |

### Capabilities Discovered

- **Cloud** — Azure cloud model integration
- **Memory** — Agent memory objects
- **Multi-Agent** — Multiple agent definitions

### Detection Example

```python
from azure.ai.agents import AgentClient

client = AgentClient(endpoint="https://...", credential=credential)
```

SafeAI detects:
- Framework: `microsoft_agent_framework`
- Agent: `AgentClient` with endpoint and credential
- Workflow: run operations

---

## Claude Code

### Detection Approach

**Priority:** repository-committed configuration only — structural analysis, not just presence detection

As of this release, the Claude Code adapter reads and structurally analyzes:

- **`.claude/settings.json` and `.claude/settings.local.json`** — read in
  that precedence order, tolerant of JSON comments and trailing commas. A
  file that still fails to parse produces a low-severity
  `CC_SETTINGS_UNPARSEABLE` finding rather than a crash or a silent skip.
- **`.mcp.json`** — MCP server configuration. A configuration that declares
  tools without naming its server is recorded under the unattributed tool
  identity rather than given an invented server name.
- **`.claude/commands/*.md`** — custom slash commands, treated as an
  untrusted-instruction surface. SafeAI looks for inline shell
  (`` !`command` ``, bang-line shell), `$ARGUMENTS`/`$1`–`$9` interpolation
  into a shell context, `@file` references, frontmatter `allowed-tools`, and
  unpinned remote-fetch patterns (`curl`, `wget`, `npx -y`, unpinned
  `pip install`, pipe-to-shell).
- **`.claude/agents/*.md`** — subagent definitions, checked for tool grants
  that exceed the parent's declared tool scope.
- **Lifecycle hooks** — shell commands bound to lifecycle events, flagged
  at a higher severity when they fetch unpinned remote content.
- **`CLAUDE.md`** — project instructions, as in earlier releases.

Permission entries are parsed in `Tool(argument)` form (for example
`Bash(npm run test:*)`, `Write(*)`, or a bare `Bash`) and MCP grants in
`mcp__server__tool` form. A bare tool name or a wildcard argument (`*`,
`**`, `*:*`, `//*`) counts as unconstrained and is flagged by
`CC_WILDCARD_PERMISSION`. See `RULES_REFERENCE.md` for the full list of ten
new `CC_*` rules this analysis produces.

### Scope boundary

**Only configuration committed inside the scanned repository is read.**
The adapter never opens `~/.claude`, `~/.claude.json`, or any other
user-level or machine-global Claude Code configuration — it reads only
from the scan's own file cache, which is built from the target directory.
This is a deliberate boundary for this release: user-level and
machine-global configuration can affect a real Claude Code session but is
not something a repository-scoped static scan can see or should claim to
see. A repository that relies on permissions or hooks defined only at the
user level will not have that configuration reflected in SafeAI's
findings; review it separately.

### Capabilities Discovered

- **Shell** — `Bash`, hook shell commands, slash-command shell invocations
- **Filesystem** — `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Read`, `Glob`, `Grep`, `Ls`
- **External APIs** — `WebFetch`, `WebSearch`
- **Delegation** — `Task`, `Agent`, subagent definitions
- **Memory** — `TodoWrite`
- **MCP** — servers and tools declared in `.mcp.json`

### Detection Example

```json
{
  "permissions": {
    "allow": ["Bash(npm run test:*)", "Write(*)"]
  }
}
```

SafeAI detects:
- `Bash` constrained to a `npm run test:*` argument pattern (not flagged)
- `Write(*)` as an unconstrained wildcard permission (`CC_WILDCARD_PERMISSION`)

---

## Azure AI Foundry

### Detection Approach

**Priority:** Configuration (YAML/JSON) → dependencies

- **File extension:** `.yaml`, `.yml` files
- **Content:** `azure` keyword, in a YAML mapping with a top-level
  `tools`, `actions` or `instructions` key (the shape of an agent
  definition). CI pipelines, GitHub workflows and lockfiles that only
  mention Azure are not reported.
- **Dependencies:** `azure-ai-projects`, `azure-ai-agents` in manifest files

### Artifacts Discovered

| Artifact | Detection | Confidence | Description |
|----------|-----------|-----------|-------------|
| Tools | YAML `tools` or `actions` keys | 0.84 | Tool definitions in config |
| Models | YAML `model`, `models`, `llm`, `deployment` keys | 0.84 | Model references |
| Workflows | YAML `name` key | 0.84 | Agent workflow name |

### Capabilities Discovered

- **Cloud** — Azure cloud service reference

### Detection Example

```yaml
azure: true
name: test-agent
tools: []
```

SafeAI detects:
- Framework: `azure_foundry`
- Tools from `tools` array
- Models from `model`/`llm` keys

---

## Claude Code

### Detection Approach

- **Files:** `CLAUDE.md`, `.claude/settings.json`, `.claude/settings.local.json`, `.claude/commands/*.md`, `.claude/agents/*`, `.mcp.json`
- **Scope:** Repository-local only (no `~/.claude` user directory reads)
- **Parser:** Lenient JSON with comments and trailing commas, YAML frontmatter on Markdown commands

### Artifacts Discovered

| Artifact | Detection | Confidence | Description |
|----------|-----------|-----------|-------------|
| Settings & Permissions | `.claude/settings.json` | High | `permissions.allow`, `deny`, `ask`, wildcard rules, bypass flags |
| Local Overrides | `.claude/settings.local.json` | High | Developer-local overrides and tool grants |
| Slash Commands | `.claude/commands/*.md` | High | Custom slash commands, frontmatter `allowed-tools`, shell invocations |
| Subagents | `.claude/agents/*` | High | Specialized subagent definitions and delegated capabilities |
| MCP Servers | `.mcp.json`, `settings.json` | High | Model Context Protocol servers and tool constraints |
| Lifecycle Hooks | `settings.json:hooks` | High | PreToolUse/PostToolUse shell command executions |

---

## Test Fixtures (v1.8.0+)

Representative test fixtures and validation tests verify that SafeAI correctly
detects each framework's artifacts and capabilities. These were contributed by
the community and cover the most common patterns for each framework.

| Framework | Test File | Fixture | What It Validates |
|-----------|-----------|---------|-------------------|
| LangGraph | `tests/test_langgraph_framework.py` | `tests/fixtures/langgraph/representative/graph.py` | `StateGraph`, `add_edge`, `add_node`, tool binding, model detection |
| LlamaIndex | `tests/test_llamaindex_framework.py` | `tests/fixtures/llamaindex/representative/agent.py` | Agent, tool, index, and model detection |
| CrewAI | `tests/test_crewai_framework.py` | `tests/fixtures/crewai/representative/crew.py` | `Agent`, `Task`, tool, and model detection |
| Claude Code | `tests/test_claude_code_deep.py` | `tests/fixtures/claude_code/` (`minimal`, `permissive`, `slash_injection`, `subagent_escalation`, `malformed`, `compatibility`) | Deep settings permissions, wildcards, bypass flags, shadowed denies, slash command shell/arg injection, subagent escalation, lifecycle hooks, and lenient JSON parsing |
| Cursor (.cursorrules) | `tests/test_cursorrules_framework.py` | `tests/fixtures/cursorrules/representative/.cursorrules` | JSON/YAML/free-text config parsing, tool/model extraction, capability scanning, unrestricted grants, MCP references |
| OpenClaw config | `tests/test_config_adapters.py` | `tests/fixtures/openclaw/representative/.openclaw/config.json` | Path detection, JSON/YAML/free-text parsing, tools, models, capabilities, and MCP servers |
| GitHub Copilot instructions | `tests/test_config_adapters.py` | `tests/fixtures/copilot/representative/.github/copilot-instructions.md` | Markdown/frontmatter/YAML parsing, tool grants, capability scanning, and MCP references |

Thanks to @adnqcr7-code for framework detection tests (PRs #59, #61, #62, #63),
to @i-safonoff for the .cursorrules adapter (PR #113),
and to @YaoSong808 for the OpenClaw and GitHub Copilot config-file adapters (PR #159),
to @Teachmeplaycode for benchmark corpus expansion (PR #174),
and to @nikitajos7 for policy profile display in reports (PR #175).

---

## Limitations

### Current Constraints

1. **Detection depth is partial**
   - Framework adapters use heuristic object detection rather than full framework-native object model parsing
   - Complex dynamic agent construction may not be fully captured
   - Capability detection relies on naming conventions and may miss unconventional patterns

2. **Cross-file analysis is limited**
   - Import graph resolves symbol origins but does not perform full interprocedural analysis
   - Re-exported symbols through `__init__.py` files are tracked but not deeply resolved

3. **Capability inference needs improvement**
   - Boolean capabilities (e.g., `memory=True`) may not be detected in all frameworks
   - Enum-based tool categories may be missed
   - Some capabilities are only detected through MCP configuration, not framework adapters

4. **False positive risk**
   - Regex fallback patterns may trigger on unrelated variables or documentation strings
   - Capability keywords in comments or documentation may generate findings

5. **JavaScript/TypeScript support**
   - Limited to `package.json` dependency detection
   - No AST-level analysis for non-Python languages

6. **No version-aware framework detection**
   - Framework version is not extracted or compared against known vulnerability databases
   - All detection is version-agnostic
