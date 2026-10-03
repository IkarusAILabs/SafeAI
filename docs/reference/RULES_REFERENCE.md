# SafeAI — Rules Reference

This document describes every rule implemented in SafeAI's rule engine.

Rules are defined in YAML format in `rules/base_rules.yaml`. Custom rules can be added via the `--rules` CLI flag.

---

## Rule Format

```yaml
- id: RULE_ID
  description: Human-readable description
  severity: critical|high|medium|low|info
  owasp_llm: LLM01-LLM06
```

---

## Prompt Injection Rules

### PROMPT_INJECTION

| Field | Value |
|-------|-------|
| **Rule ID** | `PROMPT_INJECTION` |
| **Name** | Prompt Injection |
| **Description** | Untrusted input interpolated into prompt |
| **Severity** | Critical |
| **OWASP LLM** | LLM01 (Prompt Injection) |
| **Risk Category** | Safety |
| **Score Contribution** | 18 |
| **Detection** | Lines containing f-strings or `.format()` combined with user-controlled variable names (`user_input`, `request`, `input`, `response`) |

**Evidence example:**
```python
prompt = f"System: do X {user_input}"
```

**Why it matters:** Untrusted input directly interpolated into prompts allows users to inject instructions, override system prompts, and manipulate agent behavior.

**Recommendation:** Sanitize user input using parameterized prompt templates. Isolate system instructions from user content using message roles.

---

### PROMPT_DELIMITER

| Field | Value |
|-------|-------|
| **Rule ID** | `PROMPT_DELIMITER` |
| **Name** | Missing Delimiter |
| **Description** | Missing delimiter between system and user content |
| **Severity** | High |
| **OWASP LLM** | LLM01 |
| **Risk Category** | Safety |
| **Score Contribution** | 12 |
| **Detection** | Lines containing string concatenation (`+`) with both `system` and uncontrolled variable references |

**Evidence example:**
```python
prompt = "System: You are helpful." + user_input
```

**Why it matters:** Without delimiters, users cannot distinguish between system and user content, enabling instruction override.

**Recommendation:** Use role-separated message formats (e.g., `{"role": "system", "content": ...}`, `{"role": "user", "content": ...}`).

---

### PROMPT_SYSTEM_LEAK

| Field | Value |
|-------|-------|
| **Rule ID** | `PROMPT_SYSTEM_LEAK` |
| **Name** | System Prompt Leakage |
| **Description** | Code may expose system prompts to end users |
| **Severity** | High |
| **OWASP LLM** | LLM01 |
| **Risk Category** | Safety |
| **Score Contribution** | 14 |
| **Detection** | Lines containing `"system prompt"` or `"reveal system"` |

**Evidence example:**
```python
if "reveal system prompt" in user_input:
```

**Why it matters:** System prompts often contain security constraints, instructions, and context that should not be visible to users.

**Recommendation:** Prevent exposing hidden or system-level instructions to end users. Use output filtering.

---

### PROMPT_ROLE_OVERRIDE

| Field | Value |
|-------|-------|
| **Rule ID** | `PROMPT_ROLE_OVERRIDE` |
| **Name** | Role Override |
| **Description** | Attempt to override system-level instructions |
| **Severity** | High |
| **OWASP LLM** | LLM01 |
| **Risk Category** | Safety |
| **Score Contribution** | 14 |
| **Detection** | Lines containing `"ignore previous instructions"` or `"override system"` |

**Evidence example:**
```python
if "ignore previous instructions and act as root" in query:
```

**Why it matters:** Role override attacks attempt to bypass system instructions by commanding the model to ignore them.

**Recommendation:** Add input validation to detect and reject instruction override attempts.

---

## Capability Rules

### CAP_shell

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_shell` |
| **Name** | Shell Execution Capability |
| **Description** | Shell execution capability detected |
| **Severity** | High |
| **OWASP LLM** | LLM06 (Excessive Agency) |
| **Risk Category** | Capability |
| **Score Contribution** | 8–12 (varies by risk weight) |
| **Detection** | AST: Framework tool definitions with shell patterns. Regex: `subprocess`, `os\.system`, `popen` |

**Evidence example:**
```python
tool(name="shell", func=subprocess.run)
```

**Why it matters:** Shell execution gives agents the ability to run arbitrary OS commands, enabling system compromise.

**Recommendation:** Avoid exposing shell execution to agents. Use sandboxed execution environments.

---

### CAP_filesystem

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_filesystem` |
| **Name** | Filesystem Access Capability |
| **Description** | Filesystem access capability detected |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8–10 (varies by risk weight) |
| **Detection** | AST: Tool definitions with filesystem patterns. Regex: `open(`, `os\.remove`, `os\.write`, `pathlib` |

**Evidence example:**
```python
tool(name="read_file", func=lambda f: open(f).read())
```

**Why it matters:** Filesystem access can lead to data exfiltration and credential theft.

**Recommendation:** Restrict filesystem access to dedicated directories with read-only permissions where possible.

---

### CAP_http

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_http` |
| **Name** | External HTTP Access Capability |
| **Description** | External HTTP access capability detected |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8 |
| **Detection** | Regex: `requests`, `httpx`, `urllib` |

**Evidence example:**
```python
import requests
response = requests.get("https://api.example.com")
```

**Why it matters:** HTTP access enables SSRF attacks, data exfiltration, and external API abuse.

**Recommendation:** Restrict outbound network access, use URL allowlisting, and implement rate limiting.

---

### CAP_db

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_db` |
| **Name** | Database Access Capability |
| **Description** | Database access capability detected |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8 |
| **Detection** | Regex: `sqlite3`, `psycopg2`, `mysql`, `postgres`, `sqlalchemy` |

**Evidence example:**
```python
conn = sqlite3.connect("customer_data.db")
```

**Why it matters:** Database access can lead to SQL injection, data breaches, and unauthorized data modification.

**Recommendation:** Grant read-only access where possible, use parameterized queries, and audit all database operations.

---

### CAP_code_exec

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_code_exec` |
| **Name** | Code Execution Capability |
| **Description** | Code execution (`exec`/`eval`) capability detected |
| **Severity** | High |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8 |
| **Detection** | Regex: `exec(`, `eval(` |

**Evidence example:**
```python
result = eval(user_formula)
```

**Why it matters:** Arbitrary code execution gives agents full runtime control.

**Recommendation:** Never execute untrusted code. Use safe evaluation libraries for formula evaluation.

---

### CAP_AUTONOMY

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_AUTONOMY` |
| **Name** | Autonomous Agent Behavior |
| **Description** | Potential autonomous agent loop detected |
| **Severity** | High |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Autonomy |
| **Score Contribution** | 12 |
| **Detection** | `while True` combined with agent-related content; `for _ in range(...)` with agent content |

**Evidence example:**
```python
while True:
    agent.run()
```

**Why it matters:** Unbounded autonomous loops can result in infinite execution, cost escalation, and out-of-control agent behavior.

**Recommendation:** Impose iteration limits, implement timeout and circuit breaker patterns, and require human approval for long-running loops.

---

### CAP_docker

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_docker` |
| **Name** | Docker Container Management Capability |
| **Description** | Docker container management capability detected |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8 |
| **Detection** | Regex: `import docker`, `from docker`, `DockerClient`, `docker\.run`, `containers\.run` |

**Evidence example:**
```python
client = docker.from_env()
client.containers.run("alpine", "echo hello")
```

**Why it matters:** Docker access lets an agent create and control containers, which can be used to escape sandboxing (e.g. privileged containers, mounted host paths) or run arbitrary images.

**Recommendation:** Avoid privileged containers, restrict Docker socket access, and run agent-triggered containers with least-privilege security options.

---

### CAP_kubernetes

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_kubernetes` |
| **Name** | Kubernetes Orchestration Capability |
| **Description** | Kubernetes orchestration capability detected |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8 |
| **Detection** | Regex: `import kubernetes`, `from kubernetes`, `kubectl`, `kube_config`, `KubeConfig`, `k8s` |

**Evidence example:**
```python
from kubernetes import client, config
config.load_kube_config()
```

**Why it matters:** Cluster API access can span every workload in the cluster, not just the agent's own namespace, if the credentials it uses are broader than necessary.

**Recommendation:** Scope the service account's RBAC role narrowly to the namespaces and verbs the agent actually needs; avoid cluster-admin bindings.

---

### CAP_redis

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_redis` |
| **Name** | Redis Data Store Capability |
| **Description** | Redis data store capability detected |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8 |
| **Detection** | Regex: `import redis`, `from redis`, `Redis\(`, `redis\.StrictRedis`, `redis\.Redis` |

**Evidence example:**
```python
r = redis.Redis(host="prod-cache", port=6379)
```

**Why it matters:** Read/write access to a shared cache or queue can expose data belonging to other consumers or allow cache poisoning that affects downstream readers.

**Recommendation:** Use Redis ACLs to scope the agent's user to specific key patterns and commands rather than a shared full-access credential.

---

### CAP_s3

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_s3` |
| **Name** | S3 / Cloud Storage Capability |
| **Description** | S3 / cloud storage capability detected |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8 |
| **Detection** | Regex: `import boto3`, `from boto3`, `boto3\.client(...s3...)`, `boto3\.resource(...s3...)`, `S3Client`, `s3\.put`, `s3\.get` |

**Evidence example:**
```python
s3.put_object(Bucket="reports", Key=key, Body=agent_output)
```

**Why it matters:** Bucket read/write access can leak stored objects or let the agent overwrite existing data if the IAM policy backing the credential is broader than the task requires.

**Recommendation:** Apply least-privilege bucket policies scoped to specific prefixes, and block public ACLs on any bucket an agent can write to.

---

### CAP_slack

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_slack` |
| **Name** | Slack Integration Capability |
| **Description** | Slack integration capability detected |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8 |
| **Detection** | Regex: `import slack`, `from slack`, `SlackClient`, `slack_sdk`, `slack\.WebClient`, `slack\.SocketModeClient` |

**Evidence example:**
```python
client = slack_sdk.WebClient(token=os.environ["SLACK_BOT_TOKEN"])
client.chat_postMessage(channel="#general", text=agent_reply)
```

**Why it matters:** A bot token scoped beyond its task can read or post to channels the agent has no legitimate reason to touch, including private-comms exfiltration.

**Recommendation:** Scope the bot token to the minimum OAuth scopes and channels the agent actually needs.

---

### CAP_ms_teams

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_ms_teams` |
| **Name** | Microsoft Teams Integration Capability |
| **Description** | Microsoft Teams integration capability detected |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8 |
| **Detection** | Regex: `import teams`, `from teams`, `TeamsClient`, `teams_sdk`, `pymsteams`, `pymsteams\.connectorcard`, `pymsteams\.cardsection` |

**Evidence example:**
```python
from pymsteams import connectorcard
card = connectorcard.ConnectorCard("https://outlook.office.com/webhook/...")
card.text("Agent update: access granted")
```

**Why it matters:** A Teams webhook or bot client with message-posting scope can send announcements to channels or users the agent should not address, enabling message spam or unauthorized status updates.

**Recommendation:** Use least-privilege webhooks or bot credentials scoped to the exact Teams channel and message types required, and avoid broad posting permissions for general-purpose agents.

---

### CAP_jira

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_jira` |
| **Name** | Jira Integration Capability |
| **Description** | Jira integration capability detected |
| **Severity** | Low |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8 |
| **Detection** | Regex: `import jira`, `from jira`, `JIRA\(`, `jira\.Client`, `jira\.JIRA` |

**Evidence example:**
```python
jira = JIRA(server="https://company.atlassian.net", basic_auth=(user, token))
```

**Why it matters:** Issue create/edit access can be used to spam, alter workflow state, or expose project data the agent's task did not require touching.

**Recommendation:** Use a scoped service account limited to the specific project(s) and permission scheme the agent needs.

---

### CAP_gcp

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_gcp` |
| **Name** | Google Cloud Platform Capability |
| **Description** | Google Cloud Platform capability detected |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8 |
| **Detection** | Regex: `import google\.cloud`, `from google\.cloud`, `google\.cloud\.\w+`, `GCP`, `gcsfs`, `BigQuery` |

**Evidence example:**
```python
from google.cloud import storage
client = storage.Client()
```

**Why it matters:** `google.cloud` covers a broad API surface (storage, BigQuery, Pub/Sub, and more); an over-scoped service account credential grants the agent all of it, not just the API it calls.

**Recommendation:** Use least-privilege IAM roles scoped to the specific GCP API and resource the agent needs, not project-level Editor/Owner roles.

---

### CAP_browser_playwright

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_browser_playwright` |
| **Name** | Browser Automation Capability (Playwright) |
| **Description** | Browser automation capability detected (Playwright) |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8 |
| **Detection** | Regex: `import playwright`, `from playwright`, `Playwright` |

**Evidence example:**
```python
from playwright.sync_api import sync_playwright
page.goto(agent_supplied_url)
```

**Why it matters:** A driven browser can navigate anywhere, submit forms, and enter credentials — a wide, hard-to-sandbox capability, especially when the destination URL is agent- or user-supplied.

**Recommendation:** Restrict navigation to an allowlist of domains, run in an isolated/ephemeral browser context, and avoid persisting session credentials in the automation profile.

---

### CAP_browser_selenium

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_browser_selenium` |
| **Name** | Browser Automation Capability (Selenium) |
| **Description** | Browser automation capability detected (Selenium) |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8 |
| **Detection** | Regex: `import selenium`, `from selenium`, `webdriver`, `WebDriver` |

**Evidence example:**
```python
driver = webdriver.Chrome()
driver.get(agent_supplied_url)
```

**Why it matters:** Same risk profile as `CAP_browser_playwright` — full browser control, including arbitrary navigation and form submission.

**Recommendation:** Restrict navigation to an allowlist of domains, run in an isolated/ephemeral browser context, and avoid persisting session credentials in the automation profile.

---

### CAP_browser_use

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_browser_use` |
| **Name** | Browser Automation Capability (browser-use) |
| **Description** | Browser automation capability detected (browser-use agent framework) |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 8 |
| **Detection** | Regex: `from browser_use`, `import browser_use`, `browser_use\.Agent` |

**Evidence example:**
```python
from browser_use import Agent
agent = Agent(task=user_goal, llm=llm)
```

**Why it matters:** `browser_use` lets the *model itself* decide where to navigate and what to click, compounding the standard browser-automation risk with model-directed navigation.

**Recommendation:** Constrain the agent's task scope and reachable domains; review its action log rather than trusting the task description alone.

---

> **`CAP_browser`** is declared in `rules/base_rules.yaml` (severity medium, OWASP LLM06) and used for scorecard/compliance-mapping bucketing, but has no dedicated regex detector of its own — actual browser-automation detection is split across `CAP_browser_playwright`, `CAP_browser_selenium`, and `CAP_browser_use` above.

---

## Data-Flow Rules

Generated by [`DataFlowAnalyzer`](safeai/analyzers/dataflow/analyzer.py). A
heuristic, line-level taint tracker: it looks for an untrusted-input pattern
(`user_input`, `request.form`, `response.text`, ...) on one line and the same
variable name reappearing on a later line matching a sensitive sink pattern,
within the same file. It is not a full interprocedural data-flow solver and
can miss indirect propagation or produce false positives on unrelated
variables that share a name.

### DATAFLOW_prompt

| Field | Value |
|-------|-------|
| **Rule ID** | `DATAFLOW_prompt` |
| **Description** | Untrusted input flows into prompt construction |
| **Severity** | High |
| **OWASP LLM** | LLM01 |
| **Risk Category** | Safety |
| **Score Contribution** | 15 |
| **Detection** | An untrusted-input source variable reappears on a later line matching `prompt`, `system_prompt`, `user_prompt`, `chat_history`, or `messages.append` |

**Why it matters:** Untrusted data reaching prompt construction is the concrete precondition for a prompt-injection attack.

**Recommendation:** Sanitize or template-isolate the variable before it reaches prompt-building code.

---

### DATAFLOW_tool_call

| Field | Value |
|-------|-------|
| **Rule ID** | `DATAFLOW_tool_call` |
| **Description** | Untrusted input flows into tool invocation |
| **Severity** | High |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Safety |
| **Score Contribution** | 15 |
| **Detection** | An untrusted-input source variable reappears on a later line matching `tool_call`, `invoke_tool`, `call_tool`, or `execute_tool` |

**Why it matters:** Untrusted input controlling which tool is invoked, or with what arguments, lets a user or upstream response steer agent actions.

**Recommendation:** Validate and constrain tool arguments derived from untrusted sources against an allowlist.

---

### DATAFLOW_shell

| Field | Value |
|-------|-------|
| **Rule ID** | `DATAFLOW_shell` |
| **Description** | Untrusted input flows into shell execution |
| **Severity** | Critical |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Safety |
| **Score Contribution** | 15 |
| **Detection** | An untrusted-input source variable reappears on a later line matching `subprocess`, `os.system`, `popen`, `exec(`, or `eval(` |

**Why it matters:** This is the concrete precondition for command injection — untrusted data reaching a shell sink.

**Recommendation:** Never build shell commands from untrusted input; use parameterized subprocess argument lists instead.

---

### DATAFLOW_file_write

| Field | Value |
|-------|-------|
| **Rule ID** | `DATAFLOW_file_write` |
| **Description** | Untrusted input flows into file write operation |
| **Severity** | High |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Safety |
| **Score Contribution** | 15 |
| **Detection** | An untrusted-input source variable reappears on a later line matching `open(..., "w"\|"a"\|"x"...)` |

**Why it matters:** Untrusted data controlling a file path or write contents enables path traversal or arbitrary file overwrite.

**Recommendation:** Validate file paths against an allowlist directory and never derive a path directly from untrusted input.

---

### DATAFLOW_http_request

| Field | Value |
|-------|-------|
| **Rule ID** | `DATAFLOW_http_request` |
| **Description** | Untrusted input flows into HTTP request |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Safety |
| **Score Contribution** | 15 |
| **Detection** | An untrusted-input source variable reappears on a later line matching `requests.(get\|post\|put\|delete)` or `httpx.` |

**Why it matters:** Untrusted data controlling an outbound request URL or body is the precondition for server-side request forgery (SSRF).

**Recommendation:** Validate outbound URLs against an allowlist of hosts before making the request.

---

### DATAFLOW_database

| Field | Value |
|-------|-------|
| **Rule ID** | `DATAFLOW_database` |
| **Description** | Untrusted input flows into database query |
| **Severity** | High |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Safety |
| **Score Contribution** | 15 |
| **Detection** | An untrusted-input source variable reappears on a later line matching `execute`, `cursor.execute`, or `query` |

**Why it matters:** Untrusted data reaching a query call without parameterization is the classic precondition for SQL injection.

**Recommendation:** Use parameterized queries; never format untrusted input directly into a query string.

---

> **Note:** the analyzer builds each rule ID as `DATAFLOW_<sink_type>` where
> `sink_type` is one of the lowercase keys above (`prompt`, `tool_call`,
> `shell`, `file_write`, `http_request`, `database`) — matching the casing
> used in `rules/base_rules.yaml`.

---

## Governance Rules

Generated by [`GovernanceAnalyzer`](safeai/analyzers/governance/analyzer.py).
For each declared agent tool, the analyzer checks whether the tool's own
kwargs/config, or the source code within ±10 lines of its definition,
mentions each of eight operational controls. A control that is neither
configured nor mentioned nearby produces a `GOV_*_MISSING` finding. This is
a source-level presence check, not runtime verification that the control is
actually enforced.

| Rule ID | Description | Severity | OWASP LLM |
|---------|-------------|----------|-----------|
| `GOV_TIMEOUT_MISSING` | Missing timeout configuration on agent tool | Medium | LLM06 |
| `GOV_RETRY_MISSING` | Missing retry/backoff configuration on agent tool | Medium | LLM06 |
| `GOV_APPROVAL_MISSING` | Missing human-in-the-loop approval workflow on agent tool | Medium | LLM06 |
| `GOV_AUDIT_MISSING` | Missing audit logging/tracing configuration on agent tool | Medium | LLM06 |
| `GOV_RATE_LIMIT_MISSING` | Missing rate limiting on external-facing agent tool | Medium | LLM06 |
| `GOV_CIRCUIT_BREAKER_MISSING` | Missing circuit breaker pattern on agent tool | Medium | LLM06 |
| `GOV_BACKPRESSURE_MISSING` | Missing backpressure or concurrency limit on agent tool | Low | LLM06 |
| `GOV_HEALTH_CHECK_MISSING` | Missing health check or readiness probe on agent tool | Medium | LLM06 |

**Score Contribution:** 8 (default; not overridden per-control in `base_rules.yaml`).

**Why it matters:** These are the operational controls a production agent deployment is expected to carry — without them, a slow or failing tool call can hang, retry storm, or run unchecked with no one able to intervene or trace what happened.

**Recommendation:** Add the specific missing control to the tool's configuration, or declare it in source within the tool's definition region so the analyzer picks it up.

---

## Model Configuration Rules

Generated by [`ModelConfigAnalyzer`](safeai/analyzers/model_config/analyzer.py),
which inspects model constructor kwargs and config-file dicts for unsafe
generation settings and missing/disabled safety controls.

### MODEL_UNSAFE_TEMPERATURE

| Field | Value |
|-------|-------|
| **Rule ID** | `MODEL_UNSAFE_TEMPERATURE` |
| **Description** | Model temperature set to a risky value (>1.0) |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Safety |
| **Score Contribution** | 7 |
| **Detection** | `temperature` kwarg or config key > 1.0 |

**Evidence example:**
```python
llm = ChatOpenAI(temperature=1.4)
```

**Why it matters:** High temperature increases output unpredictability and hallucination risk, which compounds with any downstream automated action the model's output drives.

**Recommendation:** Use a conservative temperature (typically ≤ 1.0) for agents that take automated action on their own output.

---

### MODEL_MISSING_CONTENT_FILTER

| Field | Value |
|-------|-------|
| **Rule ID** | `MODEL_MISSING_CONTENT_FILTER` |
| **Description** | Model configuration lacks content filters or safety settings |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Safety |
| **Score Contribution** | 6 |
| **Detection** | Provider is `google`, `bedrock`, or `azure` (providers with a known, observable safety-control key) and none of that provider's required safety keys (`safety_settings`, `guardrail_config`, `content_filter`/`content_policy`) are present |

**Why it matters:** Absence of content filtering increases exposure to harmful model outputs reaching users or downstream tools unfiltered.

**Recommendation:** Enable the provider's content-filter/safety-settings mechanism explicitly rather than relying on undocumented defaults.

---

### MODEL_DISABLED_SAFETY

| Field | Value |
|-------|-------|
| **Rule ID** | `MODEL_DISABLED_SAFETY` |
| **Description** | Model safety settings explicitly disabled |
| **Severity** | High |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Safety |
| **Score Contribution** | 12 |
| **Detection** | A safety-related key (`safety_settings`, `content_filter`, `moderation`, `guardrails`, `safety`, `content_policy`, `filter`, `blocked_categories`, `safe_search`, `grounding`, `recitation_check`) is present with a value that means disabled (`"none"`, `"disabled"`, `"off"`, `False`, `0`, `"block_none"`, `"no_filter"`, an empty list, or `{"enabled": false}`) |

**Evidence example:**
```python
llm = ChatVertexAI(model="gemini-pro", safety_settings="BLOCK_NONE")
```

**Why it matters:** An explicitly disabled safety setting is a deliberate opt-out of the provider's output protections, not an oversight.

**Recommendation:** Remove the disabling setting unless there is a documented, reviewed reason for it; prefer the provider's default safety configuration.

---

## Prompt File Rules

Generated by [`PromptFileAnalyzer`](safeai/analyzers/prompt_file/analyzer.py),
which scans standalone `.prompt` files and inline prompt template strings
(YAML/JSON config values) for injection-prone patterns, system-prompt
exposure language, and jailbreak/role-override phrasing.

### PROMPT_FILE_INJECTION

| Field | Value |
|-------|-------|
| **Rule ID** | `PROMPT_FILE_INJECTION` |
| **Description** | Prompt file contains injection-prone pattern |
| **Severity** | Critical |
| **OWASP LLM** | LLM01 |
| **Risk Category** | Safety |
| **Score Contribution** | 15 |
| **Detection** | The file contains both a template-interpolation pattern (`{{ ... }}`, `{name}`, `${name}`, `%(name)s`) and an untrusted-looking placeholder name (`user_input`, `input`, `query`, `request`, `prompt`, `text`, `message`, `data`, `context`) |

**Evidence example:**
```
System: follow these instructions exactly. User says: {{user_input}}
```

**Why it matters:** A template placeholder fed by untrusted input is the injection surface itself, independent of how the template is later rendered.

**Recommendation:** Isolate untrusted content behind a role boundary (e.g. a separate `user` message) rather than interpolating it directly into the prompt template.

---

### PROMPT_FILE_SYSTEM_LEAK

| Field | Value |
|-------|-------|
| **Rule ID** | `PROMPT_FILE_SYSTEM_LEAK` |
| **Description** | Prompt file exposes system prompt content |
| **Severity** | High |
| **OWASP LLM** | LLM01 |
| **Risk Category** | Safety |
| **Score Contribution** | 12 |
| **Detection** | Regex matching `system prompt`, `system message`, `reveal...prompt`, `show...prompt`, `print...prompt`, `output...prompt`, `what...your...instructions`, or `tell...your...instructions` |

**Why it matters:** Language referencing exposure of the system prompt is a marker that the prompt file itself may leak its own instructions when triggered.

**Recommendation:** Remove or rewrite prompt content that instructs the model to reveal its own system-level instructions.

---

### PROMPT_FILE_ROLE_OVERRIDE

| Field | Value |
|-------|-------|
| **Rule ID** | `PROMPT_FILE_ROLE_OVERRIDE` |
| **Description** | Prompt file contains role-override or jailbreak language |
| **Severity** | High |
| **OWASP LLM** | LLM01 |
| **Risk Category** | Safety |
| **Score Contribution** | 13 |
| **Detection** | Regex matching `ignore previous/prior/above instructions`, `forget previous/prior/above instructions`, `override system`, `you are now a/an ...`, `new personality`, or `act as if/though you are/were ...` |

**Why it matters:** These are the stock phrasings used to bypass a model's system-level instructions; their presence in a shipped prompt file is a jailbreak surface even before any user input is involved.

**Recommendation:** Remove jailbreak-style language from prompt templates that ship with the agent.

---

### PROMPT_FILE_UNTRUSTED_PLACEHOLDER

| Field | Value |
|-------|-------|
| **Rule ID** | `PROMPT_FILE_UNTRUSTED_PLACEHOLDER` |
| **Description** | Prompt file contains untrusted input placeholder |
| **Severity** | High |
| **OWASP LLM** | LLM01 |
| **Risk Category** | Safety |
| **Score Contribution** | 10 |
| **Detection** | A template placeholder (`{{name}}`, `{name}`, or `${name}`) whose name is `user_input`, `input`, `query`, `request`, `prompt`, `text`, `message`, `data`, or `context` — fires independently of `PROMPT_FILE_INJECTION` even when no separate interpolation-syntax match is present |

**Why it matters:** A named untrusted placeholder marks exactly where caller-supplied content enters the template, whether or not it is combined with the broader injection-prone pattern.

**Recommendation:** Confirm the placeholder's content is validated or role-isolated before the template is rendered.

---

## Skill File Rules

Generated by [`SkillAnalyzer`](safeai/analyzers/skill/analyzer.py), which
inspects standalone skill definition files (Semantic Kernel `*.skill.*`,
OpenAI skill configs, and custom skill YAML/JSON) for embedded prompts,
excessive permissions, hardcoded secrets, insecure defaults, and risky
capability grants.

### SKILL_HARDCODED_SECRET

| Field | Value |
|-------|-------|
| **Rule ID** | `SKILL_HARDCODED_SECRET` |
| **Description** | Hardcoded secret found inside a skill file |
| **Severity** | Critical |
| **OWASP LLM** | LLM02 |
| **Risk Category** | Capability |
| **Score Contribution** | 20 |
| **Detection** | Regex matching `api_key`/`token`/`password`/`secret` followed by `:` or `=` and a quoted value of 8+ characters |

**Why it matters:** A credential committed directly in a skill file is extractable by anyone with read access to the file, independent of how the skill is invoked.

**Recommendation:** Remove hardcoded secrets from skill files; load credentials from environment variables or a secret manager at runtime.

---

### SKILL_EMBEDDED_PROMPT

| Field | Value |
|-------|-------|
| **Rule ID** | `SKILL_EMBEDDED_PROMPT` |
| **Description** | Skill file contains an embedded prompt |
| **Severity** | Medium |
| **OWASP LLM** | LLM01 |
| **Risk Category** | Capability |
| **Score Contribution** | 6 |
| **Detection** | Parsed YAML/JSON contains a key named `prompt`, `system_prompt`, `user_prompt`, `instructions`, `template`, `system_message`, or `content` |

**Why it matters:** An embedded prompt is a separate injection surface from any code-level prompt construction — it inherits the same risks (see the Prompt Injection and Prompt File rule families) but lives outside the files those analyzers usually scan.

**Recommendation:** Review embedded skill prompts under the same injection-hardening standard applied to code-level prompts.

---

### SKILL_EXCESSIVE_PERMISSIONS

| Field | Value |
|-------|-------|
| **Rule ID** | `SKILL_EXCESSIVE_PERMISSIONS` |
| **Description** | Skill declares excessive or dangerous permissions |
| **Severity** | High |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 14 |
| **Detection** | A key named `permissions`, `allowed_actions`, `scopes`, `grants`, or `access` whose value(s) include `admin`, `root`, `sudo`, `system`, `all`, `*`, `full_access`, `write_all`, or `execute_all` |

**Why it matters:** A skill that grants itself an unscoped or administrative permission set has no meaningful ceiling on what it can do once invoked.

**Recommendation:** Replace broad permission grants with the specific, named actions the skill actually performs.

---

### SKILL_INSECURE_DEFAULT

| Field | Value |
|-------|-------|
| **Rule ID** | `SKILL_INSECURE_DEFAULT` |
| **Description** | Skill uses an insecure default configuration |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 7 |
| **Detection** | A key named `default`, `defaults`, `fallback`, `auto_approve`, or `allow_all` whose value is truthy/permissive (`true`, `yes`, `allow`, `all`, `any`, `none`, `disabled`, `off`, `skip`, `bypass`, `*`, boolean `True`, or numeric `0` where the field is a timeout-like setting) |

**Why it matters:** An insecure default fires even for callers who never explicitly requested the permissive behavior — it is the path of least resistance for the skill.

**Recommendation:** Default to the most restrictive behavior and require an explicit opt-in for anything permissive.

---

### SKILL_RISKY_CAPABILITY

| Field | Value |
|-------|-------|
| **Rule ID** | `SKILL_RISKY_CAPABILITY` |
| **Description** | Skill grants a risky capability (shell, exec, write) |
| **Severity** | High |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 12 |
| **Detection** | A key named `capabilities`, `tools`, `actions`, `functions`, or `operations` whose serialized value matches `shell`, `exec`, `command`, `subprocess`, `os.system`, `eval(`, `exec(`, `file_write`, or `delete` |

**Why it matters:** These are the same high-risk capability families flagged elsewhere in the report (shell execution, code execution, destructive file operations); this rule catches them when declared through a skill's capability list rather than in code.

**Recommendation:** Scope the skill's declared capability list to only what its actual implementation uses.

---

## Tool Definition Rules

Generated by [`ToolDefAnalyzer`](safeai/analyzers/tool_def/analyzer.py),
which uses AST analysis on the Python function backing each declared tool.

### TOOL_MISSING_VALIDATION

| Field | Value |
|-------|-------|
| **Rule ID** | `TOOL_MISSING_VALIDATION` |
| **Description** | Tool function lacks input validation |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 7 |
| **Detection** | AST walk of the tool's function body finds no `isinstance`/`issubclass`/`validate`/`check`/`assert_` call, no `assert` statement, and no `if` statement anywhere in the body |

**Why it matters:** A tool function with no branching or validation at all applies its logic unconditionally to whatever arguments it receives.

**Recommendation:** Validate argument types and value ranges before the tool acts on them.

---

### TOOL_DANGEROUS_PARAMS

| Field | Value |
|-------|-------|
| **Rule ID** | `TOOL_DANGEROUS_PARAMS` |
| **Description** | Tool function accepts dangerous parameter patterns |
| **Severity** | High |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 12 |
| **Detection** | A positional, keyword-only, `*args`, or `**kwargs` parameter named `cmd`, `command`, `shell`, `script`, `code`, `expression`, `eval`, `exec`, `query`, `sql`, `path`, `filename`, `file_path`, `filepath`, `url`, `uri`, or `endpoint` |

**Why it matters:** Parameter names like these suggest the tool passes model-chosen text almost directly into a command, query, or file-path context — the model effectively picks part of a sensitive operation.

**Recommendation:** Constrain these parameters with an allowlist, schema, or template rather than accepting free-form text.

---

### TOOL_SHELL_ACCESS

| Field | Value |
|-------|-------|
| **Rule ID** | `TOOL_SHELL_ACCESS` |
| **Description** | Tool function invokes shell execution |
| **Severity** | High |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 15 |
| **Detection** | The tool function's source contains `subprocess`, `os.system`, `popen`, `os.popen`, or `shell=True` |

**Why it matters:** A declared tool that shells out gives the agent OS-command execution scoped to whatever the tool's arguments allow.

**Recommendation:** Avoid shelling out from tool implementations; if unavoidable, pass arguments as a list without `shell=True` and validate them strictly.

---

### TOOL_EXCESSIVE_PERMISSIONS

| Field | Value |
|-------|-------|
| **Rule ID** | `TOOL_EXCESSIVE_PERMISSIONS` |
| **Description** | Tool definition grants excessive permissions |
| **Severity** | High |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 12 |
| **Detection** | The tool's decorator line contains a permission-related keyword (`permission`, `permissions`, `allowed`, `scope`, `scopes`, `grant`, `access`, `role`, `roles`, `admin`, `write`, `delete`, `execute`, `all`, `*`) together with `all`, `*`, or `admin` |

**Why it matters:** An unscoped or administrative permission on a tool's own declaration removes any ceiling the framework's permission model would otherwise enforce.

**Recommendation:** Replace wildcard/admin grants on the tool decorator with the specific scopes the tool needs.

---

## Workflow Rules

Generated by [`WorkflowAnalyzer`](safeai/analyzers/workflow/analyzer.py),
which inspects workflow YAML/JSON templates (steps under `steps`, `stages`,
`pipeline`, `nodes`, `tasks`, or `actions`, searched recursively).

### WORKFLOW_NO_APPROVAL

| Field | Value |
|-------|-------|
| **Rule ID** | `WORKFLOW_NO_APPROVAL` |
| **Description** | Workflow lacks human approval / gate steps |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Governance |
| **Score Contribution** | 8 |
| **Detection** | The workflow has one or more steps, but no step's serialized content matches `approv`, `gate`, `review`, `manual`, `human`, `sign-off`/`signoff`, or `confirm` |

**Why it matters:** A multi-step autonomous workflow with no human checkpoint runs every step unattended, including any destructive or irreversible one.

**Recommendation:** Add an explicit approval/gate step before irreversible or high-impact actions in the workflow.

---

### WORKFLOW_INSECURE_DEFAULT

| Field | Value |
|-------|-------|
| **Rule ID** | `WORKFLOW_INSECURE_DEFAULT` |
| **Description** | Workflow template uses insecure defaults |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Governance |
| **Score Contribution** | 8 |
| **Detection** | The serialized workflow matches `auto_approve`, `allow_all`, `skip_validation`, `no_auth`, `no_gate`, `bypass`, `disabled...auth`, or `skip...check` |

**Why it matters:** These are explicit opt-outs from the workflow's own safety mechanisms, not gaps left by omission.

**Recommendation:** Remove auto-approval and validation-skipping defaults from workflow templates that run against real data.

---

### WORKFLOW_CAPABILITY_SPRAWL

| Field | Value |
|-------|-------|
| **Rule ID** | `WORKFLOW_CAPABILITY_SPRAWL` |
| **Description** | Workflow grants excessive capabilities without scoping |
| **Severity** | High |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Governance |
| **Score Contribution** | 12 |
| **Detection** | More than two steps whose serialized content matches `shell`, `exec`, `command`, `subprocess`, `delete`, `write`, `admin`, `root`, or `sudo` |

**Why it matters:** A workflow where most steps carry dangerous capabilities has a wide blast radius if any single step misbehaves or is manipulated.

**Recommendation:** Concentrate dangerous capabilities in as few, well-reviewed steps as possible; keep the rest of the pipeline read-only.

---

### WORKFLOW_MISSING_VALIDATION

| Field | Value |
|-------|-------|
| **Rule ID** | `WORKFLOW_MISSING_VALIDATION` |
| **Description** | Workflow steps lack input validation |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Governance |
| **Score Contribution** | 6 |
| **Detection** | The workflow has one or more steps, but no step's serialized content matches `validat`, `check`, `verify`, `sanitiz`, or `assert` |

**Why it matters:** Without any validation step, data moves through the pipeline unchecked from the first step to the last.

**Recommendation:** Add explicit validation steps between stages that consume external or model-produced data.

---

## Dependency & Tool-Implementation Correlation Rules

These rules correlate signals gathered elsewhere in the scan rather than
scanning file content directly.

### ENV_DEP_INVENTORY

| Field | Value |
|-------|-------|
| **Rule ID** | `ENV_DEP_INVENTORY` |
| **Description** | Referenced external configuration/credential names (inventory; informational) |
| **Severity** | Info |
| **OWASP LLM** | LLM02 |
| **Risk Category** | Identity |
| **Score Contribution** | 0 |
| **Detection** | Generated by [`EnvDependencyAnalyzer`](safeai/analyzers/env_dependency/analyzer.py): collects every environment-variable, `.env`, secret-manager, and Kubernetes-secret *name* referenced in the scanned files. Names and source locations only — no value is ever recorded. |

**Why it matters:** This is a carrying finding, not a risk finding on its own — it feeds `DEP_UNDECLARED_CAPABILITY` and `DEP_ORPHANED_TOOL` below, and the report's dependency inventory section.

**Recommendation:** Not applicable — informational only.

---

### DEP_UNDECLARED_CAPABILITY

| Field | Value |
|-------|-------|
| **Rule ID** | `DEP_UNDECLARED_CAPABILITY` |
| **Description** | Referenced credential/config has no matching declared capability |
| **Severity** | Medium |
| **OWASP LLM** | LLM02 |
| **Risk Category** | Identity |
| **Score Contribution** | 6 |
| **Detection** | Generated by [`correlate_dependencies`](safeai/analysis/dependency_correlation.py). A referenced credential/config name's keyword family (cloud, database, messaging, or api — see the module's `_FAMILIES` table) has no corresponding declared capability anywhere in the scan |

**Why it matters:** A credential the agent reads but that maps to no declared capability is static evidence the agent reaches past its declared surface — a candidate undeclared capability.

**Recommendation:** Confirm what consumes the credential; either declare the corresponding tool/capability, or remove the unused reference.

---

### DEP_ORPHANED_TOOL

| Field | Value |
|-------|-------|
| **Rule ID** | `DEP_ORPHANED_TOOL` |
| **Description** | Declared capability lacks a matching credential/config reference |
| **Severity** | Low |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Integration |
| **Score Contribution** | 3 |
| **Detection** | Generated by [`correlate_dependencies`](safeai/analysis/dependency_correlation.py). A declared capability in a credential-demanding family (cloud, database, or messaging) has no matching environment variable, secret-manager entry, or config reference anywhere in the scan |

**Why it matters:** A capability that by nature needs a backing credential but has none referenced is usually dead code or a misconfiguration, not a working integration.

**Recommendation:** Verify the capability is real: add the expected credential/config reference, or remove the stale tool declaration.

---

### TOOL_ORPHAN_DECLARED

| Field | Value |
|-------|-------|
| **Rule ID** | `TOOL_ORPHAN_DECLARED` |
| **Description** | Tool declared in configuration but no implementation found |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | — (not set by [`map_tool_implementations`](safeai/analysis/tool_implementation.py); no score-affecting contribution) |
| **Detection** | A tool referenced from a skill or workflow declaration has no matching implementation in the scanned code's tool surface or component definitions |

**Why it matters:** A configuration that promises a tool the codebase does not actually implement will fail at runtime, or silently no-op depending on the framework.

**Recommendation:** Implement the declared tool, or remove the declaration if the tool is no longer needed.

---

### TOOL_ORPHAN_IMPLEMENTED

| Field | Value |
|-------|-------|
| **Rule ID** | `TOOL_ORPHAN_IMPLEMENTED` |
| **Description** | Tool implemented but not declared in any skill, workflow, or MCP configuration |
| **Severity** | Low |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | — (not set by [`map_tool_implementations`](safeai/analysis/tool_implementation.py); no score-affecting contribution) |
| **Detection** | A tool implementation found in code has no matching reference from any skill, workflow, or MCP configuration |

**Why it matters:** An implemented-but-undeclared tool is either dead code or a capability the agent can reach without it appearing in any reviewed declaration — a gap between what configuration review would catch and what the code actually provides.

**Recommendation:** Declare the tool in the relevant skill/workflow/MCP configuration, or remove the dead implementation if it is no longer used.

---

## Data Leakage Rules

### DATA_LEAKAGE

| Field | Value |
|-------|-------|
| **Rule ID** | `DATA_LEAKAGE` |
| **Name** | Data Leakage |
| **Description** | Potential secret exposure detected |
| **Severity** | High |
| **OWASP LLM** | LLM02 (Data Leakage) |
| **Risk Category** | Identity |
| **Score Contribution** | 16 |
| **Detection** | Regex patterns matching API keys, tokens, passwords, and environment variable references |

**Sub-patterns:**

| Pattern | Example Match |
|---------|--------------|
| `API_KEY` | `api_key = "sk-1234567890abcdef1234567890abcdef"` |
| `TOKEN` | `token = "ghp_1234567890abcdef1234"` |
| `PASSWORD` | `password = "supersecret"` |
| `ENV_SECRET` | `os.environ["SECRET_KEY"]` |

**Why it matters:** Hardcoded credentials can be extracted from source code, leading to unauthorized access.

**Recommendation:** Remove hardcoded secrets from source code. Use environment variables or secure secret storage. Add `.env` to `.gitignore`.

---

### CAP_subprocess_shell

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_subprocess_shell` |
| **Name** | Subprocess with shell=True |
| **Description** | `subprocess` invoked with `shell=True`, enabling shell injection |
| **Severity** | Critical |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 15 |
| **Detection** | Regex: `subprocess` followed by `shell=True` on the same line |

**Evidence example:**
```python
subprocess.run(user_command, shell=True)
```

**Why it matters:** `shell=True` passes the command through the system shell, making injection trivial when any part of the command is influenced by user or model output.

**Recommendation:** Pass commands as argument lists without `shell=True`, and validate any dynamic arguments.

---

### CAP_file_write

| Field | Value |
|-------|-------|
| **Rule ID** | `CAP_file_write` |
| **Name** | File Write Capability |
| **Description** | File opened in write, append, or exclusive-create mode |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |
| **Risk Category** | Capability |
| **Score Contribution** | 7 |
| **Detection** | Regex: `open(..., "w"|"a"|"x"...)` mode flags |

**Evidence example:**
```python
with open(filename, "w") as f:
    f.write(agent_output)
```

**Why it matters:** Write access enables data tampering and persistent payloads when file paths or contents are model-influenced.

**Recommendation:** Restrict writes to dedicated output directories and validate paths against an allowlist.

---

## Removed and Consolidated Rules

The following rule IDs were removed from `rules/base_rules.yaml` because they
had no dedicated detection logic. Their coverage is provided by other rules:

| Rule ID | Description | Replacement |
|---------|-------------|-------------|
| `CAP_eval` | Use of `eval()` | `CAP_code_exec` |
| `CAP_exec` | Use of `exec()` | `CAP_code_exec` |
| `PROMPT_TOOL_OUTPUT` | Tool output directly injected into prompt | Planned (see roadmap) |
| `GOAL_HIJACK` | Dangerous instruction keywords | Planned (see roadmap) |

Every rule currently declared in `rules/base_rules.yaml` has active detection
logic, with one exception: `CAP_browser` is still declared and used for
scorecard/compliance-mapping bucketing, but has no dedicated detector of its
own — see the note under [CAP_browser_use](#cap_browser_use) above. Actual
browser-automation detection is split across `CAP_browser_playwright`,
`CAP_browser_selenium`, and `CAP_browser_use`.

---

## Claude Code Rules

These rules cover deep analysis of Claude Code project configuration:
`.claude/settings.json` and `.claude/settings.local.json`, `.mcp.json`,
`.claude/commands/*.md` slash commands, `.claude/agents/*` subagent
definitions, and lifecycle hooks. Only configuration committed inside the
scanned repository is read; see `FRAMEWORK_SUPPORT.md` for the exact scope
boundary.

### CC_WILDCARD_PERMISSION

| Field | Value |
|-------|-------|
| **Rule ID** | `CC_WILDCARD_PERMISSION` |
| **Description** | Claude Code permission granted with no argument constraint (e.g. `Bash(*)`, bare `Bash`) |
| **Severity** | High |
| **OWASP LLM** | LLM06 (Excessive Agency) |

**Why it matters:** A permission entry without an argument constraint grants the tool unconditionally, regardless of what argument or command is passed at invocation time.

**Recommendation:** Scope permissions with explicit argument patterns (e.g. `Bash(npm run test:*)`) instead of a bare tool name or wildcard.

---

### CC_BYPASS_PERMISSIONS

| Field | Value |
|-------|-------|
| **Rule ID** | `CC_BYPASS_PERMISSIONS` |
| **Description** | Claude Code approval gate disabled or weakened (`bypassPermissions`, `dangerously-skip-permissions`, permissive default mode) |
| **Severity** | Critical |
| **OWASP LLM** | LLM06 |

**Why it matters:** Disabling the permission gate removes the human-in-the-loop check that would otherwise stop an unreviewed tool call.

**Recommendation:** Remove bypass settings from committed configuration; if a permissive mode is required for local development, keep it out of files that ship with the repository.

---

### CC_DENY_SHADOWED

| Field | Value |
|-------|-------|
| **Rule ID** | `CC_DENY_SHADOWED` |
| **Description** | Claude Code deny entry contradicted by a broader allow entry, so it cannot take effect |
| **Severity** | High |
| **OWASP LLM** | LLM06 |

**Why it matters:** A deny rule that is shadowed by a broader allow rule gives a false sense of restriction — the tool remains permitted in practice.

**Recommendation:** Order and scope allow/deny entries so that intended restrictions are not overridden by a broader grant.

---

### CC_FS_WRITE_OUTSIDE_ROOT

| Field | Value |
|-------|-------|
| **Rule ID** | `CC_FS_WRITE_OUTSIDE_ROOT` |
| **Description** | Claude Code write permission targets a path outside the project root |
| **Severity** | High |
| **OWASP LLM** | LLM06 |

**Why it matters:** A write grant that reaches outside the project root can modify files unrelated to the project, including shared or system paths.

**Recommendation:** Constrain write permissions to paths inside the project root.

---

### CC_SLASH_COMMAND_SHELL

| Field | Value |
|-------|-------|
| **Rule ID** | `CC_SLASH_COMMAND_SHELL` |
| **Description** | Custom slash command embeds a shell invocation or inlines external file content |
| **Severity** | Medium |
| **OWASP LLM** | LLM01 (Prompt Injection) |

**Why it matters:** Slash commands are an instruction surface that can be invoked with caller-supplied context; embedding a shell invocation or inlining file content widens what that instruction can do or see.

**Recommendation:** Keep shell invocations and file inlining out of slash command bodies where possible, or ensure the command does not accept untrusted arguments.

---

### CC_SLASH_COMMAND_ARG_INJECTION

| Field | Value |
|-------|-------|
| **Rule ID** | `CC_SLASH_COMMAND_ARG_INJECTION` |
| **Description** | Custom slash command interpolates caller-supplied `$ARGUMENTS` into a shell invocation |
| **Severity** | Critical |
| **OWASP LLM** | LLM01 |

**Why it matters:** Interpolating `$ARGUMENTS` (or `$1`–`$9`) directly into a shell command means whoever invokes the slash command controls part of the shell command executed. This is the concrete pattern that feeds the `ESC_COMBO_UNTRUSTED_INPUT_SHELL` escalation rule.

**Recommendation:** Validate or quote argument interpolation before it reaches a shell context, or avoid passing raw arguments to shell commands.

---

### CC_SUBAGENT_PRIVILEGE_ESCALATION

| Field | Value |
|-------|-------|
| **Rule ID** | `CC_SUBAGENT_PRIVILEGE_ESCALATION` |
| **Description** | Claude Code subagent granted tools beyond its parent permission scope |
| **Severity** | High |
| **OWASP LLM** | LLM08 (Excessive Agency via multi-agent systems) |

**Why it matters:** A subagent that can use tools its parent was not granted effectively bypasses the parent's permission scope. This rule only fires when the parent's tool scope is itself explicitly declared, so it never infers a violation from an undeclared parent scope.

**Recommendation:** Keep subagent tool grants within, or narrower than, the parent's declared tool scope.

---

### CC_HOOK_SHELL_EXEC

| Field | Value |
|-------|-------|
| **Rule ID** | `CC_HOOK_SHELL_EXEC` |
| **Description** | Claude Code lifecycle hook executes a shell command, or fetches unpinned remote content |
| **Severity** | High |
| **OWASP LLM** | LLM05 (Supply Chain Vulnerabilities) |

**Why it matters:** Hooks run automatically on lifecycle events without an explicit per-invocation approval step. An unpinned remote fetch inside a hook (curl/wget/npx -y/pip install without a pinned requirement/pipe-to-shell) means the exact code that runs can change without a corresponding change to the repository.

**Recommendation:** Pin hook dependencies to specific versions or hashes, and avoid piping remote content directly into a shell.

---

### CC_MCP_UNCONSTRAINED

| Field | Value |
|-------|-------|
| **Rule ID** | `CC_MCP_UNCONSTRAINED` |
| **Description** | MCP server enabled without a corresponding permission constraint |
| **Severity** | Medium |
| **OWASP LLM** | LLM06 |

**Why it matters:** An MCP server without a matching permission entry is reachable without the explicit scoping that the permission system is meant to provide.

**Recommendation:** Add an explicit permission entry (`mcp__server__tool` grant) for each enabled MCP server.

---

### CC_SETTINGS_UNPARSEABLE

| Field | Value |
|-------|-------|
| **Rule ID** | `CC_SETTINGS_UNPARSEABLE` |
| **Description** | Claude Code configuration file could not be parsed and cannot be reviewed or enforced |
| **Severity** | Low |
| **OWASP LLM** | LLM09 (Overreliance) |

**Why it matters:** A configuration file that cannot be parsed cannot be checked for any of the other Claude Code rules — it is a gap in coverage, not a clean bill of health. SafeAI tolerates JSON comments and trailing commas before falling back to this rule, so it only fires on genuinely malformed files.

**Recommendation:** Fix the configuration file's syntax so its permissions and settings can be reviewed. This finding also feeds the `assurance_boundary` coverage notes in the KYA manifest.

---

## MCP-Specific Rules

MCP-related rules are generated dynamically by the MCP analyzer and are documented in [MCP_SECURITY.md](MCP_SECURITY.md). The following MCP rule IDs are used:

| Rule ID | Description | Severity |
|---------|-------------|----------|
| `MCP_SCHEMA_REQUIRED` | Missing required MCP configuration field | Medium |
| `MCP_SCHEMA_TYPE` | MCP field type mismatch | Medium |
| `MCP_SCHEMA_ENDPOINT_TYPE` | MCP endpoint entry type mismatch | Low |
| `MCP_PY_REFERENCE` | Python source references MCP | Low |
| `MCP_AUTH_MISSING` | MCP authentication not configured | High |
| `MCP_AUTH_WEAK` | MCP authentication is weak/disabled | High |
| `MCP_PERMISSIONS_MISSING` | MCP permissions not configured | High |
| `MCP_ENDPOINT_EXPOSURE` | Potentially exposed MCP endpoint | High |
| `MCP_HARDCODED_SECRET` | Hardcoded secret in MCP configuration | Critical |
| `MCP_DANGEROUS_TOOL` | MCP tool may allow unrestricted execution | High |
| `MCP_TOOL_DESCRIPTION_INJECTION` | Hidden instructions in an MCP tool description (tool poisoning, LLM01) | High |
| `MCP_TOOL_OVERLY_BROAD` | MCP tool parameter definition uses wildcards or unrestricted patterns (`*`, `all`, `any`, `unrestricted`, `no limit`, `bypass`) | High |
| `MCP_RESOURCE_SENSITIVE` | MCP resource may expose sensitive data (password/secret/credential/token/private/SSN/credit-card/API-key patterns) | High |
| `MCP_TRANSPORT_INSECURE` | MCP transport uses an insecure protocol (`http://`, `ws://`, `stdio`, `tcp://`, or no HTTPS transport configured at all) | High |
| `MCP_ASSETS_DISCOVERED` | Scanner metadata: MCP discovery summary | Info |

---

## Adding Custom Rules

1. Create a YAML file with your rule definitions
2. Use the same format as `rules/base_rules.yaml`
3. Pass the directory via `--rules`:

```bash
python -m safeai scan /path/to/project --rules /path/to/custom-rules/
```

Custom rules merge with built-in rules. If a custom rule has the same ID as a built-in rule, the custom severity and OWASP category override the built-in values.
