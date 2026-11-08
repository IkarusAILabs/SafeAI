"""Framework parser registry and installed parser-plugin loader.

Parsers register themselves here so that ``safeai.engine.scan`` does not
need a hard-coded import list.  To add a new framework adapter, create a
sub-package with a ``parser.py`` that exposes a class with ``detect()``
and ``parse()`` methods, then call ``register_parser`` below.

External plugins may register through the ``safeai.parsers`` Python entry
point group or call ``register_parser`` at import time.
"""

import logging
from importlib import metadata

_PARSER_REGISTRY = []
_PARSER_NAMES = set()
# name -> {"external": bool, "version": str | None}. ``version`` is the
# installed distribution version for entry-point plugins, else None
# (resolved to the SafeAI version at record time).
_PARSER_META = {}
logger = logging.getLogger(__name__)


def register_parser(cls):
    """Register a framework parser class.

    The class must have ``detect(path, content, scan_ctx)`` and
    ``parse(path, content, scan_ctx)`` methods.  Instances are
    created once per scan.
    """
    name = getattr(cls, "name", None)
    if not name or not callable(getattr(cls, "detect", None)) or not callable(getattr(cls, "parse", None)):
        raise TypeError("Parser must define a non-empty name, detect(), and parse()")
    if name not in _PARSER_NAMES:
        _PARSER_REGISTRY.append(cls)
        _PARSER_NAMES.add(name)
        _PARSER_META[name] = {"external": False, "version": None}
    return cls


def _load_external_parsers():
    """Load parser classes exposed by installed ``safeai.parsers`` plugins."""
    try:
        entries = metadata.entry_points()
        if hasattr(entries, "select"):
            entries = entries.select(group="safeai.parsers")
        else:
            entries = entries.get("safeai.parsers", [])
    except Exception as exc:
        logger.debug("Unable to enumerate parser plugins: %s", exc)
        return

    for entry in entries:
        try:
            loaded = entry.load()
            dist_version = getattr(entry.dist, "version", None) if hasattr(entry, "dist") else None
            register_parser(loaded)
            _PARSER_META[getattr(loaded, "name", entry.name)] = {
                "external": True,
                "version": dist_version,
            }
        except Exception as exc:
            logger.warning("Unable to load parser plugin %s: %s", entry.name, exc)


def discover_parsers(include_external=True):
    """Return a list of all registered parser instances."""
    # Ensure all built-in parsers are imported so they register. Every
    # ``safeai/frameworks/<name>/parser.py`` must be listed here:
    # tests/test_parser_discovery.py fails when one is missing.
    from safeai.frameworks.autogen.parser import AutoGenParser  # noqa: F401
    from safeai.frameworks.azure_foundry.parser import AzureFoundryParser  # noqa: F401
    from safeai.frameworks.bedrock_agent.parser import BedrockAgentParser  # noqa: F401
    from safeai.frameworks.claude_code.parser import ClaudeCodeParser  # noqa: F401
    from safeai.frameworks.copilot.parser import CopilotParser  # noqa: F401
    from safeai.frameworks.crewai.parser import CrewAIParser  # noqa: F401
    from safeai.frameworks.cursorrules.parser import CursorRulesParser  # noqa: F401
    from safeai.frameworks.dify.parser import DifyParser  # noqa: F401
    from safeai.frameworks.google_adk.parser import GoogleADKParser  # noqa: F401
    from safeai.frameworks.haystack.parser import HaystackParser  # noqa: F401
    from safeai.frameworks.langchain.parser import LangChainParser  # noqa: F401
    from safeai.frameworks.langgraph.parser import LangGraphParser  # noqa: F401
    from safeai.frameworks.llamaindex.parser import LlamaIndexParser  # noqa: F401
    from safeai.frameworks.mastra.parser import MastraParser  # noqa: F401
    from safeai.frameworks.microsoft_agent.parser import (
        MicrosoftAgentFrameworkParser,  # noqa: F401
    )
    from safeai.frameworks.n8n.parser import N8nParser  # noqa: F401
    from safeai.frameworks.openai_agents.parser import OpenAIAgentsParser  # noqa: F401
    from safeai.frameworks.openclaw.parser import OpenClawParser  # noqa: F401
    from safeai.frameworks.semantic_kernel.parser import (
        SemanticKernelParser,  # noqa: F401
    )
    from safeai.frameworks.windsurf.parser import WindsurfParser  # noqa: F401
    if include_external:
        _load_external_parsers()
    return [cls() for cls in _PARSER_REGISTRY]


def parser_records(include_external=True):
    """Return parser metadata (name/external/version) for per-scan recording."""
    discover_parsers(include_external=include_external)
    return [
        {
            "name": getattr(cls, "name", type(cls).__name__),
            **_PARSER_META.get(getattr(cls, "name", ""), {"external": False, "version": None}),
        }
        for cls in _PARSER_REGISTRY
    ]
