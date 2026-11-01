"""Package-manager authority vocabulary (v2.9, ROADMAP E1).

Answers one question about a granted command or file scope: *can the agent
change the project's dependencies through it?* It never answers whether a
chosen package is safe — that is the Software Ecosystem Evidence Plane
(OpenPulse), not agent authority.

Two routes change dependencies:

* running a package manager — installing, adding, upgrading or removing a
  dependency (access mode ``write``), or publishing a package (``execute``);
* writing a dependency manifest or lockfile directly (``write``).

Each route is reported as a *target*: ``"<manager>:install"``,
``"<manager>:publish"`` or ``"manifest:<file>"``. Targets feed the per-tool
``dependency`` authority dimension.

Everything here is string analysis over a command or path *pattern* as
written in configuration. Nothing is executed. A pattern that does not
name a package manager or a manifest yields no target: a broad grant such
as ``Bash`` or ``Write(*)`` already carries shell or filesystem authority,
and reading dependency authority into it would be a guess.
"""

import fnmatch
import re

#: Subcommands per manager, by route. ``None`` as a manager-level wildcard
#: (``npm:*``) grants every listed route.
_ROUTES = {
    "npm": {
        "install": {"install", "i", "add", "ci", "update", "up", "upgrade",
                    "uninstall", "remove", "rm", "un", "unlink"},
        "publish": {"publish"},
    },
    "pnpm": {
        "install": {"install", "i", "add", "update", "up", "upgrade", "remove", "rm", "un"},
        "publish": {"publish"},
    },
    "yarn": {
        "install": {"install", "add", "upgrade", "up", "remove"},
        "publish": {"publish"},
    },
    "pip": {"install": {"install", "uninstall"}},
    "uv": {
        "install": {"add", "remove", "sync", "lock"},
        "publish": {"publish"},
    },
    "poetry": {
        "install": {"add", "remove", "install", "update", "lock"},
        "publish": {"publish"},
    },
    "cargo": {
        "install": {"add", "remove", "install", "update"},
        "publish": {"publish"},
    },
    "go": {"install": {"get", "install"}},
    "twine": {"publish": {"upload"}},
}

#: Executable spellings that resolve to a manager in ``_ROUTES``.
_ALIASES = {"pip3": "pip", "uvx": None}

#: Interpreter prefixes that run a manager as a module: ``python -m pip``.
_MODULE_RUNNERS = {"python", "python3", "py"}

#: Access mode per route.
ROUTE_ACCESS_MODES = {"install": "write", "publish": "execute"}

#: Dependency manifests and lockfiles, matched on the final path segment.
DEPENDENCY_MANIFESTS = (
    "package.json", "package-lock.json", "npm-shrinkwrap.json",
    "pnpm-lock.yaml", "yarn.lock",
    "requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock",
    "Pipfile", "Pipfile.lock", "setup.py", "setup.cfg",
    "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock",
)

#: ``requirements-dev.txt`` and similar are manifests too.
_REQUIREMENTS_RE = re.compile(r"^requirements[\w.-]*\.txt$")

#: Registry publishing and installation credentials, by name. Only the name
#: is ever read; a value never enters a report.
REGISTRY_CREDENTIAL_NAMES = frozenset({
    "NPM_TOKEN", "NODE_AUTH_TOKEN", "NPM_AUTH_TOKEN",
    "PYPI_TOKEN", "PYPI_API_TOKEN", "TWINE_PASSWORD", "TWINE_USERNAME",
    "UV_PUBLISH_TOKEN", "UV_PUBLISH_PASSWORD", "POETRY_PYPI_TOKEN_PYPI",
    "CARGO_REGISTRY_TOKEN",
})

_WILDCARD_SUFFIX_RE = re.compile(r"(?::\*|\s+\*)$")


def _tokens(command):
    text = _WILDCARD_SUFFIX_RE.sub("", str(command or "").strip().strip("\"'"))
    wildcard = text != str(command or "").strip().strip("\"'")
    return text.split(), wildcard


def _manager(tokens):
    """Return ``(manager, rest)`` for a command, or ``(None, [])``."""
    if not tokens:
        return None, []
    head = tokens[0].lower()
    if head in _MODULE_RUNNERS and len(tokens) >= 3 and tokens[1] == "-m":
        head, tokens = tokens[2].lower(), tokens[2:]
    elif head == "uv" and len(tokens) >= 2 and tokens[1].lower() == "pip":
        head, tokens = "pip", tokens[1:]
    head = _ALIASES.get(head, head)
    if head not in _ROUTES:
        return None, []
    return head, tokens[1:]


def command_targets(command):
    """Dependency targets a granted command pattern confers.

    ``"npm install:*"`` → ``["npm:install"]``; ``"npm publish"`` →
    ``["npm:publish"]``; ``"npm:*"`` → every route npm has; ``"npm run
    build"`` → ``[]``. Returns a sorted list.
    """
    tokens, wildcard = _tokens(command)
    manager, rest = _manager(tokens)
    if manager is None:
        return []
    routes = _ROUTES[manager]
    if not rest:
        # `npm:*` / `npm *` grants every subcommand; a bare `npm` grants none.
        return sorted(f"{manager}:{route}" for route in routes) if wildcard else []
    subcommand = rest[0].lower()
    return sorted(
        f"{manager}:{route}" for route, verbs in routes.items() if subcommand in verbs
    )


def access_mode_for(targets):
    """Highest access mode among package-manager targets (``None`` when empty)."""
    modes = {ROUTE_ACCESS_MODES[t.split(":", 1)[1]] for t in targets
             if t.split(":", 1)[1] in ROUTE_ACCESS_MODES}
    if "execute" in modes:
        return "execute"
    if "write" in modes:
        return "write"
    return None


def manifest_targets(path_pattern):
    """Manifest targets a granted file-write pattern names.

    The final path segment must name a manifest, literally or with a
    wildcard that does not lead the segment: ``package.json``,
    ``./services/api/go.mod``, ``**/Cargo.toml`` and ``requirements*.txt``
    count; ``*``, ``**`` and ``*.json`` do not, because they name no
    manifest in particular.
    """
    text = str(path_pattern or "").strip().strip("\"'").replace("\\", "/").rstrip("/")
    segment = text.rsplit("/", 1)[-1]
    if not segment or segment[0] in "*?[":
        return []
    if segment in DEPENDENCY_MANIFESTS or _REQUIREMENTS_RE.match(segment):
        return [f"manifest:{segment}"]
    if any(ch in segment for ch in "*?["):
        matched = [m for m in DEPENDENCY_MANIFESTS if fnmatch.fnmatchcase(m, segment)]
        if matched or fnmatch.fnmatchcase("requirements.txt", segment):
            return [f"manifest:{segment}"]
    return []


def registry_credentials(names):
    """The registry credential names among ``names``, sorted."""
    return sorted({str(n) for n in names or [] if str(n) in REGISTRY_CREDENTIAL_NAMES})
