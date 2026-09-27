"""Capability-to-authority semantic normalization (v2.5 redesign).

Compares authority *semantics* — provider, service, operation class,
scope, wildcards — never bare categories. ``s3:GetObject`` is not
``iam:*``; ``get pods`` is not ``* *``. When either side cannot be
safely normalized, callers must prefer UNKNOWN over guessing.

Operation classes form a strict lattice (no IAM implication assumed —
``PutObject`` does not imply ``GetObject``)::

    read < write < admin

A grant covers a requirement only when its operation set is a
superset of the required set on the same (provider, service).
"""

#: Operation classes.
READ = "read"
WRITE = "write"
ADMIN = "admin"
_OPS_ORDER = {READ: 0, WRITE: 1, ADMIN: 2}

#: Verb → operation class. Unknown verbs stay unmapped (conservative:
#: un-normalizable, never assumed benign or covered). AWS verbs are
#: CamelCase compounds (``GetObject``, ``PutObject``), so roots match
#: by prefix after exact lookup.
_READ_VERBS = frozenset({
    "get", "list", "describe", "head", "read", "select", "watch", "view",
    "detect", "scan",
})
_WRITE_VERBS = frozenset({
    "put", "create", "update", "delete", "post", "write", "patch",
    "attach", "detach", "tag", "untag", "send", "publish", "upload",
    "invoke", "execute", "run",
})
_READ_ROOTS = ("get", "list", "describ", "head", "select", "read",
               "watch", "view", "detect", "scan")
_WRITE_ROOTS = ("put", "creat", "updat", "delet", "post", "writ",
                "patch", "attach", "detach", "tag", "untag", "send",
                "publish", "upload", "invoke", "execut", "run")

#: Declared capability name → (provider, service). Exact match only.
#: ``service "*"`` means any service of that provider.
_DECLARED_DOMAINS = {
    "s3": ("aws", "s3"),
    "cloud": ("aws", "*"),
    "cloud_services": ("aws", "*"),
    "gcp": ("gcp", "*"),
    "kubernetes": ("kubernetes", "*"),
}

#: Access mode → required operation set.
_MODE_OPS = {
    "read": frozenset({READ}),
    "write": frozenset({READ, WRITE}),
    "mutate": frozenset({READ, WRITE}),
    "execute": frozenset({READ, WRITE}),
    "none": frozenset(),
}


def ops_class(verb):
    """Map a verb to an operation class, or None when unknown.

    Privilege-delegation verbs (``PassRole``, ``AssumeRole``) and
    anything containing ``admin`` map to ADMIN; delegation is never
    treated as mere read/write.
    """
    low = str(verb or "").strip().lower()
    if low in ("*", "admin", "administer") or "admin" in low:
        return ADMIN
    if low in ("passrole", "assumerole"):
        return ADMIN
    if low in _READ_VERBS or low.startswith(_READ_ROOTS):
        return READ
    if low in _WRITE_VERBS or low.startswith(_WRITE_ROOTS):
        return WRITE
    return None


def normalize_requirement(cap_name, access_mode):
    """Normalize a declared (capability, access mode) to a requirement.

    Returns ``{provider, service, ops}`` or None when the capability
    has no IaC-mappable authority domain (silently irrelevant, not
    UNKNOWN — absence of a mappable domain is not uncertainty).
    """
    domain = _DECLARED_DOMAINS.get(str(cap_name or "").lower())
    if domain is None:
        return None
    ops = _MODE_OPS.get(str(access_mode or "").lower())
    if not ops:
        return None
    return {"provider": domain[0], "service": domain[1], "ops": set(ops)}


def normalize_grant_action(action, source="terraform"):
    """Normalize one grant action value to a descriptor.

    Returns ``{provider, service, ops, wildcard}`` or None when the
    action cannot be safely normalized (unknown verb without wildcard).
    """
    raw = str(action or "").strip()
    if not raw:
        return None
    if raw == "*":
        return {"provider": "*", "service": "*",
                "ops": {READ, WRITE, ADMIN}, "wildcard": True}
    if source == "kubernetes":
        cls = ops_class(raw)
        if cls is None:
            return None
        ops = {READ, WRITE, ADMIN} if cls == ADMIN else (
            {READ} if cls == READ else {READ, WRITE})
        return {"provider": "kubernetes", "service": "*",
                "ops": ops, "wildcard": False}
    if ":" not in raw:
        cls = ops_class(raw)
        if cls is None:
            return None
        return {"provider": "aws", "service": "*",
                "ops": ({READ, WRITE, ADMIN} if cls == ADMIN
                        else ({READ} if cls == READ else {READ, WRITE})),
                "wildcard": False}
    service, verb = raw.split(":", 1)
    service = service.strip().lower() or "*"
    verb = verb.strip()
    if verb == "*":
        return {"provider": "aws", "service": service,
                "ops": {READ, WRITE, ADMIN}, "wildcard": True}
    cls = ops_class(verb)
    if cls is None:
        return None
    ops = {READ, WRITE, ADMIN} if cls == ADMIN else (
        {READ} if cls == READ else {READ, WRITE})
    return {"provider": "aws", "service": service,
            "ops": ops, "wildcard": False}


def grant_descriptor(grant):
    """Aggregate a Grant's action values to one descriptor + flags.

    Returns ``(descriptor, unresolvable)`` where ``unresolvable`` is
    True when material content is unresolved or un-normalizable (the
    caller must then prefer UNKNOWN).
    """
    actions = grant.get("actions") or {}
    values = actions.get("values") or []
    resolution = actions.get("resolution") or "unresolved"
    source = grant.get("source") or "terraform"
    providers, services, ops = set(), set(), set()
    wildcard = False
    unresolvable = resolution == "unresolved"
    for value in values:
        desc = normalize_grant_action(value, source)
        if desc is None:
            unresolvable = True
            continue
        providers.add(desc["provider"])
        services.add(desc["service"])
        ops |= desc["ops"]
        wildcard = wildcard or desc["wildcard"]
    if resolution in ("partially-resolved", "unresolved"):
        unresolvable = True
    if not values:
        unresolvable = True
    provider = "*" if "*" in providers else (
        next(iter(providers)) if len(providers) == 1 else None)
    service = "*" if "*" in services else (
        next(iter(services)) if len(services) == 1 else None)
    if provider is None or service is None:
        unresolvable = True
    return ({"provider": provider or "*", "service": service or "*",
             "ops": ops, "wildcard": wildcard}, unresolvable)


def compatible(grant_desc, requirement):
    """Decide coverage of a requirement by a grant descriptor.

    Returns ``(covered, excess_ops, notes)``. Service ``"*"`` on either
    side matches (requirement-side ``*`` = any service acceptable;
    grant-side ``*`` = wildcard, flagged). Scope is evidence-only in
    v2.5 (requirements carry no scope); recorded, never assumed.
    """
    notes = []
    if (grant_desc["provider"] != "*"
            and grant_desc["provider"] != requirement["provider"]):
        return False, set(), ["provider-mismatch"]
    if (requirement["service"] != "*" and grant_desc["service"] != "*"
            and grant_desc["service"] != requirement["service"]):
        return False, set(), ["service-mismatch"]
    if grant_desc["service"] == "*" and requirement["service"] != "*":
        notes.append("grant-service-wildcard")
    if grant_desc["wildcard"]:
        notes.append("grant-wildcard")
    covered = requirement["ops"] <= grant_desc["ops"]
    excess = set(grant_desc["ops"]) - set(requirement["ops"])
    return covered, excess, notes
