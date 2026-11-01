from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from pathlib import Path

from .errors import PathPolicyError

# Version of the sensitive-name rules below. Anything derived from a tree while an older (or unknown) version
# was in force is not trusted again by name alone: derived stores stamp this value and compare it before reuse.
# Bump it whenever a rule is added, removed or changed.
SENSITIVE_POLICY_VERSION = "uam-sensitive-names/2026-10-17.2"

# THE single source of sensitive path-component names. ``scope_search``, ``resolver``, ``discovery`` and
# ``exploration`` all decide through ``is_denied_component`` below; none keeps a list of its own.
#
# Deny exact or structurally sensitive names. Avoid broad substring blocking so documentation such as
# docs/credential-model.md or docs/secrets.md can still be researched. A name rule can only recognise the
# categories it lists: it cannot prove that an ordinary source, JSON, log or document file holds no secret.
_DENIED_EXACT = {
    ".git",
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "_netrc",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "credentials.json",
    "secrets.json",
    # Credential stores and tool dot-files that hold a secret by design.
    ".git-credentials",
    ".pgpass",
    ".my.cnf",
    ".mylogin.cnf",
    ".s3cfg",
    ".boto",
    ".dockercfg",
    ".vault-token",
    ".htpasswd",
    ".azure",
    ".password-store",
    ".secrets",
    ".secret",
    "kubeconfig",
    "token.json",
    "tokens.json",
}
_FLAGS = re.IGNORECASE | re.DOTALL  # DOTALL: ".*" must also cross a newline inside a name
_DENIED_PATTERNS = [
    # Any name that starts with ".env": .env, .env.local, .env-prod, .env_backup, .env~, .envrc, .envs.
    re.compile(r"^\.env.*$", _FLAGS),
    # Any name that ends in an ".env" segment: secrets.env, .secrets.env, tokens.env, keys.env, prod.env.bak, x.env~.
    # (S1: the incident file ".secrets.env" matched neither of the two original rules.)
    re.compile(r"^.+\.env(?:[.~].*)?$", _FLAGS),
    re.compile(r".*\.(?:pem|p12|pfx|key|keystore|jks|p8|ppk)$", _FLAGS),
    re.compile(r".*\.keychain(?:-db)?$", _FLAGS),
    re.compile(r".*\.tfstate(?:\..*)?$", _FLAGS),
    re.compile(r".*\.tfvars(?:\.json)?$", _FLAGS),
    # Private SSH keys by name; the public half (id_rsa.pub) stays readable.
    re.compile(r"^id_(?:rsa|dsa|ecdsa|ed25519)(?:_[^.]*)?$", _FLAGS),
    # Structured data files named for secrets (secrets.yml, .secrets.toml). Prose (secrets.md) and plain ".txt" are NOT
    # matched: ".txt" is too ambiguous to refuse by name, so a note called secrets.txt is a documented residual that the
    # scope the workspace is registered under (a narrow workspace) has to cover, not this list.
    re.compile(r"^\.?secrets?\.(?:json|ya?ml|toml|ini|cfg|conf|properties)$", _FLAGS),
    re.compile(r"^client_secrets?(?:[_.-].*)?\.json$", _FLAGS),
    # Shell and REPL histories routinely contain pasted tokens.
    re.compile(r"^\.[a-z0-9_]*_history$", _FLAGS),
]


@lru_cache(maxsize=65536)
def fold_name(name: str) -> str:
    """One path component as a case- and normalization-insensitive filesystem compares it.

    The default macOS volume is case-insensitive and Unicode-normalization-insensitive, so
    ``.SSH`` names the directory ``.ssh`` and a precomposed ``é`` names the same file as a
    decomposed one. A name that is matched against a denied name, or a scope root, has to be
    compared in this folded form, never as spelled: the spelling is chosen by the caller.
    """
    decomposed = unicodedata.normalize("NFD", name)
    return unicodedata.normalize("NFD", decomposed.casefold())


_DENIED_EXACT_FOLDED = frozenset(fold_name(name) for name in _DENIED_EXACT)

# Unicode Default_Ignorable_Code_Point (zero-width space/joiners, bidi controls, soft hyphen, variation selectors, BOM,
# Hangul fillers, tag characters). A legacy or network filesystem, a normalizer or a client may drop them when it
# compares names, so a spelling that differs from a denied name only by these is that name.
_DEFAULT_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5), (0x180B, 0x180F),
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
)
_DROP_IGNORABLE = {code: None for low, high in _DEFAULT_IGNORABLE_RANGES for code in range(low, high + 1)}


@lru_cache(maxsize=65536)
def _alias_key(name: str) -> str:
    """``name`` as a filesystem that drops ignorable code points and trailing blanks/dots compares it.

    Used ONLY to decide denial. A Windows-semantics volume (an SMB or exFAT mount) drops trailing spaces and dots, so
    ``credentials.json `` is ``credentials.json`` there; a line-oriented tool drops a trailing newline. The result is
    folded like ``fold_name``. It is never used to compare scope roots or to build a path.
    """
    reduced = fold_name(name.translate(_DROP_IGNORABLE))
    end = len(reduced)
    while end and (reduced[end - 1] == "." or reduced[end - 1].isspace()):
        end -= 1
    return reduced[:end]


def _denied_spelling(spelling: str, folded: str) -> bool:
    if folded in _DENIED_EXACT_FOLDED:
        return True
    # Patterns are tried on the spelling as given AND on the folded one: the filesystem may treat a spelling that
    # only folds to a denied name (a long s for "s", a Kelvin sign for "k") as that very file.
    return any(pattern.fullmatch(spelling) or pattern.fullmatch(folded) for pattern in _DENIED_PATTERNS)


def is_denied_component(component: str) -> bool:
    """Whether one path component is a sensitive name (see ``SENSITIVE_POLICY_VERSION``).

    A spelling is denied exactly when the name it reduces to is: case, normalization form, default-ignorable code
    points and trailing blanks/dots are all alias closure (see ``_alias_key``). That closure adds no name family: a
    name that is readable stays readable under every one of those spellings.
    """
    folded = fold_name(component)
    if _denied_spelling(component, folded):
        return True
    alias = _alias_key(component)
    return alias != folded and _denied_spelling(alias, alias)


# The historical private name: still imported by tests and by modules that predate the public one.
_is_denied_component = is_denied_component


def is_denied_path(path: str | Path) -> bool:
    """Whether any component of ``path`` (relative or absolute) is a sensitive name."""
    return any(is_denied_component(part) for part in Path(path).parts)


def is_git_metadata_component(component: str) -> bool:
    """Whether a component is (an alias of) a repository's own metadata directory, ``.git``.

    Not a sensitive name: it is not part of the denied-name policy and adds nothing to it. It is the one name a tree
    rebuilt out of a repository's index must never contain, because a file written below it would land in the
    metadata of the rebuilt copy. Aliases (case, ignorable code points, trailing dots and blanks, the Windows short
    name) count, as for ``is_denied_component``.
    """
    return _alias_key(component) in (".git", "git~1")


def ensure_relative_path(raw: str) -> Path:
    if "\x00" in raw:
        raise PathPolicyError("NUL byte is forbidden")
    path = Path(raw or ".")
    if path.is_absolute():
        raise PathPolicyError("absolute paths are forbidden")
    if any(part in {"..", "~"} for part in path.parts):
        raise PathPolicyError("path traversal is forbidden")
    for part in path.parts:
        if is_denied_component(part):
            raise PathPolicyError(f"denied path component: {part}")
    return path


def resolve_safe_path(root: str | Path, raw: str, *, must_exist: bool = True) -> Path:
    root_path = Path(root).expanduser().resolve(strict=True)
    rel = ensure_relative_path(raw)
    candidate = (root_path / rel).resolve(strict=must_exist)
    try:
        candidate.relative_to(root_path)
    except ValueError as exc:
        raise PathPolicyError("resolved path escapes workspace") from exc

    # Re-check the resolved relative path so a symlink cannot land inside a
    # denied subtree while using an innocent-looking alias.
    resolved_rel = candidate.relative_to(root_path)
    for part in resolved_rel.parts:
        if is_denied_component(part):
            # The target of a link is a name the caller did not send: refuse, but do not say what it was called.
            raise PathPolicyError("denied resolved path component")
    return candidate


def should_hide_path(root: str | Path, path: Path) -> bool:
    try:
        rel = path.relative_to(Path(root).resolve(strict=True))
    except ValueError:
        return True
    return any(is_denied_component(part) for part in rel.parts)


def is_loopback_host(host: str) -> bool:
    return host in {"127.0.0.1", "::1", "localhost"}
