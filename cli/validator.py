"""
GAM command validator for the integrated web terminal.

Philosophy:
  The web CLI is not a general shell — it is a GAM-only interface.
  Commands pass through this validator before being executed. Anything
  that isn't a clean GAM invocation is rejected outright.

  If a tech needs true shell access, they SSH in. That's the correct
  escape hatch, and it's an intentionally higher bar.

Rules (applied in order):
  1. Strip leading/trailing whitespace and collapse multiple spaces.
  2. First token must be exactly "gam". No path prefixes, no aliases.
  3. No shell metacharacters: | & ; $ ` > < ( ) { } ! \\ newlines
     These enable command injection, piping, redirection, subshells, etc.
  4. No environment variable assignments (VAR=value gam ...)
  5. Blocklist: a small set of GAM subcommands that are too destructive
     to allow from the web interface even for admins. SSH for these.
  6. Token count sanity check (1–64 tokens).

Returns:
  (True, cleaned_command_string)  if valid
  (False, error_message)          if rejected

Future (v0.4):
  - Per-user command allowlists (some techs get read-only, some get more)
  - Command history per tech per client (stored in DB)
  - LLM-assisted command composition (v0.6-0.8):
      natural language → suggested GAM command → tech reviews → submits
      GamCommands.txt (386KB) is the knowledge base — perfect for RAG
      Key rule: LLM SUGGESTS, human EXECUTES. Never auto-execute.
"""
import re
import shlex
from typing import NamedTuple

# Shell metacharacters that enable injection or redirection
_SHELL_CHARS = re.compile(r'[|&;$`><(){}\\\n!]')

# GAM subcommands too dangerous for web execution.
# This is belt-and-suspenders — the credential tier already limits what
# the underlying OAuth token can do. This blocklist prevents misuse at
# the command layer.
_BLOCKED_SUBCOMMANDS = {
    # Bulk deletion / deprovisioning — too easy to cause mass damage
    "delete",          # gam delete user/group/etc.
    "remove",          # gam remove member/alias/etc.
    "clear",           # gam user X clear/purge
    "purge",
    "deprovision",
    "deprov",
    # Config/oauth — would allow credential replacement
    "oauth",
    "config",
    "rotate",
    # Reporting exports — could exfiltrate PII at scale
    "todrive",
}

# Some subcommands are fine in read-only context but blocked in write
# when issued as bulk (acting on all users, all groups, etc.)
_BULK_TARGETS = {"all_users", "all users", "allusers"}

MAX_TOKENS = 64


class ValidationResult(NamedTuple):
    valid: bool
    value: str   # cleaned command if valid, error message if not


def validate(raw: str) -> ValidationResult:
    """
    Validate and sanitize a raw command string entered in the web terminal.
    Returns ValidationResult(valid=True, value=cleaned) or (False, error).
    """
    cmd = raw.strip()

    if not cmd:
        return ValidationResult(False, "Empty command.")

    # Rule 3: no shell metacharacters
    match = _SHELL_CHARS.search(cmd)
    if match:
        return ValidationResult(
            False,
            f"Shell metacharacter '{match.group()}' is not allowed. "
            "Use SSH for shell access."
        )

    # Rule 4: no env var assignments at start
    if re.match(r'^\s*\w+=', cmd):
        return ValidationResult(False, "Environment variable assignments are not allowed.")

    # Tokenize safely
    try:
        tokens = shlex.split(cmd)
    except ValueError as e:
        return ValidationResult(False, f"Could not parse command: {e}")

    if not tokens:
        return ValidationResult(False, "Empty command.")

    # Rule 6: token count
    if len(tokens) > MAX_TOKENS:
        return ValidationResult(False, f"Command too long ({len(tokens)} tokens, max {MAX_TOKENS}).")

    # Rule 2: first token must be "gam"
    if tokens[0].lower() != "gam":
        return ValidationResult(
            False,
            "Only GAM commands are accepted here. "
            "First token must be 'gam'. Use SSH for shell access."
        )

    # Rule 5: blocked subcommands
    # The subcommand is typically the second token (gam <subcommand> ...)
    # but can be third for "gam user X <verb>" patterns
    lower_tokens = [t.lower() for t in tokens[1:]]
    for i, tok in enumerate(lower_tokens):
        if tok in _BLOCKED_SUBCOMMANDS:
            return ValidationResult(
                False,
                f"The '{tok}' subcommand is not available in the web terminal. "
                "Use SSH for destructive or bulk operations."
            )

    # Bulk target check
    cmd_lower = cmd.lower()
    for bulk in _BULK_TARGETS:
        if bulk in cmd_lower:
            return ValidationResult(
                False,
                "Bulk operations targeting all users/groups are not allowed "
                "from the web terminal. Use SSH."
            )

    # Reconstruct from tokens to normalize whitespace
    cleaned = " ".join(tokens)
    return ValidationResult(True, cleaned)


def validate_and_build_exec(raw: str, gam_path: str, config_dir: str) -> ValidationResult:
    """
    Validate the command and return the full executable form
    (with gam_path substituted for the 'gam' token).
    Safe to pass directly to subprocess.
    """
    result = validate(raw)
    if not result.valid:
        return result
    tokens = shlex.split(result.value)
    # Replace the 'gam' token with the actual binary path
    tokens[0] = gam_path
    return ValidationResult(True, " ".join(tokens))


# ── Standalone test ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    tests = [
        "gam info user test@example.com",
        "gam user test@example.com show forward",
        "gam delete user test@example.com",           # blocked
        "gam user test@example.com | cat /etc/passwd", # shell injection
        "ls -la",                                      # not gam
        "gam oauth create",                            # blocked
        "gam update user test@example.com suspended on",
        "",                                            # empty
    ]
    for t in tests:
        r = validate(t)
        status = "OK " if r.valid else "BLOCKED"
        print(f"{status}  {t!r:<55}  → {r.value}")
