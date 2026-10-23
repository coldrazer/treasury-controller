"""Configuration: environment variables, policy thresholds and the reserve floor.

Credentials come from the environment (or a local, git-ignored ``.env`` file).
Nothing secret is ever written to this file or logged.

Policy numbers live in code (``PolicyConfig`` here, confidence tiers in
``policy.py``). They are never placed in a model prompt.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlparse

BASE_CURRENCY = "USD"
SANDBOX_BASE_URL = "https://api.sandbox.airwallex.com"
PROJECT_DIR = Path(__file__).resolve().parent
PRODUCTION_HOST = "api.airwallex.com"
# The only hosts this build will hand its x-client-id and x-api-key to. Anything else has to be named
# in the environment by a person who accepts that the credentials travel there.
KNOWN_HOSTS = frozenset({PRODUCTION_HOST, "api.sandbox.airwallex.com", "127.0.0.1", "localhost", "::1"})


# ---------------------------------------------------------------------------
# Policy thresholds (code-owned, never in prompts)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PolicyConfig:
    # Hard line: USD balance net of commitments may never drop below this.
    reserve_floor: Decimal = Decimal("10000.00")
    # Any single payout above this USD-equivalent is routed to a human.
    single_payment_approval_threshold: Decimal = Decimal("15000.00")
    # Flat payout fees in the payout currency. SWIFT EUR fee per builder guide.
    swift_fees: Mapping[str, Decimal] = field(
        default_factory=lambda: MappingProxyType({"EUR": Decimal("12.85")})
    )
    local_fee: Decimal = Decimal("0.00")
    # An approval binds a ceiling on the sell amount: indicative estimate plus
    # this tolerance. A quote above the ceiling needs a fresh approval.
    fx_slippage_tolerance: Decimal = Decimal("0.005")
    approval_ttl_hours: int = 24
    planning_window_hours: int = 72
    deferral_horizon_days: int = 7  # "push to next week"


DEFAULT_POLICY = PolicyConfig()


# ---------------------------------------------------------------------------
# Runtime settings (env driven)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Settings:
    base_url: str
    client_id: str | None = field(default=None, repr=False)
    api_key: str | None = field(default=None, repr=False)
    api_version: str | None = None  # sent on non-FX calls only
    llm_provider: str = "auto"  # auto | anthropic | openai | rules
    llm_model: str = "claude-haiku-5-5"
    anthropic_api_key: str | None = field(default=None, repr=False)
    openai_api_key: str | None = field(default=None, repr=False)
    openai_base_url: str = "https://api.openai.com/v1"
    state_dir: Path = PROJECT_DIR / "state"
    operator: str = "operator"                 # who runs the agent (requests approvals; cannot approve them)
    audit_key: str | None = field(default=None, repr=False)   # TREASURY_AUDIT_KEY (hex/base64, >= 32 bytes)
    screening_list: Path | None = PROJECT_DIR / "fixtures" / "screening_list.json"
    approver_id: str | None = None             # only for unattended --yes runs against the live sandbox
    approver_pin: str | None = field(default=None, repr=False)
    apply_scenario_cash_cap: bool = True
    warnings: tuple[str, ...] = ()

    @property
    def has_airwallex_credentials(self) -> bool:
        return bool(self.client_id and self.api_key)


class ConfigError(RuntimeError):
    pass


def load_dotenv(path: Path | None = None) -> list[str]:
    """Minimal .env loader (no dependency). Existing env vars always win. Returns warnings."""
    path = path or PROJECT_DIR / ".env"
    if not path.is_file():
        return []
    warnings = []
    if os.name == "posix" and path.stat().st_mode & 0o077:
        warnings.append(f"{path} is readable by other users; run: chmod 600 {path}")
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().removeprefix("export ").strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)
    return warnings


def host_of(url: str) -> str:
    """The host as DNS resolves it: a trailing dot is the same origin as the name without it, and the
    scheme's case is not part of the identity either."""
    return (urlparse(url).hostname or "").rstrip(".").lower()


def is_production(url: str) -> bool:
    return host_of(url) == PRODUCTION_HOST


def require_https(url: str, name: str) -> str:
    """Only https, except plain http to this machine (mock sandbox, local model server)."""
    url = url.rstrip("/")
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if parsed.scheme == "https" and host:
        return url
    if parsed.scheme == "http" and host_of(url) in {"127.0.0.1", "localhost", "::1"}:
        return url
    raise ConfigError(f"{name} must be an https URL (got {url!r})")


def validate_base_url(url: str, env: Mapping[str, str]) -> str:
    url = require_https(url, "AWX_BASE_URL")
    host = host_of(url)
    if host == PRODUCTION_HOST and env.get("TREASURY_ALLOW_PRODUCTION") != "1":
        raise ConfigError(
            "Refusing to run against production Airwallex. This build is sandbox-only; "
            "set TREASURY_ALLOW_PRODUCTION=1 only if you really mean it."
        )
    named = host_of("https://" + (env.get("TREASURY_ALLOW_HOST") or ""))
    if host not in KNOWN_HOSTS and host != named:
        raise ConfigError(
            f"AWX_BASE_URL points at {host!r}, which is not a known Airwallex host. The client id and API "
            "key in this environment would be sent there. Point AWX_BASE_URL at the sandbox, or set "
            "TREASURY_ALLOW_HOST to that exact host if you operate the endpoint yourself."
        )
    return url


def _flag(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_settings(env: Mapping[str, str] | None = None, *, use_dotenv: bool = True) -> Settings:
    warnings: list[str] = []
    if env is None:
        if use_dotenv:
            warnings += load_dotenv()
        env = os.environ
    base_url = validate_base_url(env.get("AWX_BASE_URL", SANDBOX_BASE_URL), env)
    provider = env.get("LLM_PROVIDER", "auto").strip().lower()
    if provider not in {"auto", "anthropic", "openai", "rules"}:
        raise ConfigError(f"LLM_PROVIDER must be auto|anthropic|openai|rules (got {provider!r})")
    return Settings(
        base_url=base_url,
        client_id=env.get("AWX_CLIENT_ID") or None,
        api_key=env.get("AWX_API_KEY") or None,
        api_version=env.get("AWX_API_VERSION") or None,
        llm_provider=provider,
        llm_model=env.get("LLM_MODEL") or "claude-haiku-5-5",
        anthropic_api_key=env.get("ANTHROPIC_API_KEY") or None,
        openai_api_key=env.get("OPENAI_API_KEY") or None,
        openai_base_url=require_https(env.get("OPENAI_BASE_URL") or "https://api.openai.com/v1", "OPENAI_BASE_URL"),
        state_dir=Path(env.get("TREASURY_STATE_DIR") or PROJECT_DIR / "state"),
        operator=(env.get("TREASURY_OPERATOR") or _os_user()).strip().lower(),
        audit_key=env.get("TREASURY_AUDIT_KEY") or None,
        screening_list=_screening_path(env.get("TREASURY_SCREENING_LIST")),
        approver_id=env.get("TREASURY_APPROVER_ID") or None,
        approver_pin=env.get("TREASURY_APPROVER_PIN") or None,
        apply_scenario_cash_cap=_flag(env.get("TREASURY_APPLY_CASH_CAP"), True),
        warnings=tuple(warnings),
    )


def _os_user() -> str:
    try:
        import getpass
        return getpass.getuser() or "operator"
    except Exception:  # pragma: no cover - no user database (some containers)
        return "operator"


def _screening_path(value: str | None) -> Path | None:
    if value is None or value == "":
        return PROJECT_DIR / "fixtures" / "screening_list.json"
    if value.strip().lower() in {"off", "none", "0"}:
        return None
    return Path(value)
