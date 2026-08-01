"""Declarative scope policy for routes, actions, and MCP tool catalogs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Sequence, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class ScopeRequirement:
    scopes: frozenset[str]
    mode: str = "all"

    def __post_init__(self) -> None:
        if self.mode not in {"all", "any"}:
            raise ValueError("scope requirement mode must be 'all' or 'any'")
        if not self.scopes:
            raise ValueError("scope requirement must include at least one scope")

    def allows(self, granted: Iterable[str]) -> bool:
        granted_set = set(granted)
        if self.mode == "all":
            return self.scopes.issubset(granted_set)
        return bool(self.scopes.intersection(granted_set))


class ScopePolicyError(PermissionError):
    def __init__(self, action: str, requirement: ScopeRequirement) -> None:
        super().__init__(
            f"'{action}' requires {requirement.mode} of: "
            + " ".join(sorted(requirement.scopes))
        )
        self.action = action
        self.requirement = requirement


def _coerce_requirement(
    value: str | Iterable[str] | ScopeRequirement,
) -> ScopeRequirement:
    if isinstance(value, ScopeRequirement):
        return value
    if isinstance(value, str):
        return ScopeRequirement(frozenset({value}), "all")
    return ScopeRequirement(frozenset(str(scope) for scope in value), "all")


class ScopePolicy:
    """Map operation names to scope requirements and filter visible operations."""

    def __init__(
        self,
        rules: Mapping[str, str | Iterable[str] | ScopeRequirement],
        *,
        default: str | Iterable[str] | ScopeRequirement | None = None,
    ) -> None:
        self._rules = {
            str(action): _coerce_requirement(requirement)
            for action, requirement in rules.items()
        }
        self._default = None if default is None else _coerce_requirement(default)

    def requirement_for(self, action: str) -> ScopeRequirement | None:
        return self._rules.get(action, self._default)

    def allows(self, action: str, granted_scopes: Iterable[str]) -> bool:
        requirement = self.requirement_for(action)
        return requirement is None or requirement.allows(granted_scopes)

    def require(self, action: str, granted_scopes: Iterable[str]) -> None:
        requirement = self.requirement_for(action)
        if requirement is not None and not requirement.allows(granted_scopes):
            raise ScopePolicyError(action, requirement)

    def filter_names(
        self,
        actions: Iterable[str],
        granted_scopes: Iterable[str],
    ) -> list[str]:
        granted = tuple(granted_scopes)
        return [action for action in actions if self.allows(action, granted)]

    def filter_items(
        self,
        items: Sequence[T],
        granted_scopes: Iterable[str],
        *,
        name: Callable[[T], str],
    ) -> list[T]:
        granted = tuple(granted_scopes)
        return [item for item in items if self.allows(name(item), granted)]

    def required_scopes_for(self, action: str) -> frozenset[str]:
        requirement = self.requirement_for(action)
        return frozenset() if requirement is None else requirement.scopes
