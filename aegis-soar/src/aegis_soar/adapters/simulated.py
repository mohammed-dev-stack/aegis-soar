from __future__ import annotations

import asyncio
import enum
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Protocol
from uuid import UUID


class AdapterState(enum.StrEnum):
    NOT_FOUND = "NOT_FOUND"
    APPLIED = "APPLIED"
    ROLLED_BACK = "ROLLED_BACK"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class AdapterResult:
    state: AdapterState
    ref: str
    detail: str = ""


class SimulatedAdapterCrashError(RuntimeError):
    """Injected fault simulating worker crash immediately after adapter.apply()."""


class ResponseAdapter(Protocol):
    """Idempotent external containment adapter protocol (NG-1, INV-7)."""

    async def apply(
        self,
        action_id: UUID,
        action_type: str,
        target_ip: IPv4Address | IPv6Address,
    ) -> AdapterResult: ...

    async def rollback(self, action_id: UUID) -> AdapterResult: ...

    async def get_state(self, action_id: UUID) -> AdapterState: ...


class SimulatedResponseAdapter:
    """In-memory, async-safe, strictly idempotent simulated ResponseAdapter (NG-1)."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._states: dict[UUID, AdapterState] = {}
        self._refs: dict[UUID, str] = {}
        self.apply_calls: dict[UUID, int] = {}
        self.rollback_calls: dict[UUID, int] = {}
        # Fault-injection hooks for Gate G5 crash reconciliation tests
        self.fail_apply_ids: set[UUID] = set()
        self.crash_after_apply_ids: set[UUID] = set()
        self.fail_rollback_ids: set[UUID] = set()

    async def apply(
        self,
        action_id: UUID,
        action_type: str,
        target_ip: IPv4Address | IPv6Address,
    ) -> AdapterResult:
        async with self._lock:
            self.apply_calls[action_id] = self.apply_calls.get(action_id, 0) + 1
            existing = self._states.get(action_id)
            if existing == AdapterState.APPLIED:
                return AdapterResult(
                    state=AdapterState.APPLIED,
                    ref=self._refs[action_id],
                    detail="idempotent_replay",
                )

            if action_id in self.fail_apply_ids:
                self._states[action_id] = AdapterState.FAILED
                return AdapterResult(
                    state=AdapterState.FAILED,
                    ref="",
                    detail="simulated_apply_failure",
                )

            ref = f"sim:{action_type}:{target_ip}:{action_id}"
            self._states[action_id] = AdapterState.APPLIED
            self._refs[action_id] = ref

            if action_id in self.crash_after_apply_ids:
                self.crash_after_apply_ids.remove(action_id)
                raise SimulatedAdapterCrashError(f"Simulated worker crash after apply({action_id})")

            return AdapterResult(state=AdapterState.APPLIED, ref=ref)

    async def rollback(self, action_id: UUID) -> AdapterResult:
        async with self._lock:
            self.rollback_calls[action_id] = self.rollback_calls.get(action_id, 0) + 1
            existing = self._states.get(action_id)
            if existing == AdapterState.ROLLED_BACK:
                return AdapterResult(
                    state=AdapterState.ROLLED_BACK,
                    ref=self._refs.get(action_id, ""),
                    detail="idempotent_replay",
                )

            if action_id in self.fail_rollback_ids:
                self._states[action_id] = AdapterState.FAILED
                return AdapterResult(
                    state=AdapterState.FAILED,
                    ref=self._refs.get(action_id, ""),
                    detail="simulated_rollback_failure",
                )

            self._states[action_id] = AdapterState.ROLLED_BACK
            return AdapterResult(
                state=AdapterState.ROLLED_BACK,
                ref=self._refs.get(action_id, ""),
            )

    async def get_state(self, action_id: UUID) -> AdapterState:
        async with self._lock:
            return self._states.get(action_id, AdapterState.NOT_FOUND)
