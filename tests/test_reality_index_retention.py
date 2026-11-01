"""The snapshot table is a short rollback window, not an ever-growing history.

Only the active generation is read. Before this bound existed every refresh added one full
inventory to ``scope_snapshots`` and nothing ever removed it (3,095 rows, 250 MB in four weeks);
refreshing before every Doctor run would have multiplied that by three.
"""
from __future__ import annotations

import sqlite3
from unittest.mock import patch

import pytest

from universal_agent_middleware.reality_index import (
    SNAPSHOT_HISTORY_KEEP,
    SNAPSHOT_PRUNE_BATCH,
    RealityIndex,
)

POLICY = "policy-v1"


def inventory(marker: int) -> dict:
    return {"scope_root": "/tmp/scope", "projects": [], "total_projects": 0, "marker": marker}


def rows(index: RealityIndex, scope_id: str) -> list[str]:
    with sqlite3.connect(index.db_path) as conn:
        return [generation for (generation,) in conn.execute(
            "SELECT generation_id FROM scope_snapshots WHERE scope_id = ? ORDER BY observed_at", (scope_id,))]


def insert_old_rows(index: RealityIndex, scope_id: str, count: int, *, observed_at: float) -> None:
    with sqlite3.connect(index.db_path) as conn:
        conn.executemany(
            "INSERT INTO scope_snapshots (scope_id, generation_id, policy_generation, observed_at, "
            "git_enriched, snapshot_json, status) VALUES (?, ?, ?, ?, 1, '{}', 'complete')",
            [(scope_id, f"old-{scope_id}-{n}", POLICY, observed_at + n) for n in range(count)])


@pytest.fixture
def index(tmp_path) -> RealityIndex:
    return RealityIndex(tmp_path / "state")


def test_the_history_never_exceeds_its_bound_and_the_newest_snapshot_stays_active(index):
    for marker in range(SNAPSHOT_HISTORY_KEEP + 4):
        generation = index.write_snapshot("scope", inventory(marker), POLICY, git_enriched=True)
        kept = rows(index, "scope")
        assert len(kept) <= SNAPSHOT_HISTORY_KEEP and generation in kept
    assert len(rows(index, "scope")) == SNAPSHOT_HISTORY_KEEP
    active = index.get_active_snapshot("scope", POLICY)
    assert active["marker"] == SNAPSHOT_HISTORY_KEEP + 3 and active["index_generation"] == generation


def test_each_scope_keeps_its_own_history(index):
    for marker in range(SNAPSHOT_HISTORY_KEEP + 3):
        index.write_snapshot("busy", inventory(marker), POLICY, git_enriched=True)
    index.write_snapshot("quiet", inventory(0), POLICY, git_enriched=True)
    assert len(rows(index, "busy")) == SNAPSHOT_HISTORY_KEEP
    assert len(rows(index, "quiet")) == 1


def test_a_table_far_over_the_bound_is_trimmed_in_batches_not_in_one_long_write(index):
    index.write_snapshot("scope", inventory(0), POLICY, git_enriched=True)
    insert_old_rows(index, "scope", 23, observed_at=1.0)
    with patch("universal_agent_middleware.reality_index.SNAPSHOT_PRUNE_BATCH", 5):
        sizes = []
        for marker in range(1, 8):
            index.write_snapshot("scope", inventory(marker), POLICY, git_enriched=True)
            sizes.append(len(rows(index, "scope")))
    assert sizes[0] == 24 + 1 - 5 and sizes == sorted(sizes, reverse=True)
    assert sizes[-1] == SNAPSHOT_HISTORY_KEEP
    assert index.get_active_snapshot("scope", POLICY)["marker"] == 7


def test_the_default_batch_is_large_enough_to_converge_but_small_enough_to_stay_short():
    assert 0 < SNAPSHOT_PRUNE_BATCH <= 1000


def test_the_snapshot_just_written_survives_even_if_its_timestamp_is_the_oldest(index):
    index.write_snapshot("scope", inventory(0), POLICY, git_enriched=True)
    insert_old_rows(index, "scope", 10, observed_at=4_000_000_000.0)
    generation = index.write_snapshot("scope", inventory(1), POLICY, git_enriched=True)
    assert generation in rows(index, "scope")
    assert index.get_active_snapshot("scope", POLICY, allow_stale=True)["marker"] == 1


def test_a_skipped_non_enriched_write_prunes_nothing(index):
    enriched = index.write_snapshot("scope", inventory(0), POLICY, git_enriched=True)
    before = rows(index, "scope")
    assert index.write_snapshot("scope", inventory(1), POLICY, git_enriched=False) == enriched
    assert rows(index, "scope") == before
