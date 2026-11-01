"""LaunchAgent definitions: scheduling class and cadence.

launchd's ProcessType decides how the kernel schedules the job. Measured on this host at a load of
about 400 on 16 cores, the same CPU loop took 0.12 s as Interactive, 2.1 s as Standard and did not
finish in 100 s as Background. With ``Background`` the Supervisor and the tunnel were starved behind
the default-priority work of other tenants: health probes timed out, the Doctor timed out, and the
last published verdict was 40 minutes old. The service exists to answer, so it is Interactive.
"""
from __future__ import annotations

import plistlib
from pathlib import Path

import pytest

from universal_agent_middleware import installer as inst
from universal_agent_middleware.supervisor import CYCLE_DEADLINE_SEC

PLISTS = Path(__file__).resolve().parents[1] / "tools/system-service/plists"
AGENTS = ["com.openjay.uam.tunnel.plist", "com.openjay.uam.supervisor.plist"]


def load(name: str) -> dict:
    return plistlib.loads((PLISTS / name).read_bytes())


@pytest.mark.parametrize("name", AGENTS)
def test_every_uam_agent_is_scheduled_as_interactive(name):
    assert load(name)["ProcessType"] == "Interactive"


def test_the_installer_renders_the_scheduling_class_unchanged(tmp_path):
    rendered = inst.render_plists(PLISTS, tmp_path / "out", tmp_path / "home", tmp_path / "uam",
                                  tmp_path / "logs", tmp_path / "uam-runtime.json")
    assert {plistlib.loads(path.read_bytes())["ProcessType"] for path in rendered} == {"Interactive"}


def test_the_supervisor_ticks_no_faster_than_host_policy_and_never_overlaps_its_own_cycle():
    interval = load("com.openjay.uam.supervisor.plist")["StartInterval"]
    assert interval >= 300 and interval > CYCLE_DEADLINE_SEC
