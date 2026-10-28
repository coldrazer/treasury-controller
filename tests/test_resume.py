"""Item 03: deferrals and the autonomous total survive a restart.

A reopened cycle restores both from the store instead of silently resetting them,
so a reschedule after a restart still sees the deferral date the first run set.
"""
from datetime import datetime, timedelta, timezone

from conftest import pin_cycle
from models import State


def test_deferral_survives_restart(make_agent):
    """The reopened run re-triages (the real restart flow) and keeps the original
    deferral date instead of resetting it to now plus the horizon."""
    agent1 = make_agent(cycle_id="test-resume-defer")
    agent1.bootstrap()
    agent1.triage()
    rec = agent1.records[3]
    assert rec.state is State.DEFERRED and rec.deferred_until is not None
    agent2 = make_agent(cycle_id="test-resume-defer")
    agent2.bootstrap()
    agent2.triage()
    assert agent2.records[3].state is State.DEFERRED
    assert agent2.records[3].deferred_until == rec.deferred_until


def test_deferred_reschedules_after_restart(make_agent):
    agent1 = make_agent(cycle_id="test-resume-reschedule")
    agent1.bootstrap()
    agent1.triage()
    due = agent1.records[3].deferred_until
    assert due is not None
    agent2 = make_agent(cycle_id="test-resume-reschedule")
    agent2.bootstrap()
    agent2.triage()
    assert agent2.records[3].deferred_until == due
    agent2._clock = lambda: due + timedelta(days=1)
    results = agent2.reschedule_deferred()
    hit = [r for r in results if r.obligation_id == 3]
    assert hit and hit[0].status == "deferred"
    assert agent2.records[3].deferred_until > due


def test_autonomous_total_survives_restart(make_agent):
    agent1 = make_agent(cycle_id="test-resume-autonomous")
    agent1.bootstrap()
    agent1.triage()
    agent1.execute()
    assert agent1.autonomous_executed > 0
    agent2 = make_agent(cycle_id="test-resume-autonomous")
    assert agent2.autonomous_executed == agent1.autonomous_executed


def test_deferral_cleared_when_funded(make_agent, scenario, simulator):
    agent1 = make_agent(cycle_id="test-resume-funded")
    agent1.bootstrap()
    agent1.triage()
    assert agent1.records[3].state is State.DEFERRED
    dep = scenario.deposit
    simulator.deposit(amount=dep.amount, currency=dep.currency,
                      payer_name=dep.payer_name, reference=dep.reference)
    agent1.on_balance_event(currency=dep.currency, amount=dep.amount,
                            reference=dep.reference, wait_seconds=0)
    assert agent1.records[3].state is State.FUNDED
    assert all(r["obligation_id"] != 3
               for r in agent1.store.deferral_rows("test-resume-funded"))
    agent2 = make_agent(cycle_id="test-resume-funded")
    assert agent2.records[3].deferred_until is None


def test_unknown_deferral_row_dropped(make_agent, store):
    cycle_id = pin_cycle(store, "test-resume-unknown")
    store.save_deferral(cycle_id, 999, datetime.now(timezone.utc) + timedelta(days=7))
    agent = make_agent(cycle_id=cycle_id)
    assert 999 not in agent.records
    assert store.deferral_rows(cycle_id) == []
