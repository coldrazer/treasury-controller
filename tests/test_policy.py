"""The four decision rules as pure functions."""
import random
from decimal import Decimal

import pytest

import policy as P
from config import DEFAULT_POLICY
from models import Action, Obligation

D = Decimal
RATES = {"EUR": D("1.085"), "GBP": D("1.27")}


def ob(i, amount, cur, **kw):
    base = dict(id=i, name=f"ob{i}", counterparty=f"cp{i}", amount=D(amount), currency=cur, due_in_hours=48,
                category="time_sensitive", deferrable=False, deferral_penalty_usd=D("100"),
                payout_method="LOCAL", payout_country="US", reference=f"R{i}")
    base.update(kw)
    return Obligation(**base)


def scenario_obs(scenario):
    return list(scenario.obligations)


def ctx(headroom, held=None, confidence="0.92"):
    return P.PlanContext(headroom=D(headroom), held=held or {"EUR": D("500"), "GBP": D("0")},
                         usd_per_unit=RATES, confidence=D(confidence))


# --- building blocks -------------------------------------------------------
@pytest.mark.parametrize("conf,limit", [("0.95", "15000"), ("0.80", "15000"), ("0.79", "5000"),
                                        ("0.50", "5000"), ("0.49", "2500"), ("0", "2500")])
def test_autonomous_limit_tiers(conf, limit):
    assert P.autonomous_fx_limit(D(conf)) == D(limit)


def test_limit_rejects_out_of_range_confidence():
    with pytest.raises(P.PolicyError):
        P.autonomous_fx_limit(D("1.2"))


def test_swift_fee_included_and_local_free():
    eur = ob(2, "12000", "EUR", payout_method="SWIFT", payout_country="DE")
    assert P.gross_need(eur, DEFAULT_POLICY) == D("12012.85")
    assert P.gross_need(ob(1, "8500", "USD"), DEFAULT_POLICY) == D("8500.00")


def test_unknown_swift_fee_refuses_to_guess():
    gbp_swift = ob(4, "100", "GBP", payout_method="SWIFT")
    with pytest.raises(P.UnknownFeeError):
        P.gross_need(gbp_swift, DEFAULT_POLICY)


def test_fx_requirement_buys_only_the_minimum():
    eur = ob(2, "12000", "EUR", payout_method="SWIFT", payout_country="DE")
    need = P.fx_requirement(eur, D("500"), D("1.085"), DEFAULT_POLICY)
    assert need.buy_amount == D("11512.85")          # 12,000 + 12.85 fee - 500 held
    assert need.held_used == D("500.00")
    assert need.est_sell_amount == D("12491.45")     # rounded UP, never under-estimated


def test_fx_requirement_with_enough_held_buys_nothing():
    eur = ob(2, "100", "EUR", payout_method="SWIFT")
    need = P.fx_requirement(eur, D("1000"), D("1.085"), DEFAULT_POLICY)
    assert need.buy_amount == 0 and need.est_sell_amount == 0 and need.held_used == D("112.85")


def test_select_deferrals_cheapest_first():
    a = ob(1, "1200", "USD", deferrable=True, deferral_penalty_usd=D("0"))
    b = ob(2, "500", "USD", deferrable=True, deferral_penalty_usd=D("50"))
    assert P.select_deferrals([(b, D("500")), (a, D("1200"))], D("100")) == [1]
    assert P.select_deferrals([(b, D("500")), (a, D("1200"))], D("1500")) == [1, 2]
    assert P.select_deferrals([(a, D("1200"))], D("0")) == []


def test_reserve_ok_is_inclusive_at_floor():
    assert P.reserve_ok(D("20000"), D("10000"), DEFAULT_POLICY)
    assert not P.reserve_ok(D("19999.99"), D("10000"), DEFAULT_POLICY)


def test_requires_fx_approval():
    assert not P.requires_fx_approval(D("12491.45"), D("0.92"))
    assert P.requires_fx_approval(D("12491.45"), D("0.37"))


# --- the scenario, rule by rule ----------------------------------------------
def test_scenario_plan_makes_four_different_decisions(scenario):
    plan = P.plan(scenario_obs(scenario), ctx("27500"), DEFAULT_POLICY)
    assert {i: d.action for i, d in plan.items()} == {
        1: Action.FUND, 2: Action.CONVERT, 3: Action.DEFER, 4: Action.ESCALATE, 5: Action.FUND}
    assert plan[1].rule == "R1_FUND_OPERATIONS_CRITICAL"
    assert plan[5].rule == "R2_FUND_FIXED"
    assert plan[2].rule == "R3_CONVERT_MINIMUM" and not plan[2].requires_approval
    assert plan[3].rule == "R4_DEFER_CHEAPEST" and plan[3].cash_constrained
    assert plan[4].rule == "R5_ESCALATE_THRESHOLD" and plan[4].funding_gap > 0 and plan[4].cash_constrained
    used = sum(d.usd_draw for d in plan.values())
    assert used == D("26991.45") and used <= D("27500")


def test_low_confidence_gates_the_same_conversion(scenario):
    plan = P.plan(scenario_obs(scenario), ctx("27500", confidence="0.37"), DEFAULT_POLICY)
    assert plan[2].action is Action.CONVERT and plan[2].requires_approval


def test_threshold_escalation_never_splits_and_holds_cash_when_fundable(scenario):
    plan = P.plan(scenario_obs(scenario), ctx("100000"), DEFAULT_POLICY)
    assert plan[4].action is Action.ESCALATE
    assert plan[4].usd_draw == D("19050.00") and plan[4].funding_gap == 0 and not plan[4].cash_constrained
    assert plan[3].action is Action.FUND  # no shortfall, nothing deferred


def test_subset_replan_after_deposit(scenario):
    obs = {o.id: o for o in scenario.obligations}
    plan = P.plan([obs[3], obs[4]], ctx("25508.55"), DEFAULT_POLICY)
    assert plan[3].action is Action.FUND
    assert plan[4].action is Action.ESCALATE and plan[4].usd_draw == D("19050.00")


def test_non_deferrable_shortfall_escalates():
    a = ob(1, "9000", "USD", category="operations_critical")
    b = ob(2, "5000", "USD", category="fixed")
    plan = P.plan([a, b], ctx("10000"), DEFAULT_POLICY)
    assert plan[1].action is Action.FUND
    assert plan[2].action is Action.ESCALATE and plan[2].rule == "R6_ESCALATE_SHORTFALL"


def test_negative_headroom_funds_nothing(scenario):
    plan = P.plan(scenario_obs(scenario), ctx("-500"), DEFAULT_POLICY)
    assert all(d.usd_draw == 0 for d in plan.values())


def test_plan_never_draws_more_than_headroom_randomised(scenario):
    rng = random.Random(7)
    for _ in range(300):
        obs = []
        for i in range(1, rng.randint(2, 7)):
            cur = rng.choice(["USD", "USD", "EUR", "GBP"])
            obs.append(ob(i, str(rng.randint(100, 30000)), cur,
                          category=rng.choice(list(P.PRIORITY)), deferrable=rng.random() < 0.4,
                          deferral_penalty_usd=D(rng.randint(0, 3000)),
                          payout_method="SWIFT" if cur == "EUR" and rng.random() < .5 else "LOCAL"))
        headroom = D(rng.randint(-2000, 60000))
        held = {"EUR": D(rng.randint(0, 5000)), "GBP": D(rng.randint(0, 5000))}
        plan = P.plan(obs, P.PlanContext(headroom, held, RATES, D(rng.choice(["0.3", "0.6", "0.9"]))),
                      DEFAULT_POLICY)
        assert set(plan) == {o.id for o in obs}
        drawn = sum(d.usd_draw for d in plan.values())
        assert drawn <= max(headroom, D(0)), (headroom, drawn)
        for cur in ("EUR", "GBP"):
            assert sum(d.held_draw for d in plan.values() if d.fx and d.fx.buy_currency == cur) <= held[cur]
        for d in plan.values():
            if d.action is Action.ESCALATE and d.rule == "R5_ESCALATE_THRESHOLD":
                assert d.usd_equivalent > DEFAULT_POLICY.single_payment_approval_threshold
            if d.action in (Action.FUND, Action.CONVERT):
                assert d.usd_equivalent <= DEFAULT_POLICY.single_payment_approval_threshold


def test_thresholds_are_code_not_prompt():
    import email_reader
    import explainer
    text = email_reader.SYSTEM_PROMPT + explainer.SYSTEM
    for number in ("15000", "15,000", "10000", "10,000", "2500", "2,500", "0.80", "0.5"):
        assert number not in text
