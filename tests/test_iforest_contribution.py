"""Regression checks for the normal-diversity/IF ablation path.

These tests do not claim a trained model has already detected an attack. They
ensure the collector provides a legitimate in-envelope UTM attack case that a
density model can be evaluated on, while unsafe XFH and Fat GET primitives stay
outside normal traffic.
"""
from common.features import build_feature_profile, normal_profile_reasons
from traffic.fusion_scenarios import LABS, attack_case, normal_case


def _normal_requests(per_lab=60):
    user_agent = "Mozilla/5.0 Fusion-Test/1.0"
    language = "en-US,en;q=0.9"
    return [
        normal_case(lab, f"{index:024x}", user_agent, language, index).request_dict()
        for lab in LABS
        for index in range(per_lab)
    ]


def test_diverse_normal_traffic_keeps_unsafe_primitives_attack_only():
    requests = _normal_requests()
    # Matched XFH values are legitimate proxy metadata and give the
    # route-local IF normal lexical variation.  The unsafe mismatch remains
    # attack-only; no collector change touches the vulnerable lab itself.
    assert all(
        "X-Forwarded-Host" not in request["headers"]
        or request["headers"]["X-Forwarded-Host"] == request["headers"]["Host"]
        for request in requests
    )
    assert all(not request["body"] for request in requests)


def test_utm_cloaking_attack_is_in_envelope_for_iforest_ablation():
    """The profile should not win solely on a scalar bound in this case.

    The corresponding held-out model evaluation must report whether IF detects
    this in-envelope, low-density combination. Promotion is blocked if it does
    not; the test prevents silently reverting to constant-only normal traffic.
    """
    profile = build_feature_profile(_normal_requests())
    attack = attack_case("utm", "a" * 24, "Mozilla/5.0 Fusion-Test/1.0", "en-US,en;q=0.9", 0)
    assert normal_profile_reasons(attack.request_dict(), profile) == []
