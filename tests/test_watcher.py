from datetime import datetime, timezone
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import secplus_voucher_watcher as w  # noqa: E402

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)
CONFIG = json.loads((Path(__file__).resolve().parents[1] / "config.json").read_text(encoding="utf-8"))


def test_active_free_secplus_voucher_is_candidate():
    text = (
        "Cyber Program 2027: get a free CompTIA Security+ exam voucher (SY0-701). "
        "100% discount on the certification exam. Registration closes January 30, 2027. Apply now."
    )
    result = w.evaluate_offer(text, NOW)
    assert result.is_candidate
    assert result.has_scope
    assert any("Security+" in reason for reason in result.reasons)


def test_partial_discount_is_rejected():
    text = "Save 15% off on your CompTIA Security+ exam voucher. Register today."
    result = w.evaluate_offer(text, NOW)
    assert not result.is_candidate


def test_expired_campaign_is_rejected():
    text = (
        "Free CompTIA Security+ exam voucher for participants. "
        "Registration closed. Applications ended March 1, 2025."
    )
    result = w.evaluate_offer(text, NOW)
    assert not result.is_candidate
    assert result.expired


def test_other_certification_is_rejected():
    text = "Free AWS certification exam voucher, 100% discount. Register now until December 20, 2026."
    result = w.evaluate_offer(text, NOW)
    assert not result.has_scope
    assert not result.is_candidate


def test_paid_reseller_is_rejected():
    text = "CompTIA Security+ exam voucher SY0-701 - free shipping. Add to cart. Buy now."
    result = w.evaluate_offer(text, NOW)
    assert not result.is_candidate


def test_free_training_without_voucher_is_rejected():
    text = "Curso gratuito de preparação para Security+ com inscrição aberta até 10 de dezembro de 2026."
    result = w.evaluate_offer(text, NOW)
    assert not result.is_candidate


def test_any_comptia_exam_voucher_counts_for_secplus():
    text = (
        "Free exam voucher valid for any CompTIA certification exam, 100% discount. "
        "Apply by December 15, 2026."
    )
    result = w.evaluate_offer(text, NOW)
    assert result.has_scope
    assert result.is_candidate
    score, priority, labels, _ = w.generic_career_scope(text, CONFIG)
    assert score > 0 and priority == "alta"
    assert labels == ["Qualquer certificacao CompTIA"]


def test_career_match_detects_secplus_codes():
    score, priority, labels, _ = w.career_match("Exam SY0-701 voucher", CONFIG)
    assert score == 12
    assert priority == "essencial"
    assert labels and "Security+" in labels[0]


def test_normalize_url_strips_tracking():
    url = "https://www.comptia.org/certifications/security/?utm_source=x&gclid=1&lang=pt"
    assert w.normalize_url(url) == "https://www.comptia.org/certifications/security?lang=pt"


def test_blocked_hosts_and_forums():
    assert w._host_is_blocked("https://www.reddit.com/r/CompTIA/comments/abc")
    assert w._host_is_blocked("https://community.comptia.org/t/free-voucher")
    assert not w._host_is_blocked("https://www.comptia.org/certifications/security")


def test_signup_link_prefers_registration_on_trusted_host():
    links = [
        ("Privacy policy", "https://example.org/privacy"),
        ("Apply now", "https://www.perscholas.org/apply"),
        ("Learn more", "https://example.org/about"),
    ]
    url, score = w.rank_signup_link("https://example.org/news", links)
    assert url == "https://www.perscholas.org/apply"
    assert score >= 5
