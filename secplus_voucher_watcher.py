#!/usr/bin/env python3
"""Monitor the web for active 100% free CompTIA Security+ exam vouchers.

The watcher searches the web through Tavily, applies conservative heuristics to
reject partial discounts, paid resellers, expired campaigns, discussion pages and
study-material offers, then ranks opportunities against a configurable career
profile focused on cybersecurity (CompTIA Security+, SY0-701 / SY0-801).
It sends only new, relevant opportunities by email and/or Telegram and is designed
to run on a GitHub Actions schedule.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import logging
import os
import re
import smtplib
import ssl
import sys
import unicodedata
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from zoneinfo import ZoneInfo

import requests

LOGGER = logging.getLogger("secplus-voucher-watcher")
DEFAULT_CONFIG = Path(__file__).with_name("config.json")
DEFAULT_STATE = Path(__file__).with_name("data") / "seen.json"
TAVILY_SEARCH_URL = "https://api.tavily.com/search"
TRACKING_QUERY_PREFIXES = ("utm_",)
TRACKING_QUERY_KEYS = {
    "fbclid",
    "gclid",
    "dclid",
    "msclkid",
    "mc_cid",
    "mc_eid",
    "ref",
    "source",
    "campaign",
}


@dataclass(slots=True)
class SearchHit:
    title: str
    url: str
    content: str = ""
    raw_content: str = ""
    score: float = 0.0
    published_date: str | None = None


@dataclass(slots=True)
class DateSignal:
    value: date
    context: str
    is_deadline: bool
    is_registration: bool = False
    is_redemption: bool = False


@dataclass(slots=True)
class Evaluation:
    score: int
    is_candidate: bool
    expired: bool
    has_scope: bool
    has_strong_offer: bool
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    dates: list[DateSignal] = field(default_factory=list)


@dataclass(slots=True)
class Candidate:
    title: str
    source_url: str
    signup_url: str
    confidence: str
    score: int
    reasons: list[str]
    warnings: list[str]
    evidence: list[str]
    excerpt: str
    future_dates: list[str]
    fingerprint: str
    career_priority: str = ""
    matched_certifications: list[str] = field(default_factory=list)
    career_reason: str = ""


class PageParser(HTMLParser):
    """Small HTML parser that extracts readable text and links without JS."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text_parts: list[str] = []
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._anchor_text: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "noscript", "svg"}:
            self._ignored_depth += 1
            return
        if self._ignored_depth:
            return
        if tag == "a":
            attr_map = {key.lower(): value for key, value in attrs}
            self._href = attr_map.get("href")
            self._anchor_text = []
        if tag in {"p", "br", "li", "div", "section", "article", "h1", "h2", "h3"}:
            self.text_parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "noscript", "svg"}:
            if self._ignored_depth:
                self._ignored_depth -= 1
            return
        if self._ignored_depth:
            return
        if tag == "a" and self._href:
            text = clean_space(" ".join(self._anchor_text))
            self.links.append((text, self._href))
            self._href = None
            self._anchor_text = []

    def handle_data(self, data: str) -> None:
        if self._ignored_depth:
            return
        text = clean_space(data)
        if not text:
            return
        self.text_parts.append(text)
        if self._href is not None:
            self._anchor_text.append(text)

    @property
    def text(self) -> str:
        return clean_space(" ".join(self.text_parts))


def clean_space(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def fold_text(value: str) -> str:
    value = unicodedata.normalize("NFKD", value or "")
    value = "".join(ch for ch in value if not unicodedata.combining(ch))
    return clean_space(value).lower()


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "sim", "on"}


def env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} precisa ser um número inteiro") from exc


def now_local() -> datetime:
    timezone_name = os.getenv("WATCHER_TIMEZONE", "America/Sao_Paulo")
    try:
        return datetime.now(ZoneInfo(timezone_name))
    except Exception:
        LOGGER.warning("Fuso %s inválido; usando UTC", timezone_name)
        return datetime.now(timezone.utc)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Não foi possível ler {path}: {exc}") from exc


def save_json_atomic(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def normalize_url(value: str) -> str:
    if not value:
        return ""
    try:
        split = urlsplit(value.strip())
    except ValueError:
        return value.strip()
    if split.scheme not in {"http", "https"}:
        return value.strip()
    host = split.netloc.lower()
    if host.endswith(":80") and split.scheme == "http":
        host = host[:-3]
    if host.endswith(":443") and split.scheme == "https":
        host = host[:-4]
    filtered_query: list[tuple[str, str]] = []
    for key, val in parse_qsl(split.query, keep_blank_values=True):
        lowered = key.lower()
        if lowered.startswith(TRACKING_QUERY_PREFIXES) or lowered in TRACKING_QUERY_KEYS:
            continue
        filtered_query.append((key, val))
    path = re.sub(r"/{2,}", "/", split.path or "/")
    if path != "/":
        path = path.rstrip("/")
    return urlunsplit((split.scheme.lower(), host, path, urlencode(filtered_query), ""))


def unique_hits(hits: Iterable[SearchHit]) -> list[SearchHit]:
    merged: dict[str, SearchHit] = {}
    for hit in hits:
        key = normalize_url(hit.url)
        if not key:
            continue
        existing = merged.get(key)
        if existing is None:
            hit.url = key
            merged[key] = hit
            continue
        if len(hit.raw_content) > len(existing.raw_content):
            existing.raw_content = hit.raw_content
        if len(hit.content) > len(existing.content):
            existing.content = hit.content
        existing.score = max(existing.score, hit.score)
        if not existing.published_date:
            existing.published_date = hit.published_date
    return list(merged.values())


def search_tavily(api_key: str, query: str, config: dict[str, Any]) -> list[SearchHit]:
    payload: dict[str, Any] = {
        "query": query,
        "search_depth": config.get("search_depth", "basic"),
        "chunks_per_source": int(config.get("chunks_per_source", 3)),
        "max_results": int(config.get("max_results_per_query", 8)),
        "topic": "general",
        "time_range": config.get("time_range", "year"),
        "include_answer": False,
        "include_raw_content": "text",
        "include_images": False,
        "include_usage": True,
    }
    country = config.get("country")
    if country:
        payload["country"] = country
    response = requests.post(
        TAVILY_SEARCH_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "secplus-voucher-watcher/1.0",
        },
        json=payload,
        timeout=env_int("SEARCH_TIMEOUT_SECONDS", 45),
    )
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        body = clean_space(response.text)[:500]
        raise RuntimeError(f"Falha na busca Tavily ({response.status_code}): {body}") from exc
    data = response.json()
    usage = data.get("usage") or {}
    if usage:
        LOGGER.info("Consulta consumiu %s crédito(s)", usage.get("credits", "?"))
    results: list[SearchHit] = []
    for item in data.get("results", []):
        url = clean_space(str(item.get("url", "")))
        if not url:
            continue
        results.append(
            SearchHit(
                title=clean_space(str(item.get("title", "Sem título"))),
                url=url,
                content=clean_space(str(item.get("content", ""))),
                raw_content=clean_space(str(item.get("raw_content", "") or "")),
                score=float(item.get("score", 0.0) or 0.0),
                published_date=item.get("published_date"),
            )
        )
    return results


def fetch_page(url: str) -> tuple[str, list[tuple[str, str]], str]:
    """Return plain text, links and final URL. Network failures are non-fatal."""
    try:
        response = requests.get(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (compatible; SecPlusVoucherWatcher/1.0; "
                    "+https://github.com/)"
                ),
                "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
            },
            timeout=env_int("PAGE_TIMEOUT_SECONDS", 20),
            allow_redirects=True,
            stream=True,
        )
        response.raise_for_status()
        content_type = response.headers.get("Content-Type", "").lower()
        if "html" not in content_type and "text" not in content_type:
            return "", [], normalize_url(response.url)
        max_bytes = env_int("MAX_PAGE_BYTES", 2_000_000)
        chunks: list[bytes] = []
        size = 0
        for chunk in response.iter_content(chunk_size=65536):
            if not chunk:
                continue
            remaining = max_bytes - size
            if remaining <= 0:
                break
            chunks.append(chunk[:remaining])
            size += min(len(chunk), remaining)
        raw = b"".join(chunks)
        encoding = response.encoding or "utf-8"
        body = raw.decode(encoding, errors="replace")
        parser = PageParser()
        parser.feed(body)
        links: list[tuple[str, str]] = []
        for text, href in parser.links:
            absolute = normalize_url(urljoin(response.url, href))
            if absolute.startswith(("http://", "https://")):
                links.append((text, absolute))
        return parser.text, links, normalize_url(response.url)
    except (requests.RequestException, ValueError, UnicodeError) as exc:
        LOGGER.debug("Não foi possível abrir %s: %s", url, exc)
        return "", [], normalize_url(url)


# Security+ exam codes: SY0-601 (retired), SY0-701 (current), SY0-801 (next).
SECPLUS_CODE_RE = re.compile(r"\bsy0\s*-\s*\d{3}\b", re.IGNORECASE)

BLOCKED_SOURCE_HOSTS = (
    "youtube.com", "youtu.be", "reddit.com", "facebook.com", "instagram.com",
    "tiktok.com", "x.com", "twitter.com",
    # Exam-dump / prep marketplaces are not voucher issuers. Their "free exam"
    # wording usually refers to study material, not a free certification attempt.
    "examtopics.com", "examcollection.com", "exam-labs.com", "pass4sure.com",
    "testking.com", "actual4test.com", "examcompass.com", "crucialexams.com",
    "quizlet.com",
)
BLOCKED_SOURCE_PATHS = ("/answers/", "/questions/", "/q/", "/forum/")
QUESTION_STYLE_RE = re.compile(
    r"\b(?:how (?:do|can) i|get a free voucher|where can i|get free voucher|como (?:consigo|obter)|"
    r"onde (?:consigo|achar)|voucher question|free voucher question)\b", re.IGNORECASE
)
SPECULATIVE_RE = re.compile(
    r"\b(?:may offer|might offer|can offer|could offer|keep an eye|watch for upcoming|"
    r"fique atento|podem oferecer|pode oferecer|talvez ofereca|talvez ofereça)\b", re.IGNORECASE
)
STUDY_MATERIAL_RE = re.compile(
    r"\b(?:exam material|certification exam material|study material|study guide|exam prep|"
    r"practice questions?|practice tests?|exam questions?|exam dumps?|braindumps?|dumps?|"
    r"questions and answers|q\s*&\s*a|mock exam|sample questions?|premium access|"
    r"material de estudo|material para prova|preparacao para exame|preparação para exame|"
    r"questoes? de prova|questões? de prova|simulados?|banco de questoes|banco de questões)\b",
    re.IGNORECASE,
)
STRONG_OFFER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "menciona desconto de 100%",
        re.compile(r"\b100\s*%\s*(?:off|discount|desconto|de desconto)\b", re.IGNORECASE),
    ),
    (
        "menciona voucher de exame gratuito",
        re.compile(
            r"\b(?:free|gratuit[oa]|sem custo|no cost|complimentary)\b.{0,80}"
            r"\b(?:exam(?:ination)?|exame|certification|certificacao)\b.{0,50}\b(?:voucher|cupom)\b"
            r"|\b(?:exam(?:ination)?|exame|certification|certificacao)\b.{0,50}\b(?:voucher|cupom)\b.{0,80}"
            r"\b(?:free|gratuit[oa]|sem custo|no cost|complimentary|100\s*%)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "declara exame de certificação sem custo",
        re.compile(
            r"\b(?:free|gratuit[oa]|sem custo|no cost|complimentary)\b.{0,70}"
            r"\b(?:certification exam|exam voucher|exame de certificacao|voucher de exame)\b",
            re.IGNORECASE,
        ),
    ),
]
WEAK_OFFER_RE = re.compile(
    r"\b(?:voucher|exam voucher|voucher de exame|certification voucher|cupom)\b",
    re.IGNORECASE,
)
SECPLUS_RE = re.compile(r"\bsecurity\s*(?:\+|plus\b)|\bsec\s*\+", re.IGNORECASE)
COMPTIA_RE = re.compile(r"\bcomptia\b", re.IGNORECASE)
COMPTIA_CERT_RE = re.compile(
    r"\b(?:comptia certification|comptia certified|certificacao comptia|certificação comptia)\b",
    re.IGNORECASE,
)
# Paid offers from resellers: "buy", "add to cart" or a list price next to the voucher.
PAID_OFFER_RE = re.compile(
    r"\b(?:add to cart|buy now|comprar agora|adicionar ao carrinho|checkout)\b",
    re.IGNORECASE,
)
SIGNUP_TERMS_RE = re.compile(
    r"\b(?:register|registration|sign up|apply now|enroll|enrol|inscrev[ae]|inscricao|inscrição|"
    r"cadastre-se|participe|claim voucher|obter voucher|garanta sua vaga)\b",
    re.IGNORECASE,
)
PARTIAL_DISCOUNT_RE = re.compile(
    r"\b(?:[1-9]\d?|(?:1[0-9]{2}|[2-9]\d{2}))\s*%\s*(?:off|discount|desconto)\b",
    re.IGNORECASE,
)
EXPIRED_RE = re.compile(
    r"\b(?:expired|offer ended|promotion ended|registration closed|registrations? closed|"
    r"no longer available|voucher(?:s)? exhausted|sold out|encerrad[oa]s?|expirad[oa]s?|"
    r"inscricoes encerradas|inscrições encerradas|vouchers? esgotados?|prazo encerrado|"
    r"nao esta mais disponivel|não está mais disponível)\b",
    re.IGNORECASE,
)
FREE_TRAINING_ONLY_RE = re.compile(
    r"\b(?:free training|free course|curso gratuito|treinamento gratuito|formacao gratuita|"
    r"formação gratuita|bootcamp gratuito)\b",
    re.IGNORECASE,
)
NON_VOUCHER_RE = re.compile(
    r"\b(?:practice assessment|practice exam|simulado gratuito|free retake|segunda tentativa gratuita|"
    r"certification renewal|renovacao gratuita|renovação gratuita)\b",
    re.IGNORECASE,
)
DEADLINE_CUE_RE = re.compile(
    r"(?:expires?|expiration|valid until|valid through|redeem.{0,40}\bby|use by|deadline|"
    r"registration closes?|offer ends?|voucher ends?|expira|expiracao|expiração|"
    r"valido ate|válido até|resgatar.{0,40}\b(?:ate|até)|usar ate|usar até|"
    r"inscricoes ate|inscrições até|prazo|encerra em|termina em)"
    r".{0,120}",
    re.IGNORECASE,
)
EVENT_DATE_CUE_RE = re.compile(
    r"(?:event dates?|training dates?|certification week|data do evento|datas do evento|"
    r"semana de certificacao|semana de certificação|acontece de|realizado de|join us|"
    r"participe de|active period|periodo ativo|período ativo)"
    r".{0,140}",
    re.IGNORECASE,
)
REGISTRATION_CONTEXT_RE = re.compile(
    r"\b(?:registration|register|sign up|apply|enroll|enrol|participat|complete by|challenge ends?|"
    r"inscri[cç][aã]o|inscrev|cadastre|participe|concluir ate|concluir até|periodo ativo|período ativo)\b",
    re.IGNORECASE,
)
REDEMPTION_CONTEXT_RE = re.compile(
    r"\b(?:redeem|redemption|use by|valid until|valid through|voucher expires?|claim by|"
    r"resgatar|resgate|usar ate|usar até|valido ate|válido até|voucher expira)\b",
    re.IGNORECASE,
)
ANY_COMPTIA_EXAM_RE = re.compile(
    r"\b(?:any comptia (?:certification )?exam|any comptia certification|"
    r"qualquer exame (?:de certificacao )?(?:da )?comptia|qualquer certificacao (?:da )?comptia|"
    r"todos os exames (?:de certificacao )?(?:da )?comptia)\b",
    re.IGNORECASE,
)
GENERIC_COMPTIA_VOUCHER_RE = re.compile(
    r"\b(?:comptia (?:certification |exam )?(?:exam )?voucher|"
    r"voucher (?:gratuito )?(?:para (?:o |um )?exame )?(?:da )?comptia|"
    r"voucher de exame (?:da )?comptia)\b",
    re.IGNORECASE,
)


MONTH_NUMBERS = {
    # English
    "january": 1, "jan": 1,
    "february": 2, "feb": 2,
    "march": 3, "mar": 3,
    "april": 4, "apr": 4,
    "may": 5,
    "june": 6, "jun": 6,
    "july": 7, "jul": 7,
    "august": 8, "aug": 8,
    "september": 9, "sep": 9, "sept": 9,
    "october": 10, "oct": 10,
    "november": 11, "nov": 11,
    "december": 12, "dec": 12,
    # Portuguese
    "janeiro": 1,
    "fevereiro": 2, "fev": 2,
    "marco": 3,
    "abril": 4, "abr": 4,
    "maio": 5, "mai": 5,
    "junho": 6,
    "julho": 7,
    "agosto": 8, "ago": 8,
    "setembro": 9, "set": 9,
    "outubro": 10, "out": 10,
    "novembro": 11,
    "dezembro": 12, "dez": 12,
    # Spanish
    "enero": 1, "ene": 1,
    "febrero": 2,
    "marzo": 3,
    "mayo": 5,
    "junio": 6,
    "julio": 7,
    "septiembre": 9,
    "octubre": 10,
    "noviembre": 11,
    "diciembre": 12, "dic": 12,
}
MONTH_PATTERN = "|".join(sorted((re.escape(item) for item in MONTH_NUMBERS), key=len, reverse=True))


def _safe_date(year: int, month: int, day: int) -> date | None:
    try:
        return date(year, month, day)
    except ValueError:
        return None


def _date_spans_in_text(value: str) -> list[tuple[date, int, int]]:
    """Extract explicit dates together with their character spans."""
    folded = fold_text(value)
    found: list[tuple[date, int, int]] = []
    seen: set[tuple[date, int, int]] = set()

    def add(parsed: date | None, match: re.Match[str]) -> None:
        if not parsed:
            return
        item = (parsed, match.start(), match.end())
        if item not in seen:
            seen.add(item)
            found.append(item)

    for match in re.finditer(r"\b(20\d{2})-(\d{1,2})-(\d{1,2})\b", folded):
        add(_safe_date(int(match.group(1)), int(match.group(2)), int(match.group(3))), match)

    for match in re.finditer(r"\b(\d{1,2})[/.](\d{1,2})[/.](20\d{2})\b", folded):
        first, second, year = map(int, match.groups())
        parsed = _safe_date(year, second, first)
        if not parsed:
            parsed = _safe_date(year, first, second)
        add(parsed, match)

    day_month_year = re.compile(
        rf"\b(\d{{1,2}})(?:st|nd|rd|th)?(?:\s*(?:-|–|—|a|to)\s*\d{{1,2}})?"
        rf"\s*(?:de\s+)?({MONTH_PATTERN})(?:\s+de|,)?\s+(20\d{{2}})\b"
    )
    for match in day_month_year.finditer(folded):
        add(_safe_date(int(match.group(3)), MONTH_NUMBERS[match.group(2)], int(match.group(1))), match)

    month_day_year = re.compile(
        rf"\b({MONTH_PATTERN})\s+(\d{{1,2}})(?:st|nd|rd|th)?"
        rf"(?:\s*(?:-|–|—|to)\s*\d{{1,2}}(?:st|nd|rd|th)?)?[,]?\s+(20\d{{2}})\b"
    )
    for match in month_day_year.finditer(folded):
        add(_safe_date(int(match.group(3)), MONTH_NUMBERS[match.group(1)], int(match.group(2))), match)

    range_day_month = re.compile(
        rf"\b\d{{1,2}}\s*(?:-|–|—|a|to)\s*(\d{{1,2}})"
        rf"\s*(?:de\s+)?({MONTH_PATTERN})(?:\s+de|,)?\s+(20\d{{2}})\b"
    )
    for match in range_day_month.finditer(folded):
        add(_safe_date(int(match.group(3)), MONTH_NUMBERS[match.group(2)], int(match.group(1))), match)

    range_month_day = re.compile(
        rf"\b({MONTH_PATTERN})\s+\d{{1,2}}(?:st|nd|rd|th)?\s*(?:-|–|—|to)\s*"
        rf"(\d{{1,2}})(?:st|nd|rd|th)?[,]?\s+(20\d{{2}})\b"
    )
    for match in range_month_day.finditer(folded):
        add(_safe_date(int(match.group(3)), MONTH_NUMBERS[match.group(1)], int(match.group(2))), match)

    return sorted(found, key=lambda item: (item[1], item[0]))


def _parse_date_windows(text: str, now: datetime) -> list[DateSignal]:
    signals: list[DateSignal] = []
    seen: set[tuple[date, bool, bool, bool]] = set()
    folded = fold_text(text)
    for parsed_date, start, end in _date_spans_in_text(text):
        if parsed_date.year < now.year - 12 or parsed_date.year > now.year + 4:
            continue
        prefix = folded[max(0, start - 140):end]
        suffix = folded[end:min(len(folded), end + 70)]
        context = text[max(0, start - 100):min(len(text), end + 100)]

        is_redemption = bool(REDEMPTION_CONTEXT_RE.search(prefix))
        is_registration = bool(REGISTRATION_CONTEXT_RE.search(prefix))
        if re.search(r"\b(?:registration|inscri[cç][aã]o)\s+(?:deadline|closes?|encerra|ate|até)\b", suffix):
            is_registration = True
        if re.search(r"\b(?:redemption|resgate|voucher)\s+(?:deadline|expires?|expira)\b", suffix):
            is_redemption = True
        is_deadline = bool(DEADLINE_CUE_RE.search(prefix)) or bool(
            re.search(r"\b(?:deadline|prazo|expires?|expira)\b", suffix)
        )
        if is_redemption:
            # A nearby generic "register now" must not turn a redemption date into a registration date.
            is_registration = False

        key = (parsed_date, is_deadline, is_registration, is_redemption)
        if key in seen:
            continue
        seen.add(key)
        signals.append(
            DateSignal(
                parsed_date,
                clean_space(context)[:200],
                is_deadline,
                is_registration,
                is_redemption,
            )
        )
    return sorted(signals, key=lambda item: item.value)


def parse_explicit_date(value: str | None) -> date | None:
    if not value:
        return None
    cleaned = clean_space(value)
    try:
        parsed = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
        return parsed.date()
    except ValueError:
        pass
    spans = _date_spans_in_text(cleaned)
    return spans[0][0] if spans else None

def _evidence_excerpt(text: str, pattern: re.Pattern[str], width: int = 120) -> str | None:
    match = pattern.search(text)
    if not match:
        return None
    start = max(0, match.start() - width)
    end = min(len(text), match.end() + width)
    return clean_space(text[start:end])


def evaluate_offer(text: str, now: datetime | None = None, min_score: int = 8) -> Evaluation:
    now = now or now_local()
    normalized = fold_text(text)
    score = 0
    reasons: list[str] = []
    warnings: list[str] = []
    evidence: list[str] = []

    has_secplus_word = bool(SECPLUS_RE.search(normalized))
    has_comptia_word = bool(COMPTIA_RE.search(normalized))
    exam_codes = sorted(
        set(re.sub(r"\s+", "", code.upper()) for code in SECPLUS_CODE_RE.findall(normalized))
    )
    any_comptia_exam = bool(ANY_COMPTIA_EXAM_RE.search(normalized))
    generic_comptia_voucher = bool(GENERIC_COMPTIA_VOUCHER_RE.search(normalized))
    has_scope = has_secplus_word or bool(exam_codes) or any_comptia_exam or generic_comptia_voucher
    if has_secplus_word:
        score += 6
        reasons.append("cita CompTIA Security+")
    if exam_codes:
        score += 3
        reasons.append("cita exame Security+: " + ", ".join(exam_codes[:4]))
    if any_comptia_exam:
        score += 3
        reasons.append("voucher válido para qualquer exame CompTIA, incluindo Security+")
    elif generic_comptia_voucher and not has_secplus_word and not exam_codes:
        score += 1
        reasons.append("menciona voucher de exame CompTIA potencialmente aplicável ao Security+")
        warnings.append("confirme nos termos se o Security+ é elegível")
    if has_comptia_word:
        score += 1
    if COMPTIA_CERT_RE.search(normalized):
        score += 1

    has_strong_offer = False
    for reason, pattern in STRONG_OFFER_PATTERNS:
        excerpt = _evidence_excerpt(normalized, pattern)
        if excerpt:
            has_strong_offer = True
            score += 7
            if reason not in reasons:
                reasons.append(reason)
            evidence.append(excerpt)

    if WEAK_OFFER_RE.search(normalized):
        score += 2
        if not has_strong_offer:
            warnings.append("há menção a voucher, mas o desconto integral não está totalmente claro")

    partial_matches = [match.group(0) for match in PARTIAL_DISCOUNT_RE.finditer(normalized)]
    partial_matches = [value for value in partial_matches if not re.search(r"100\s*%", value)]
    if partial_matches:
        score -= 10
        warnings.append("a página também menciona desconto parcial: " + ", ".join(partial_matches[:3]))

    if PAID_OFFER_RE.search(normalized):
        score -= 15
        warnings.append("parece loja/revenda de voucher pago, não oferta gratuita")

    expired = bool(EXPIRED_RE.search(normalized))
    if expired:
        score -= 20
        warnings.append("a página contém indicação de campanha encerrada ou expirada")

    if FREE_TRAINING_ONLY_RE.search(normalized) and not has_strong_offer:
        score -= 6
        warnings.append("parece divulgar treinamento gratuito, não necessariamente o exame")
    if NON_VOUCHER_RE.search(normalized):
        score -= 6
        warnings.append("parece tratar de simulado, renovação ou nova tentativa, não de voucher integral")

    dates = _parse_date_windows(text, now)
    deadline_dates = [item.value for item in dates if item.is_deadline]
    future_dates = [item.value for item in dates if item.value >= now.date()]
    past_dates = [item.value for item in dates if item.value < now.date()]
    past_deadlines = [item for item in deadline_dates if item < now.date()]
    future_deadlines = [item for item in deadline_dates if item >= now.date()]
    future_registration = [
        item.value for item in dates
        if item.value >= now.date() and item.is_registration and not item.is_redemption
    ]
    past_registration = [
        item.value for item in dates
        if item.value < now.date() and item.is_registration and not item.is_redemption
    ]
    future_redemption = [
        item.value for item in dates
        if item.value >= now.date() and item.is_redemption
    ]
    future_event_dates = [
        item.value for item in dates
        if item.value >= now.date() and not item.is_deadline and not item.is_redemption
    ]
    past_event_dates = [
        item.value for item in dates
        if item.value < now.date() and not item.is_deadline and not item.is_redemption
    ]

    # A future voucher-redemption date does not mean that new registrations remain open.
    if past_registration and not future_registration and not future_event_dates:
        expired = True
        score -= 18
        warnings.append("o período de inscrição/participação detectado já terminou")
    elif past_event_dates and not future_event_dates and not future_registration:
        expired = True
        score -= 14
        warnings.append("as datas do evento detectadas já passaram")
    elif dates and past_dates and not future_dates:
        expired = True
        score -= 14
        warnings.append("todas as datas detectadas na oferta já passaram")
    elif future_registration:
        score += 4
        reasons.append("inscrição ou participação futura detectada: " + min(future_registration).isoformat())
    elif future_event_dates:
        score += 2
        reasons.append("data futura relacionada ao evento: " + min(future_event_dates).isoformat())
    elif future_deadlines:
        score += 1
        reasons.append("prazo futuro detectado: " + min(future_deadlines).isoformat())
    elif past_deadlines:
        expired = True
        score -= 15
        warnings.append("prazo detectado já passou: " + max(past_deadlines).isoformat())

    has_signup_signal = bool(SIGNUP_TERMS_RE.search(normalized))
    redemption_only = bool(
        future_redemption and not future_registration and not future_event_dates and not has_signup_signal
    )
    if redemption_only:
        score -= 12
        warnings.append("foi encontrado prazo de resgate, mas não uma inscrição aberta para novos participantes")
    if has_signup_signal:
        score += 2
        reasons.append("possui chamada para inscrição ou resgate")

    if not has_scope:
        score -= 12
        warnings.append("não foi possível confirmar relação direta com CompTIA Security+")
    if not has_strong_offer:
        score -= 5
    is_candidate = bool(
        has_scope and has_strong_offer and not expired and not redemption_only and score >= min_score
    )
    return Evaluation(
        score=score,
        is_candidate=is_candidate,
        expired=expired,
        has_scope=has_scope,
        has_strong_offer=has_strong_offer,
        reasons=list(dict.fromkeys(reasons)),
        warnings=list(dict.fromkeys(warnings)),
        evidence=list(dict.fromkeys(evidence))[:4],
        dates=dates,
    )



def _host_is_blocked(url: str) -> bool:
    split = urlsplit(normalize_url(url))
    host = split.netloc.lower()
    path = split.path.lower()
    if any(host == item or host.endswith("." + item) for item in BLOCKED_SOURCE_HOSTS):
        return True
    if any(item in path for item in BLOCKED_SOURCE_PATHS):
        return True
    if host.startswith(("community.", "forum.", "forums.")):
        return True
    return False


def career_match(text: str, config: dict[str, Any]) -> tuple[int, str, list[str], list[str]]:
    """Return career score, priority, matched cert labels and human rationale."""
    folded = fold_text(text)
    profiles = config.get("career_targets") or []
    matched: list[tuple[int, str, str, str]] = []
    for item in profiles:
        if not isinstance(item, dict) or not item.get("enabled", True):
            continue
        patterns = [str(p) for p in item.get("patterns", [])]
        if not patterns:
            continue
        if any(re.search(pattern, folded, re.IGNORECASE) for pattern in patterns):
            weight = int(item.get("weight", 0))
            matched.append((weight, str(item.get("priority", "media")), str(item.get("label", "certificacao")), str(item.get("reason", ""))))
    if not matched:
        return 0, "", [], []
    matched.sort(reverse=True)
    score = max(x[0] for x in matched)
    priority_order = {"essencial": 4, "alta": 3, "media": 2, "baixa": 1}
    priority = max((x[1] for x in matched), key=lambda x: priority_order.get(x, 0))
    labels = list(dict.fromkeys(x[2] for x in matched))
    reasons = list(dict.fromkeys(x[3] for x in matched if x[3]))
    return score, priority, labels, reasons


def generic_career_scope(text: str, config: dict[str, Any]) -> tuple[int, str, list[str], list[str]]:
    """Handle vouchers valid for any CompTIA certification (Security+ included)."""
    folded = fold_text(text)
    if re.search(
        r"\b(?:any|all|qualquer|todos os)\b.{0,60}\bcomptia\b.{0,80}\b(?:exam|certification|exame|certificacao)\b",
        folded,
    ):
        return 8, "alta", ["Qualquer certificacao CompTIA"], [
            "voucher amplo da CompTIA pode ser usado no Security+"
        ]
    return 0, "", [], []

def rank_signup_link(source_url: str, links: list[tuple[str, str]]) -> tuple[str, int]:
    source = normalize_url(source_url)
    source_host = urlsplit(source).netloc
    best_url = source
    best_score = 0
    positive = re.compile(
        r"(?:register|registration|sign[- ]?up|apply|enroll|enrol|inscrev|inscri[cç][aã]o|"
        r"cadastre|particip|claim|redeem|voucher|garanta|reserve)",
        re.IGNORECASE,
    )
    negative = re.compile(
        r"(?:privacy|terms|legal|cookie|unsubscribe|facebook|linkedin|instagram|youtube|"
        r"saiba mais|learn more|agenda|speaker|palestrante)",
        re.IGNORECASE,
    )
    preferred_hosts = (
        "comptia.org",
        "pearsonvue.com",
        "perscholas.org",
        "npower.org",
        "wicys.org",
        "cyberskills2work.org",
        "onwardtoopportunity.org",
    )
    for anchor_text, href in links:
        candidate = normalize_url(href)
        if not candidate.startswith(("http://", "https://")):
            continue
        folded = fold_text(f"{anchor_text} {candidate}")
        score = 0
        if positive.search(folded):
            score += 8
        if re.search(r"(?:register|inscrev|apply|enroll|claim|redeem)", fold_text(anchor_text)):
            score += 5
        if urlsplit(candidate).netloc.endswith(preferred_hosts):
            score += 4
        if urlsplit(candidate).netloc != source_host:
            score += 1
        if negative.search(folded):
            score -= 8
        if candidate == source:
            score -= 1
        if score > best_score:
            best_url = candidate
            best_score = score
    return best_url, best_score


def make_excerpt(text: str, evidence: list[str], limit: int = 430) -> str:
    base = evidence[0] if evidence else clean_space(text)
    if len(base) <= limit:
        return base
    return base[: limit - 1].rstrip() + "…"


def build_candidate(
    hit: SearchHit,
    config: dict[str, Any],
    now: datetime,
) -> Candidate | None:
    if _host_is_blocked(hit.url):
        LOGGER.info("Rejeitado [%s]: fonte de discussao/social/video", hit.title)
        return None
    page_text, links, final_url = fetch_page(hit.url)
    if _host_is_blocked(final_url or hit.url):
        LOGGER.info("Rejeitado [%s]: redirecionou para fonte bloqueada", hit.title)
        return None
    combined = clean_space(" ".join([hit.title, hit.content, hit.raw_content, page_text]))
    folded_title = fold_text(hit.title)
    folded_combined = fold_text(combined)
    if QUESTION_STYLE_RE.search(folded_title) or SPECULATIVE_RE.search(folded_combined):
        LOGGER.info("Rejeitado [%s]: pagina de pergunta ou linguagem especulativa", hit.title)
        return None
    # Only the title decides: official CompTIA pages and workforce programs often
    # bundle a free voucher with CertMaster/study material in the body text.
    if STUDY_MATERIAL_RE.search(folded_title):
        LOGGER.info("Rejeitado [%s]: material de estudo/preparacao, nao voucher de exame", hit.title)
        return None
    evaluation = evaluate_offer(combined, now, int(config.get("min_score", 8)))
    if not evaluation.is_candidate:
        LOGGER.info(
            "Rejeitado [%s]: score=%s expired=%s strong=%s scope=%s",
            hit.title,
            evaluation.score,
            evaluation.expired,
            evaluation.has_strong_offer,
            evaluation.has_scope,
        )
        return None

    career_score, career_priority, matched_certs, career_reasons = career_match(combined, config)
    if career_score <= 0:
        career_score, career_priority, matched_certs, career_reasons = generic_career_scope(combined, config)
    if career_score <= 0:
        LOGGER.info("Rejeitado [%s]: voucher nao corresponde ao perfil de carreira", hit.title)
        return None

    has_future_date = any(item.value >= now.date() for item in evaluation.dates)
    published_date = parse_explicit_date(hit.published_date)
    stale_after_days = int(config.get("stale_result_days", 450))
    if published_date and not has_future_date and published_date < now.date() - timedelta(days=stale_after_days):
        LOGGER.info("Rejeitado [%s]: resultado publicado em %s sem data futura", hit.title, published_date)
        return None

    signup_url, signup_score = rank_signup_link(final_url or hit.url, links)
    reasons = list(evaluation.reasons)
    warnings = list(evaluation.warnings)
    adjusted_score = evaluation.score
    if signup_score >= 5:
        adjusted_score += 3
        reasons.append("link específico de inscrição identificado")
    elif not SIGNUP_TERMS_RE.search(fold_text(combined)):
        LOGGER.info("Rejeitado [%s]: sem inscricao/resgate identificavel", hit.title)
        return None
    else:
        warnings.append("o link leva à página da oferta; confirme nela o botão de inscrição")

    adjusted_score += career_score
    reasons.extend(career_reasons)

    source_host = urlsplit(final_url or hit.url).netloc.lower()
    trusted_domains = tuple(str(item).lower() for item in config.get("trusted_domains", []))
    is_trusted_source = any(
        source_host == domain or source_host.endswith("." + domain) for domain in trusted_domains
    )
    if is_trusted_source:
        adjusted_score += 2
        reasons.append("fonte oficial ou parceira conhecida")
    else:
        # Conservative rule: an untrusted article is only alert-worthy when its
        # registration link leaves that site and lands on a trusted organizer.
        signup_host = urlsplit(normalize_url(signup_url)).netloc.lower()
        signup_is_trusted = any(
            signup_host == domain or signup_host.endswith("." + domain) for domain in trusted_domains
        )
        if not signup_is_trusted:
            LOGGER.info(
                "Rejeitado [%s]: fonte nao oficial sem link de inscricao em organizador confiavel",
                hit.title,
            )
            return None
        adjusted_score += 1
        reasons.append("fonte secundária aponta para inscrição em domínio confiável")
        warnings.append("fonte não oficial; valide os termos na página oficial de inscrição")

    high_threshold = int(config.get("high_confidence_score", 15))
    scope_uncertain = any("se o Security+ é elegível" in item for item in warnings)
    confidence = (
        "alta"
        if adjusted_score >= high_threshold and is_trusted_source and not scope_uncertain
        else "média"
    )
    future_dates = sorted(
        {signal.value.isoformat() for signal in evaluation.dates if signal.value >= now.date()}
    )
    evidence = evaluation.evidence
    fingerprint_input = json.dumps(
        {
            "title": fold_text(hit.title),
            "source": normalize_url(final_url or hit.url),
            "signup": normalize_url(signup_url),
            "future_dates": future_dates,
            "evidence": [fold_text(item)[:240] for item in evidence],
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    fingerprint = hashlib.sha256(fingerprint_input.encode("utf-8")).hexdigest()
    return Candidate(
        title=hit.title,
        source_url=normalize_url(final_url or hit.url),
        signup_url=normalize_url(signup_url),
        confidence=confidence,
        score=adjusted_score,
        career_priority=career_priority,
        matched_certifications=matched_certs,
        career_reason="; ".join(career_reasons),
        reasons=list(dict.fromkeys(reasons)),
        warnings=list(dict.fromkeys(warnings)),
        evidence=evidence,
        excerpt=make_excerpt(combined, evidence),
        future_dates=future_dates,
        fingerprint=fingerprint,
    )



def unique_candidates(candidates: Iterable[Candidate]) -> list[Candidate]:
    """Keep the strongest result when several pages point to the same signup URL."""
    best: dict[str, Candidate] = {}
    for candidate in candidates:
        signup = normalize_url(candidate.signup_url)
        source = normalize_url(candidate.source_url)
        key = signup if signup and signup != source else source
        existing = best.get(key)
        if existing is None or candidate.score > existing.score:
            best[key] = candidate
    return list(best.values())

def state_key(candidate: Candidate) -> str:
    return normalize_url(candidate.source_url)


def load_state(path: Path) -> dict[str, Any]:
    state = load_json(path, {"version": 1, "items": {}})
    if not isinstance(state, dict):
        return {"version": 1, "items": {}}
    state.setdefault("version", 1)
    if not isinstance(state.get("items"), dict):
        state["items"] = {}
    return state


def parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def filter_new_candidates(
    candidates: list[Candidate],
    state: dict[str, Any],
    now: datetime,
    cooldown_days: int,
) -> list[Candidate]:
    fresh: list[Candidate] = []
    for candidate in candidates:
        entry = state["items"].get(state_key(candidate))
        if not entry:
            fresh.append(candidate)
            continue
        if entry.get("fingerprint") == candidate.fingerprint:
            continue
        last_alerted = parse_iso_datetime(entry.get("last_alerted"))
        if last_alerted is None or now.astimezone(timezone.utc) - last_alerted >= timedelta(days=cooldown_days):
            fresh.append(candidate)
    return fresh


def update_state(state: dict[str, Any], candidates: list[Candidate], now: datetime) -> None:
    timestamp = now.astimezone(timezone.utc).isoformat()
    for candidate in candidates:
        state["items"][state_key(candidate)] = {
            "title": candidate.title,
            "signup_url": candidate.signup_url,
            "fingerprint": candidate.fingerprint,
            "last_alerted": timestamp,
        }
    # Keep the file small and remove entries unseen for more than 18 months.
    cutoff = now.astimezone(timezone.utc) - timedelta(days=550)
    stale: list[str] = []
    for key, entry in state["items"].items():
        last_alerted = parse_iso_datetime(entry.get("last_alerted"))
        if last_alerted and last_alerted < cutoff:
            stale.append(key)
    for key in stale:
        state["items"].pop(key, None)
    state["updated_at"] = timestamp


def _candidate_plain(candidate: Candidate, index: int) -> str:
    lines = [
        f"{index}. {candidate.title}",
        f"Confiança: {candidate.confidence} | prioridade para sua carreira: {candidate.career_priority or 'n/a'} | score: {candidate.score}",
        "Certificacao(s): " + (", ".join(candidate.matched_certifications) or "voucher generico relevante"),
        "Motivos: " + "; ".join(candidate.reasons),
    ]
    if candidate.future_dates:
        lines.append("Datas futuras detectadas: " + ", ".join(candidate.future_dates))
    if candidate.warnings:
        lines.append("Atenção: " + "; ".join(candidate.warnings))
    if candidate.excerpt:
        lines.append("Trecho: " + candidate.excerpt)
    lines.extend(
        [
            f"Inscrição: {candidate.signup_url}",
            f"Fonte: {candidate.source_url}",
        ]
    )
    return "\n".join(lines)


def render_plain(candidates: list[Candidate], now: datetime) -> str:
    header = (
        "Monitor de vouchers CompTIA Security+ — oportunidades relevantes\n"
        f"Verificação: {now.strftime('%d/%m/%Y %H:%M %Z')}\n\n"
        "O filtro exige exame/voucher 100% gratuito, inscricao ativa e relacao com o CompTIA Security+. "
        "Ainda assim, confirme elegibilidade, quantidade e prazo na página oficial.\n\n"
    )
    return header + "\n\n".join(_candidate_plain(item, i) for i, item in enumerate(candidates, 1))


def render_html(candidates: list[Candidate], now: datetime) -> str:
    cards: list[str] = []
    for candidate in candidates:
        reasons = "".join(f"<li>{html.escape(reason)}</li>" for reason in candidate.reasons)
        warnings = ""
        if candidate.warnings:
            warning_items = "".join(f"<li>{html.escape(item)}</li>" for item in candidate.warnings)
            warnings = f"<p><strong>Atenção:</strong></p><ul>{warning_items}</ul>"
        dates = ""
        if candidate.future_dates:
            dates = "<p><strong>Datas futuras detectadas:</strong> " + html.escape(
                ", ".join(candidate.future_dates)
            ) + "</p>"
        cards.append(
            "<div style='border:1px solid #d0d7de;border-radius:10px;padding:18px;margin:16px 0;'>"
            f"<h2 style='margin-top:0'>{html.escape(candidate.title)}</h2>"
            f"<p><strong>Confiança:</strong> {html.escape(candidate.confidence)} "
            f"&nbsp; <strong>Score:</strong> {candidate.score}</p>"
            f"<ul>{reasons}</ul>{dates}{warnings}"
            f"<p>{html.escape(candidate.excerpt)}</p>"
            f"<p><a href='{html.escape(candidate.signup_url, quote=True)}' "
            "style='display:inline-block;padding:11px 16px;border-radius:7px;"
            "background:#0969da;color:#fff;text-decoration:none;font-weight:700'>"
            "Abrir inscrição</a></p>"
            f"<p style='font-size:12px'>Fonte: <a href='{html.escape(candidate.source_url, quote=True)}'>"
            f"{html.escape(candidate.source_url)}</a></p>"
            "</div>"
        )
    return (
        "<!doctype html><html><body style='font-family:Arial,sans-serif;line-height:1.45;"
        "max-width:760px;margin:auto;padding:20px'>"
        "<h1>Novos vouchers gratuitos do CompTIA Security+</h1>"
        f"<p>Verificação: {html.escape(now.strftime('%d/%m/%Y %H:%M %Z'))}</p>"
        "<p>O filtro exige exame/voucher 100% gratuito, inscricao ativa e relacao com o CompTIA Security+. "
        "Confirme elegibilidade, disponibilidade e prazo antes de contar com o benefício.</p>"
        + "".join(cards)
        + "</body></html>"
    )


def smtp_settings() -> dict[str, Any] | None:
    gmail_user = clean_space(os.getenv("GMAIL_USER", ""))
    gmail_password = re.sub(r"\s+", "", os.getenv("GMAIL_APP_PASSWORD", ""))
    host = clean_space(os.getenv("SMTP_HOST", ""))
    user = clean_space(os.getenv("SMTP_USER", ""))
    password = os.getenv("SMTP_PASSWORD", "")
    if gmail_user and gmail_password:
        return {
            "host": "smtp.gmail.com",
            "port": 465,
            "ssl": True,
            "starttls": False,
            "user": gmail_user,
            "password": gmail_password,
            "sender": clean_space(os.getenv("EMAIL_FROM", gmail_user)),
        }
    if host and user and password:
        return {
            "host": host,
            "port": env_int("SMTP_PORT", 465),
            "ssl": env_bool("SMTP_SSL", True),
            "starttls": env_bool("SMTP_STARTTLS", False),
            "user": user,
            "password": password,
            "sender": clean_space(os.getenv("EMAIL_FROM", user)),
        }
    return None


def send_email(candidates: list[Candidate], now: datetime) -> bool:
    settings = smtp_settings()
    recipients = [item.strip() for item in os.getenv("ALERT_TO", "").split(",") if item.strip()]
    if not settings or not recipients:
        return False
    subject = (
        f"[Security+ Gratis] {len(candidates)} oportunidade"
        + ("" if len(candidates) == 1 else "s")
        + " com 100% de desconto"
    )
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings["sender"]
    message["To"] = ", ".join(recipients)
    message.set_content(render_plain(candidates, now))
    message.add_alternative(render_html(candidates, now), subtype="html")
    context = ssl.create_default_context()
    try:
        if settings["ssl"]:
            with smtplib.SMTP_SSL(
                settings["host"], settings["port"], context=context, timeout=30
            ) as smtp:
                smtp.login(settings["user"], settings["password"])
                smtp.send_message(message)
        else:
            with smtplib.SMTP(settings["host"], settings["port"], timeout=30) as smtp:
                smtp.ehlo()
                if settings["starttls"]:
                    smtp.starttls(context=context)
                    smtp.ehlo()
                smtp.login(settings["user"], settings["password"])
                smtp.send_message(message)
        LOGGER.info("E-mail enviado para %s", ", ".join(recipients))
        return True
    except (OSError, smtplib.SMTPException) as exc:
        LOGGER.error("Falha ao enviar e-mail: %s", exc)
        return False


def send_telegram(candidates: list[Candidate], now: datetime) -> bool:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        return False
    successful = True
    for index, candidate in enumerate(candidates, 1):
        reason_text = "; ".join(candidate.reasons)
        text = (
            f"<b>Voucher relevante novo ({index}/{len(candidates)})</b>\n"
            f"<b>{html.escape(candidate.title)}</b>\n"
            f"Confiança: {html.escape(candidate.confidence)} | score: {candidate.score}\n"
            f"Motivos: {html.escape(reason_text)}\n"
            f"<a href=\"{html.escape(candidate.signup_url, quote=True)}\">Abrir inscrição</a>\n"
            f"Verificado em {html.escape(now.strftime('%d/%m/%Y %H:%M %Z'))}"
        )
        try:
            response = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": text[:4000],
                    "parse_mode": "HTML",
                    "disable_web_page_preview": False,
                },
                timeout=30,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            LOGGER.error("Falha ao enviar Telegram: %s", exc)
            successful = False
    if successful:
        LOGGER.info("Telegram enviado para chat %s", chat_id)
    return successful


def notify(candidates: list[Candidate], now: datetime) -> list[str]:
    channels: list[str] = []
    if send_email(candidates, now):
        channels.append("email")
    if send_telegram(candidates, now):
        channels.append("telegram")
    return channels


def test_notification(now: datetime) -> int:
    candidate = Candidate(
        title="Teste do monitor de vouchers Security+",
        source_url="https://www.comptia.org/certifications/security",
        signup_url="https://www.comptia.org/certifications/security",
        confidence="teste",
        score=99,
        reasons=["configuração de notificação validada"],
        warnings=["esta não é uma oferta real"],
        evidence=[],
        excerpt="Mensagem de teste. Nenhum voucher foi encontrado ou consumido.",
        future_dates=[],
        fingerprint="test",
    )
    channels = notify([candidate], now)
    if not channels:
        LOGGER.error(
            "Nenhum canal configurado. Defina Gmail/SMTP e ALERT_TO, ou Telegram."
        )
        return 2
    LOGGER.info("Teste enviado por: %s", ", ".join(channels))
    return 0


def run(args: argparse.Namespace) -> int:
    config_path = Path(args.config).resolve()
    config = load_json(config_path, {})
    if not isinstance(config, dict):
        raise RuntimeError("O arquivo config.json precisa conter um objeto JSON")
    now = now_local()

    if args.test_notification:
        return test_notification(now)

    api_key = os.getenv("TAVILY_API_KEY", "").strip()
    if not api_key:
        LOGGER.error("Defina o segredo TAVILY_API_KEY antes de executar a busca.")
        return 2

    queries = config.get("queries") or []
    if not isinstance(queries, list) or not queries:
        LOGGER.error("Nenhuma consulta definida em %s", config_path)
        return 2

    all_hits: list[SearchHit] = []
    errors = 0
    for index, query in enumerate(queries, 1):
        LOGGER.info("Busca %s/%s: %s", index, len(queries), query)
        try:
            all_hits.extend(search_tavily(api_key, str(query), config))
        except Exception as exc:
            errors += 1
            LOGGER.error("Consulta falhou: %s", exc)

    hits = unique_hits(all_hits)
    LOGGER.info("%s resultado(s) único(s) para avaliar", len(hits))
    if not hits and errors == len(queries):
        return 1

    candidates: list[Candidate] = []
    for hit in hits:
        candidate = build_candidate(hit, config, now)
        if candidate:
            candidates.append(candidate)
    candidates = unique_candidates(candidates)
    priority_rank = {"essencial": 4, "alta": 3, "media": 2, "baixa": 1}
    candidates.sort(key=lambda item: (priority_rank.get(item.career_priority, 0), item.confidence == "alta", item.score), reverse=True)
    LOGGER.info("%s candidato(s) após validação", len(candidates))

    if args.dry_run:
        if candidates:
            print(render_plain(candidates, now))
        else:
            print("Nenhuma oportunidade com confiança suficiente foi encontrada.")
        return 0

    state_path = Path(args.state).resolve()
    state = load_state(state_path)
    new_candidates = filter_new_candidates(
        candidates,
        state,
        now,
        env_int("ALERT_COOLDOWN_DAYS", int(config.get("alert_cooldown_days", 7))),
    )
    if not new_candidates:
        LOGGER.info("Nenhuma oportunidade nova para alertar.")
        return 0

    channels = notify(new_candidates, now)
    if not channels:
        LOGGER.error(
            "Foram encontradas oportunidades, mas nenhum canal enviou o alerta. "
            "Configure Gmail/SMTP ou Telegram."
        )
        print(render_plain(new_candidates, now))
        return 2

    update_state(state, new_candidates, now)
    save_json_atomic(state_path, state)
    LOGGER.info(
        "%s alerta(s) enviado(s) por %s; estado salvo em %s",
        len(new_candidates),
        ", ".join(channels),
        state_path,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Busca vouchers 100% gratuitos do CompTIA Security+ e envia alertas por e-mail/Telegram."
    )
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="Caminho do config.json")
    parser.add_argument("--state", default=str(DEFAULT_STATE), help="Caminho do estado JSON")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Pesquisa e imprime candidatos sem notificar nem alterar o estado",
    )
    parser.add_argument(
        "--test-notification",
        action="store_true",
        help="Envia uma mensagem de teste sem fazer buscas",
    )
    parser.add_argument("--verbose", action="store_true", help="Ativa logs detalhados")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )
    try:
        return run(args)
    except KeyboardInterrupt:
        LOGGER.warning("Execução interrompida")
        return 130
    except Exception as exc:
        LOGGER.exception("Erro inesperado: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
