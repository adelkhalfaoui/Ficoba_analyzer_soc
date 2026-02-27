#!/usr/bin/env python3
"""
FICOBA SOC Log Analyzer (version robuste)
=======================================
=============================================================================
 RÉALISÉ PAR : Adel Salah Eddine KHALFAOUI
 EMAIL      : adel.khalfaoui@efrei.net
 PROMO      : 2025-CSC2
 MODULE     : Développement sécurisé
 ENCADRANT  : Minh Duc NGUYEN
 DATE       : 27/02/2026
=============================================================================

Analyse SOC post-incident pour les logs d'accès FICOBA.

Détections :
  1) Usurpation d'identité        : IP externe / IP invalide
  2) Accès hors horaires          : nuits / weekends (UTC par défaut)
  3) Anomalies MFA                : MFA_FAIL / MFA_BYPASS (+ pattern FAIL→BYPASS)
  4) Extraction massive           : volume de requêtes anormal (par session)
  5) Export de données            : action EXPORT (+ volume)
  6) Rafales                      : cadence automatisée (fenêtre glissante)
  7) Changement d'IP              : utilisateur observé sur plusieurs IP
  8) Sessions concurrentes        : chevauchements temporels pour un même utilisateur

Format attendu :
[TIMESTAMP] USER | ROLE | IP | APP | ACTION | RESOURCE | QUERY_COUNT | STATUS | MFA | SESSION_ID

Exemples :
  python ficoba_analyzer.py -l access_ficoba.log
  python ficoba_analyzer.py -l access_ficoba.log -o rapport.txt
  python ficoba_analyzer.py -l access_ficoba.log -j -o rapport.json
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, time, timezone, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


# =============================================================================
# CONFIGURATION — Seuils et paramètres
# =============================================================================

# Réseaux internes (RFC1918). Adapte si tu as des plages publiques DGFiP/Intermin.
INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# Horaires "business" en UTC (fin exclue)
WORK_HOURS_START = time(7, 0)
WORK_HOURS_END = time(19, 0)
WORK_DAYS = {0, 1, 2, 3, 4}  # lun..ven

# Volumétrie (le script détecte si QUERY_COUNT est cumulatif ou par événement)
QUERY_THRESHOLD_WARNING = 10
QUERY_THRESHOLD_CRITICAL = 50

# Rafales
BURST_WINDOW_SECONDS = 15
BURST_QUERY_THRESHOLD = 20

# Exports
EXPORT_VOLUME_CRITICAL = 1000

# MFA
MFA_SUSPICIOUS = {"MFA_FAIL", "MFA_BYPASS"}
MFA_PATTERN_WINDOW_SECONDS = 300  # 5 min


# =============================================================================
# MODÈLES DE DONNÉES
# =============================================================================

class Severity(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class LogEntry:
    timestamp: datetime
    user: str
    role: str
    ip: str
    app: str
    action: str
    resource: str
    query_count: Optional[int]
    status: str
    mfa: str
    session_id: str
    line_number: int
    raw_line: str

    # Calculé au build session
    effective_queries: int = 0


@dataclass
class Alert:
    severity: Severity
    category: str
    title: str
    description: str
    indicators: Dict[str, str]
    log_entries: List[int]
    timestamp: Optional[datetime] = None


@dataclass
class SessionInfo:
    session_id: str
    user: str
    role: str
    app: str

    ips: Set[str] = field(default_factory=set)
    actions: List[str] = field(default_factory=list)
    entries: List[LogEntry] = field(default_factory=list)
    line_numbers: List[int] = field(default_factory=list)
    mfa_events: List[str] = field(default_factory=list)

    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    total_queries: int = 0
    max_query_count_seen: int = 0
    query_count_mode: str = "unknown"   # cumulative | per_event | unknown

    has_export: bool = False
    export_volume: int = 0


# =============================================================================
# PARSER
# =============================================================================

class LogParser:
    EXPECTED_FIELDS = 11
    TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.parse_errors: List[Tuple[int, str, str]] = []

    def parse_file(self, filepath: str) -> List[LogEntry]:
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Fichier introuvable : {filepath}")

        entries: List[LogEntry] = []

        def looks_like_new_event(line: str) -> bool:
            s = line.lstrip()
            if s.startswith("[") and "T" in s and "Z" in s:
                return True
            if len(s) >= 20 and s[4] == "-" and "T" in s[:20]:
                return True
            return False

        def normalize_event_line(line: str) -> str:
            line = line.strip()
            # Convertit "[TS] user | ..." -> "TS | user | ..."
            if line.startswith("["):
                end = line.find("]")
                if end != -1:
                    ts = line[1:end].strip()
                    rest = line[end + 1:].strip()
                    line = f"{ts} | {rest}" if rest else ts
            # normaliser les pipes
            line = " | ".join(p.strip() for p in line.split("|"))
            return line.strip()

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                buffer = ""
                buffer_line_num = 0

                def split_multi_events(raw_line: str) -> List[str]:
                    """
                    Certains fichiers collent plusieurs événements sur une même ligne.
                    On découpe sur chaque occurrence de timestamp (avec ou sans crochets).
                    """
                    raw_line = raw_line.strip()
                    markers = list(re.finditer(
                        r"(\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\]|\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\b)",
                        raw_line
                    ))
                    if len(markers) <= 1:
                        return [raw_line] if raw_line else []
                    cuts = [m.start() for m in markers] + [len(raw_line)]
                    parts: List[str] = []
                    for a, b in zip(cuts, cuts[1:]):
                        chunk = raw_line[a:b].strip()
                        if chunk:
                            parts.append(chunk)
                    return parts

                for line_num, raw in enumerate(fh, start=1):
                    raw = raw.rstrip("\n")
                    for piece in split_multi_events(raw):
                        raw2 = piece

                        if not raw2.strip() or raw2.lstrip().startswith("#"):
                            continue

                        if looks_like_new_event(raw2):
                            if buffer:
                                full = normalize_event_line(buffer)
                                e = self._parse_line(buffer_line_num, full)
                                if e:
                                    entries.append(e)
                                buffer = ""
                            buffer = raw2.strip()
                            buffer_line_num = line_num
                        else:
                            if not buffer:
                                msg = "Ligne orpheline (continuation sans début d'événement)"
                                self.parse_errors.append((line_num, raw2, msg))
                                self.logger.warning("Ligne %d: %s", line_num, msg)
                                continue
                            cont = raw2.strip()
                            if cont.startswith("|"):
                                cont = cont[1:].strip()
                            buffer = buffer.rstrip() + " | " + cont

                # Flush du dernier événement
                if buffer:
                    full = normalize_event_line(buffer)
                    e = self._parse_line(buffer_line_num, full)
                    if e:
                        entries.append(e)

        except PermissionError:
            raise PermissionError(f"Permission refusée : {filepath}")

        self.logger.info("%d entrées parsées, %d erreurs", len(entries), len(self.parse_errors))
        return entries

    def _parse_line(self, line_num: int, raw_line: str) -> Optional[LogEntry]:
        try:
            parts = [p.strip() for p in raw_line.split("|")]
            # Corrige les champs vides (ex: pipe en fin de ligne avant wrap)
            if len(parts) != self.EXPECTED_FIELDS:
                compact = [p for p in parts if p != ""]
                if len(compact) == self.EXPECTED_FIELDS:
                    parts = compact
                else:
                    msg = f"Nombre de champs incorrect : {len(parts)} (attendu {self.EXPECTED_FIELDS})"
                    self.parse_errors.append((line_num, raw_line, msg))
                    self.logger.warning("Ligne %d: %s", line_num, msg)
                    return None

            try:
                ts = datetime.strptime(parts[0], self.TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
            except ValueError:
                msg = f"Timestamp invalide : '{parts[0]}'"
                self.parse_errors.append((line_num, raw_line, msg))
                self.logger.warning("Ligne %d: %s", line_num, msg)
                return None

            qc: Optional[int] = None
            raw_qc = parts[7].strip()
            if raw_qc not in ("-", ""):
                try:
                    qc = int(raw_qc)
                except ValueError:
                    msg = f"query_count non numérique : '{raw_qc}'"
                    self.parse_errors.append((line_num, raw_line, msg))
                    self.logger.warning("Ligne %d: %s", line_num, msg)
                    return None

            return LogEntry(
                timestamp=ts,
                user=parts[1],
                role=parts[2],
                ip=parts[3],
                app=parts[4],
                action=parts[5],
                resource=parts[6],
                query_count=qc,
                status=parts[8],
                mfa=parts[9],
                session_id=parts[10],
                line_number=line_num,
                raw_line=raw_line,
            )

        except Exception as exc:
            msg = f"Erreur inattendue : {exc}"
            self.parse_errors.append((line_num, raw_line, msg))
            self.logger.error("Ligne %d: %s", line_num, msg)
            return None


# =============================================================================
# ANALYSEUR SOC
# =============================================================================

class FICOBAAnalyzer:
    def __init__(self, entries: List[LogEntry]) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.entries = sorted(entries, key=lambda e: e.timestamp)
        self.alerts: List[Alert] = []
        self.sessions: Dict[str, SessionInfo] = {}
        self._build_sessions()

    def _build_sessions(self) -> None:
        grouped: Dict[str, List[LogEntry]] = defaultdict(list)
        for e in self.entries:
            grouped[e.session_id].append(e)

        for sid, evs in grouped.items():
            evs.sort(key=lambda e: e.timestamp)
            s0 = evs[0]
            s = SessionInfo(session_id=sid, user=s0.user, role=s0.role, app=s0.app)

            # Heuristique: QUERY_COUNT cumulatif ou par événement ?
            qvals = [
                e.query_count for e in evs
                if e.query_count is not None and e.action in ("SEARCH", "EXPORT")
            ]
            mode = "unknown"
            if len(qvals) >= 3:
                nondecreasing = all(qvals[i] <= qvals[i + 1] for i in range(len(qvals) - 1))
                strictly_increasing = any(qvals[i] < qvals[i + 1] for i in range(len(qvals) - 1))
                mode = "cumulative" if (nondecreasing and strictly_increasing) else "per_event"
            elif len(qvals) >= 1:
                mode = "per_event"
            s.query_count_mode = mode

            last_cum: Optional[int] = None

            for e in evs:
                s.entries.append(e)
                s.line_numbers.append(e.line_number)
                s.actions.append(e.action)
                s.ips.add(e.ip)
                if e.mfa and e.mfa != "-":
                    s.mfa_events.append(e.mfa)

                if s.start_time is None or e.timestamp < s.start_time:
                    s.start_time = e.timestamp
                if s.end_time is None or e.timestamp > s.end_time:
                    s.end_time = e.timestamp

                eff = 0
                if e.query_count is not None and e.action in ("SEARCH", "EXPORT"):
                    s.max_query_count_seen = max(s.max_query_count_seen, e.query_count)

                    if mode == "cumulative":
                        if last_cum is None:
                            eff = max(0, e.query_count)
                        else:
                            eff = max(0, e.query_count - last_cum)
                        last_cum = e.query_count
                    else:
                        eff = max(0, e.query_count)

                e.effective_queries = eff
                s.total_queries += eff

                if e.action == "EXPORT":
                    s.has_export = True
                    s.export_volume += eff

            self.sessions[sid] = s

        self.logger.info("%d sessions reconstituées", len(self.sessions))

    def run_all_detections(self) -> None:
        self.detect_external_ip()
        self.detect_off_hours()
        self.detect_mfa_anomalies()
        self.detect_massive_queries()
        self.detect_exports()
        self.detect_burst_activity()
        self.detect_ip_change_per_user()
        self.detect_concurrent_sessions()

        order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
        self.alerts.sort(key=lambda a: (order.get(a.severity, 3),
                                        a.timestamp or datetime.min.replace(tzinfo=timezone.utc)))

    # --- 1) IP externe / invalide ---
    def detect_external_ip(self) -> None:
        for sid, s in self.sessions.items():
            invalid_ips = [ip for ip in s.ips if not self._is_valid_ip(ip)]
            for ip in invalid_ips:
                self.alerts.append(Alert(
                    severity=Severity.CRITICAL,
                    category="USURPATION_IDENTITE",
                    title="Adresse IP invalide",
                    description=(f"Session '{sid}' — '{s.user}' contient une IP invalide: {ip}."),
                    indicators={"user": s.user, "session_id": sid, "ip": ip},
                    log_entries=s.line_numbers,
                    timestamp=s.start_time,
                ))

            external_ips = [ip for ip in s.ips if self._is_valid_ip(ip) and not self._is_internal_ip(ip)]
            if external_ips:
                self.alerts.append(Alert(
                    severity=Severity.CRITICAL,
                    category="USURPATION_IDENTITE",
                    title="Connexion depuis IP externe",
                    description=(f"Session '{sid}' — '{s.user}' observé depuis IP(s) externe(s): "
                                 f"{', '.join(sorted(set(external_ips)))}."),
                    indicators={
                        "user": s.user,
                        "session_id": sid,
                        "ips": ", ".join(sorted(set(external_ips))),
                        "app": s.app,
                        "timestamp": s.start_time.isoformat() if s.start_time else "N/A",
                    },
                    log_entries=s.line_numbers,
                    timestamp=s.start_time,
                ))

    # --- 2) Hors horaires ---
    def detect_off_hours(self) -> None:
        jours = ["Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi", "Dimanche"]
        for sid, s in self.sessions.items():
            if not s.start_time:
                continue
            ts = s.start_time
            off = (ts.weekday() not in WORK_DAYS) or (ts.time() < WORK_HOURS_START) or (ts.time() >= WORK_HOURS_END)
            if off:
                self.alerts.append(Alert(
                    severity=Severity.WARNING,
                    category="ACCES_HORS_HORAIRES",
                    title="Accès hors horaires",
                    description=(f"Session '{sid}' — '{s.user}' ouverte le {jours[ts.weekday()]} à "
                                 f"{ts.strftime('%H:%M:%S')} UTC."),
                    indicators={"user": s.user, "session_id": sid, "timestamp": ts.isoformat()},
                    log_entries=s.line_numbers,
                    timestamp=ts,
                ))

    # --- 3) MFA anomalies + pattern FAIL→BYPASS ---
    def detect_mfa_anomalies(self) -> None:
        for e in self.entries:
            if e.mfa not in MFA_SUSPICIOUS:
                continue
            sev = Severity.CRITICAL if e.mfa == "MFA_BYPASS" else Severity.WARNING
            self.alerts.append(Alert(
                severity=sev,
                category="CONTOURNEMENT_MFA",
                title=f"Anomalie MFA : {e.mfa}",
                description=(f"'{e.user}' — MFA='{e.mfa}' à {e.timestamp.isoformat()}."),
                indicators={"user": e.user, "ip": e.ip, "session_id": e.session_id, "mfa": e.mfa,
                            "timestamp": e.timestamp.isoformat()},
                log_entries=[e.line_number],
                timestamp=e.timestamp,
            ))

        last_fail: Dict[str, datetime] = {}
        for e in self.entries:
            if e.mfa == "MFA_FAIL":
                last_fail[e.user] = e.timestamp
            if e.mfa == "MFA_BYPASS":
                ts_fail = last_fail.get(e.user)
                if ts_fail and (e.timestamp - ts_fail).total_seconds() <= MFA_PATTERN_WINDOW_SECONDS:
                    self.alerts.append(Alert(
                        severity=Severity.CRITICAL,
                        category="CONTOURNEMENT_MFA",
                        title="Pattern MFA_FAIL → MFA_BYPASS",
                        description=(f"'{e.user}' — MFA_FAIL puis MFA_BYPASS en ≤ {MFA_PATTERN_WINDOW_SECONDS//60} min."),
                        indicators={"user": e.user, "session_id": e.session_id,
                                    "timestamp_fail": ts_fail.isoformat(), "timestamp_bypass": e.timestamp.isoformat()},
                        log_entries=[e.line_number],
                        timestamp=e.timestamp,
                    ))

    # --- 4) Extraction massive (volume) ---
    def detect_massive_queries(self) -> None:
        for sid, s in self.sessions.items():
            if s.total_queries > QUERY_THRESHOLD_CRITICAL:
                self.alerts.append(Alert(
                    severity=Severity.CRITICAL,
                    category="EXTRACTION_MASSIVE",
                    title="Volume de requêtes critique",
                    description=(f"Session '{sid}' — '{s.user}' : {s.total_queries} requêtes effectives "
                                 f"(mode={s.query_count_mode})."),
                    indicators={"user": s.user, "session_id": sid, "total_queries": str(s.total_queries),
                                "mode": s.query_count_mode, "max_seen": str(s.max_query_count_seen)},
                    log_entries=s.line_numbers,
                    timestamp=s.start_time,
                ))
            elif s.total_queries > QUERY_THRESHOLD_WARNING:
                self.alerts.append(Alert(
                    severity=Severity.WARNING,
                    category="VOLUME_ANORMAL",
                    title="Volume de requêtes élevé",
                    description=(f"Session '{sid}' — '{s.user}' : {s.total_queries} requêtes effectives "
                                 f"(mode={s.query_count_mode})."),
                    indicators={"user": s.user, "session_id": sid, "total_queries": str(s.total_queries),
                                "mode": s.query_count_mode},
                    log_entries=s.line_numbers,
                    timestamp=s.start_time,
                ))

    # --- 5) Exports ---
    def detect_exports(self) -> None:
        for sid, s in self.sessions.items():
            if not s.has_export:
                continue
            sev = Severity.CRITICAL if s.export_volume >= EXPORT_VOLUME_CRITICAL else Severity.WARNING
            self.alerts.append(Alert(
                severity=sev,
                category="EXPORT_DONNEES",
                title="Export détecté",
                description=(f"Session '{sid}' — '{s.user}' : export_volume={s.export_volume} (mode={s.query_count_mode})."),
                indicators={"user": s.user, "session_id": sid, "export_volume": str(s.export_volume),
                            "ips": ", ".join(sorted(s.ips))},
                log_entries=s.line_numbers,
                timestamp=s.start_time,
            ))

    # --- 6) Rafales ---
    def detect_burst_activity(self) -> None:
        window = timedelta(seconds=BURST_WINDOW_SECONDS)

        for sid, s in self.sessions.items():
            evs = [e for e in s.entries if e.action in ("SEARCH", "EXPORT") and e.effective_queries > 0]
            if len(evs) < 2:
                continue

            dq = deque()  # (ts, eff, line)
            sum_q = 0

            for e in evs:
                dq.append((e.timestamp, e.effective_queries, e.line_number))
                sum_q += e.effective_queries

                while dq and (e.timestamp - dq[0][0]) > window:
                    _, q_old, _ = dq.popleft()
                    sum_q -= q_old

                if sum_q >= BURST_QUERY_THRESHOLD and len(dq) >= 2:
                    delta_sec = max(1.0, (dq[-1][0] - dq[0][0]).total_seconds())
                    qps = sum_q / delta_sec
                    self.alerts.append(Alert(
                        severity=Severity.CRITICAL,
                        category="RAFALE_REQUETES",
                        title="Rafale détectée",
                        description=(f"Session '{sid}' — '{s.user}' : {sum_q} requêtes en {delta_sec:.0f}s "
                                     f"({qps:.1f} req/s)."),
                        indicators={"user": s.user, "session_id": sid,
                                    "queries_in_window": str(sum_q),
                                    "window_seconds": f"{delta_sec:.0f}",
                                    "queries_per_second": f"{qps:.1f}"},
                        log_entries=[x[2] for x in dq],
                        timestamp=dq[0][0],
                    ))
                    break

    # --- 7) Changement IP par utilisateur ---
    def detect_ip_change_per_user(self) -> None:
        user_ips: Dict[str, Set[str]] = defaultdict(set)
        user_sids: Dict[str, List[str]] = defaultdict(list)
        user_lines: Dict[str, Set[int]] = defaultdict(set)

        for sid, s in self.sessions.items():
            user_ips[s.user].update(s.ips)
            user_sids[s.user].append(sid)
            user_lines[s.user].update(s.line_numbers)

        for user, ips in user_ips.items():
            if len(ips) <= 1:
                continue
            has_ext = any(self._is_valid_ip(ip) and not self._is_internal_ip(ip) for ip in ips)
            self.alerts.append(Alert(
                severity=Severity.CRITICAL if has_ext else Severity.WARNING,
                category="CHANGEMENT_IP",
                title="Utilisateur sur plusieurs IP",
                description=(f"'{user}' observé sur {len(ips)} IP : {', '.join(sorted(ips))}. "
                             + ("Présence d'IP(s) externe(s)." if has_ext else "Toutes internes, mais inhabituel.")),
                indicators={"user": user, "ip_count": str(len(ips)),
                            "ips": ", ".join(sorted(ips)),
                            "sessions": ", ".join(user_sids[user])},
                log_entries=sorted(user_lines[user]),
                timestamp=None,
            ))

    # --- 8) Sessions concurrentes ---
    def detect_concurrent_sessions(self) -> None:
        user_sessions: Dict[str, List[SessionInfo]] = defaultdict(list)
        for s in self.sessions.values():
            if s.start_time and s.end_time:
                user_sessions[s.user].append(s)

        for user, sess_list in user_sessions.items():
            ordered = sorted(sess_list, key=lambda x: x.start_time or datetime.min.replace(tzinfo=timezone.utc))

            active_end: Optional[datetime] = None
            active_sid: Optional[str] = None
            active_ips: Optional[str] = None

            for s in ordered:
                if active_end and s.start_time and s.start_time < active_end:
                    lines = []
                    if active_sid and active_sid in self.sessions:
                        lines.extend(self.sessions[active_sid].line_numbers)
                    lines.extend(s.line_numbers)

                    self.alerts.append(Alert(
                        severity=Severity.WARNING,
                        category="SESSIONS_CONCURRENTES",
                        title="Sessions concurrentes",
                        description=(f"'{user}' — chevauchement entre '{active_sid}' et '{s.session_id}'."),
                        indicators={
                            "user": user,
                            "session_1": active_sid or "N/A",
                            "session_2": s.session_id,
                            "ips_1": active_ips or "",
                            "ips_2": ", ".join(sorted(s.ips)),
                        },
                        log_entries=sorted(set(lines)),
                        timestamp=s.start_time,
                    ))

                if s.end_time and (active_end is None or s.end_time > active_end):
                    active_end = s.end_time
                    active_sid = s.session_id
                    active_ips = ", ".join(sorted(s.ips))

    # --- Utilitaires ---
    def _is_valid_ip(self, ip_str: str) -> bool:
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    def _is_internal_ip(self, ip_str: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in net for net in INTERNAL_NETWORKS)
        except ValueError:
            return False

    def get_alerts_by_severity(self, sev: Severity) -> List[Alert]:
        return [a for a in self.alerts if a.severity == sev]

    def get_summary(self) -> Dict[str, object]:
        return {
            "total_entries": len(self.entries),
            "total_sessions": len(self.sessions),
            "total_alerts": len(self.alerts),
            "critical": len(self.get_alerts_by_severity(Severity.CRITICAL)),
            "warning": len(self.get_alerts_by_severity(Severity.WARNING)),
            "info": len(self.get_alerts_by_severity(Severity.INFO)),
            "unique_users": len({e.user for e in self.entries}),
            "unique_ips": len({e.ip for e in self.entries}),
            "date_range": {
                "start": min((e.timestamp for e in self.entries), default=None).isoformat() if self.entries else "N/A",
                "end": max((e.timestamp for e in self.entries), default=None).isoformat() if self.entries else "N/A",
            },
        }


# =============================================================================
# RAPPORT
# =============================================================================

class ReportGenerator:
    ICONS = {Severity.CRITICAL: "🔴", Severity.WARNING: "🟡", Severity.INFO: "🔵"}

    @staticmethod
    def generate_text(analyzer: FICOBAAnalyzer, parse_errors: List[Tuple[int, str, str]]) -> str:
        lines: List[str] = []
        sep = "=" * 80
        sep2 = "-" * 80
        summary = analyzer.get_summary()

        lines += [
            sep,
            "  RAPPORT D'ANALYSE SOC — FICOBA SOC Log Analyzer",
            f"  Généré le : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            sep, "",
            "  RÉSUMÉ", sep2,
            f"  Entrées analysées    : {summary['total_entries']}",
            f"  Sessions identifiées : {summary['total_sessions']}",
            f"  Utilisateurs uniques : {summary['unique_users']}",
            f"  IPs uniques          : {summary['unique_ips']}",
            f"  Période              : {summary['date_range']['start']} → {summary['date_range']['end']}",
            "",
            f"  🔴 CRITIQUES  : {summary['critical']}",
            f"  🟡 WARNING    : {summary['warning']}",
            f"  🔵 INFO       : {summary['info']}",
            f"  Total alertes : {summary['total_alerts']}",
        ]

        if parse_errors:
            lines += ["", f"  ⚠️  Erreurs de parsing : {len(parse_errors)}"]
            for ln, _, err in parse_errors[:5]:
                lines.append(f"     Ligne {ln} : {err}")
            if len(parse_errors) > 5:
                lines.append(f"     … et {len(parse_errors) - 5} autre(s)")

        lines += ["", sep, "  ALERTES DÉTAILLÉES", sep]

        if not analyzer.alerts:
            lines.append("  ✅ Aucune alerte — aucune activité suspecte détectée.")
        else:
            for i, alert in enumerate(analyzer.alerts, 1):
                icon = ReportGenerator.ICONS.get(alert.severity, "⚪")
                lines += [
                    "",
                    f"  {icon} ALERTE #{i} [{alert.severity.value}] — {alert.category}",
                    f"  {sep2}",
                    f"  Titre       : {alert.title}",
                    f"  Description : {alert.description}",
                    f"  Indicateurs :",
                ]
                for k, v in alert.indicators.items():
                    lines.append(f"    • {k} : {v}")
                lines.append(f"  Lignes log  : {', '.join(str(n) for n in alert.log_entries)}")
                if alert.timestamp:
                    lines.append(f"  Horodatage  : {alert.timestamp.isoformat()}")

        return "\n".join(lines)

    @staticmethod
    def generate_json(analyzer: FICOBAAnalyzer, parse_errors: List[Tuple[int, str, str]]) -> str:
        report = {
            "metadata": {
                "tool": "FICOBA SOC Log Analyzer",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "version": "2.0.0",
            },
            "summary": analyzer.get_summary(),
            "alerts": [
                {
                    "severity": a.severity.value,
                    "category": a.category,
                    "title": a.title,
                    "description": a.description,
                    "indicators": a.indicators,
                    "log_lines": a.log_entries,
                    "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                }
                for a in analyzer.alerts
            ],
            "parse_errors": [{"line": ln, "error": err} for ln, _, err in parse_errors],
        }
        return json.dumps(report, indent=2, ensure_ascii=False)


# =============================================================================
# CLI / MAIN
# =============================================================================

def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main() -> int:
    cli = argparse.ArgumentParser(
        description="FICOBA SOC Log Analyzer — Outil d'analyse post-incident",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    cli.add_argument("--logfile", "-l", required=True, help="Chemin vers le fichier de logs FICOBA")
    cli.add_argument("--output", "-o", default=None, help="Fichier de sortie (défaut: stdout)")
    cli.add_argument("--json", "-j", action="store_true", dest="json_output", help="Sortie au format JSON")
    cli.add_argument("--verbose", "-v", action="store_true", help="Logs debug")
    args = cli.parse_args()

    setup_logging(args.verbose)
    logger = logging.getLogger("main")

    try:
        logger.info("Lecture du fichier: %s", args.logfile)
        parser = LogParser()
        entries = parser.parse_file(args.logfile)

        if not entries:
            print("⚠️  Aucune entrée valide trouvée. Vérifie le format du fichier.")
            return 1

        analyzer = FICOBAAnalyzer(entries)
        analyzer.run_all_detections()

        report = (
            ReportGenerator.generate_json(analyzer, parser.parse_errors)
            if args.json_output
            else ReportGenerator.generate_text(analyzer, parser.parse_errors)
        )

        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report)
            print(f"✅ Rapport généré : {args.output}")
        else:
            print(report)

        if analyzer.get_summary()["critical"] > 0:
            logger.warning("Alerte(s) critique(s) détectée(s)")
            return 2
        return 0

    except FileNotFoundError as exc:
        print(f"❌ {exc}")
        return 1
    except PermissionError as exc:
        print(f"❌ {exc}")
        return 1
    except KeyboardInterrupt:
        print("\n⚠️  Analyse interrompue.")
        return 130
    except Exception as exc:
        logger.critical("Erreur inattendue: %s", exc, exc_info=True)
        print(f"❌ Erreur inattendue : {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
