from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

CAN_LINE = re.compile(r"(?:\((?P<ts>[^)]+)\)\s+)?(?:\S+\s+)?(?P<id>[0-9A-Fa-f]{3,8})#(?P<data>[0-9A-Fa-f]*)")
HEX_LINE = re.compile(r"^(?P<id>[0-9A-Fa-f]{3,8})\s+(?:\[[0-9]+\]\s+)?(?P<data>(?:[0-9A-Fa-f]{2}\s*)+)$")
SERVICE_NAMES = {
    0x10: "DiagnosticSessionControl", 0x11: "ECUReset", 0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation", 0x22: "ReadDataByIdentifier", 0x23: "ReadMemoryByAddress",
    0x27: "SecurityAccess", 0x2E: "WriteDataByIdentifier", 0x31: "RoutineControl",
    0x34: "RequestDownload", 0x36: "TransferData", 0x37: "RequestTransferExit",
    0x3E: "TesterPresent",
}
SENSITIVE_SERVICES = {0x27, 0x2E, 0x31, 0x34, 0x36, 0x37}


def _hex_data(value: object) -> str:
    raw = str(value or "").strip().replace("0x", "").replace(" ", "").replace(":", "")
    if len(raw) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", raw):
        raise ValueError(f"invalid CAN data: {value}")
    return raw.upper()


def _record(ts: object, arbitration_id: object, data: object, source: str) -> dict:
    ident = str(arbitration_id).strip().lower().replace("0x", "")
    if not re.fullmatch(r"[0-9a-f]{3,8}", ident):
        raise ValueError(f"invalid CAN arbitration ID: {arbitration_id}")
    payload = _hex_data(data)
    return {"timestamp": str(ts or ""), "id": ident.upper(), "data": payload, "length": len(payload) // 2, "source": source}


def parse_file(path: str) -> tuple[list[dict], list[str]]:
    """Parse JSONL, CSV, candump, or simple `ID [len] bytes` text offline."""
    records, errors = [], []
    source = str(path)
    lines = Path(path).read_text(errors="replace").splitlines()
    if not lines:
        return records, errors
    try:
        if lines[0].lstrip().startswith("{"):
            for number, line in enumerate(lines, 1):
                try:
                    item = json.loads(line)
                    records.append(_record(item.get("timestamp", item.get("ts")), item.get("id", item.get("arbitration_id")), item.get("data", item.get("payload")), source))
                except Exception as exc:
                    errors.append(f"{source}:{number}: {exc}")
            return records, errors
        if "," in lines[0] and any(x in lines[0].lower() for x in ("id", "arbitration", "data")):
            for number, row in enumerate(csv.DictReader(lines), 2):
                try:
                    ident = row.get("arbitration_id") or row.get("id") or row.get("can_id")
                    records.append(_record(row.get("timestamp") or row.get("ts"), ident, row.get("data") or row.get("payload"), source))
                except Exception as exc:
                    errors.append(f"{source}:{number}: {exc}")
            return records, errors
    except Exception as exc:
        errors.append(f"{source}: {exc}")
    for number, line in enumerate(lines, 1):
        match = CAN_LINE.search(line) or HEX_LINE.search(line.strip())
        if not match:
            continue
        try:
            records.append(_record(match.groupdict().get("ts"), match.group("id"), match.group("data"), source))
        except Exception as exc:
            errors.append(f"{source}:{number}: {exc}")
    return records, errors


def analyze(records: list[dict]) -> dict:
    by_id: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        by_id[record["id"]].append(record)
    message_stats, anomalies, services = [], [], []
    for ident, items in sorted(by_id.items()):
        lengths = Counter(x["length"] for x in items)
        stat = {"id": ident, "frames": len(items), "lengths": dict(sorted(lengths.items())), "sample_data": items[0]["data"]}
        message_stats.append(stat)
        if len(lengths) > 1:
            anomalies.append({"id": ident, "type": "variable_payload_length", "detail": f"observed lengths: {sorted(lengths)}", "confidence": "review"})
        for item in items:
            if not item["data"]:
                continue
            # ISO-TP single-frame payloads begin with a PCI/length byte; the
            # diagnostic service follows it. Raw service-byte captures are
            # also accepted for simple lab fixtures.
            first_byte = int(item["data"][:2], 16)
            offset = 2 if (first_byte >> 4) == 0 and len(item["data"]) >= 4 else 0
            first = int(item["data"][offset:offset + 2], 16)
            if first in SERVICE_NAMES:
                services.append({"id": ident, "service": f"0x{first:02X}", "name": SERVICE_NAMES[first], "sensitive": first in SENSITIVE_SERVICES, "source": item["source"]})
            elif first == 0x7F and len(item["data"]) >= offset + 6:
                code = int(item["data"][offset + 2:offset + 4], 16)
                services.append({"id": ident, "service": "0x7F", "name": f"NegativeResponse for 0x{code:02X}", "sensitive": code in SENSITIVE_SERVICES, "source": item["source"]})
    unique_services = {(x["id"], x["service"], x["name"]): x for x in services}
    return {"frames": len(records), "ecu_ids": sorted(by_id), "message_stats": message_stats, "anomalies": anomalies, "uds_services": list(unique_services.values())}
