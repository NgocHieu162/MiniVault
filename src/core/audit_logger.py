"""
src/core/audit_logger.py — Tamper-Evident Hash-Chained Audit Log

Each log entry is stored as a JSONL line containing:
  index, timestamp, event, prev_hash, hash

where hash = SHA256(f"{index}|{timestamp}|{event}|{prev_hash}")

This forms a chain: tampering with ANY entry invalidates all subsequent
hashes and is instantly detected by verify_integrity().
"""

import hashlib
import json
import os
import time
from typing import List, Optional


LOG_DIR = os.path.join("data", "logs")
LOG_PATH = os.path.join(LOG_DIR, "audit.log")

_GENESIS_HASH = "0" * 64  # Sentinel value for the first entry


class AuditLogger:
    """Append-only, hash-chained audit log.

    Every call to log() appends one JSONL entry to LOG_PATH.
    The entry embeds the SHA-256 hash of the previous entry,
    creating a tamper-evident chain.

    verify_integrity() replays the chain and returns True only if
    every entry's hash matches its recorded fields.
    """

    def __init__(self, log_path: str = LOG_PATH):
        self.log_path = log_path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_hash(index: int, timestamp: str, event: str, prev_hash: str) -> str:
        payload = f"{index}|{timestamp}|{event}|{prev_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _read_entries(self) -> List[dict]:
        """Load all JSONL entries from the log file."""
        if not os.path.exists(self.log_path):
            return []
        entries = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        # Treat malformed lines as tampering evidence
                        entries.append({"__malformed__": True})
        return entries

    def _last_hash(self) -> str:
        """Returns the hash of the most recent log entry (or genesis hash if empty)."""
        entries = self._read_entries()
        if not entries:
            return _GENESIS_HASH
        last = entries[-1]
        return last.get("hash", _GENESIS_HASH)

    def _last_index(self) -> int:
        """Returns the index of the most recent log entry (-1 if empty)."""
        entries = self._read_entries()
        if not entries:
            return -1
        return entries[-1].get("index", len(entries) - 1)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log(self, event: str) -> None:
        """Append one event to the hash-chained audit log.

        Args:
            event: A human-readable event description string.
        """
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        index = self._last_index() + 1
        prev_hash = self._last_hash()
        entry_hash = self._compute_hash(index, timestamp, event, prev_hash)

        entry = {
            "index": index,
            "timestamp": timestamp,
            "event": event,
            "prev_hash": prev_hash,
            "hash": entry_hash,
        }

        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except IOError:
            pass  # Never let logging errors crash the main service

    def verify_integrity(self) -> dict:
        """Verify the integrity of the entire audit log chain.

        Returns:
            A dict with:
              - "intact": bool — True if the entire chain is valid
              - "total_entries": int
              - "tampered_at_index": int | None — first tampered entry index, or None
              - "message": str — human-readable summary
        """
        entries = self._read_entries()
        if not entries:
            return {
                "intact": True,
                "total_entries": 0,
                "tampered_at_index": None,
                "message": "Log is empty. No entries to verify.",
            }

        prev_hash = _GENESIS_HASH
        for entry in entries:
            if "__malformed__" in entry:
                return {
                    "intact": False,
                    "total_entries": len(entries),
                    "tampered_at_index": entries.index(entry),
                    "message": f"Malformed (non-JSON) line detected at index {entries.index(entry)}.",
                }

            index = entry.get("index")
            timestamp = entry.get("timestamp", "")
            event = entry.get("event", "")
            recorded_prev_hash = entry.get("prev_hash", "")
            recorded_hash = entry.get("hash", "")

            # Check 1: prev_hash continuity
            if recorded_prev_hash != prev_hash:
                return {
                    "intact": False,
                    "total_entries": len(entries),
                    "tampered_at_index": index,
                    "message": f"Hash chain broken at index {index}: prev_hash mismatch.",
                }

            # Check 2: hash of current entry
            expected_hash = self._compute_hash(index, timestamp, event, prev_hash)
            if recorded_hash != expected_hash:
                return {
                    "intact": False,
                    "total_entries": len(entries),
                    "tampered_at_index": index,
                    "message": f"Entry at index {index} has been tampered with (hash mismatch).",
                }

            prev_hash = recorded_hash

        return {
            "intact": True,
            "total_entries": len(entries),
            "tampered_at_index": None,
            "message": f"All {len(entries)} log entries are intact. Chain verified.",
        }

    def get_entries(self, limit: Optional[int] = None) -> List[dict]:
        """Return the last `limit` entries (or all entries if limit is None)."""
        entries = self._read_entries()
        if limit:
            return entries[-limit:]
        return entries


# Module-level singleton for easy import
_default_logger = AuditLogger()


def audit_log(event: str) -> None:
    """Module-level convenience function to log an event."""
    _default_logger.log(event)
