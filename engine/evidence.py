"""Per-run evidence store — raw tool output plus normalized artefacts on disk.

Everything a run produces lands under output/run-<UTC timestamp>/ so results are
reproducible and auditable: raw/ holds the untouched tool output, and the run root
holds the normalized findings, metadata, and reports. Timestamps are colon-free so
the paths are valid on Windows.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone


def _timestamp_slug() -> str:
    return datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ")


class EvidenceStore:
    def __init__(self, output_dir: str) -> None:
        self.output_dir = output_dir
        self.run_id = _timestamp_slug()
        self.run_dir = os.path.join(output_dir, self.run_id)
        self.raw_dir = os.path.join(self.run_dir, "raw")
        os.makedirs(self.raw_dir, exist_ok=True)

    def save_raw(self, name: str, content) -> str:
        """Persist untouched tool output (dict/list serialized as JSON, else text)."""
        path = os.path.join(self.raw_dir, name)
        if isinstance(content, (dict, list)):
            data = json.dumps(content, indent=2, ensure_ascii=False)
        else:
            data = "" if content is None else str(content)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(data)
        return path

    def save_json(self, name: str, obj) -> str:
        path = os.path.join(self.run_dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(obj, handle, indent=2, ensure_ascii=False)
        return path

    def save_text(self, name: str, text: str) -> str:
        path = os.path.join(self.run_dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def save_findings(self, findings) -> str:
        return self.save_json("findings.json", [f.to_dict() for f in findings])

    def save_metadata(self, metadata: dict) -> str:
        return self.save_json("metadata.json", metadata)

    def path(self, *parts: str) -> str:
        return os.path.join(self.run_dir, *parts)
