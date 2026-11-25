#!/usr/bin/env bash
# pcap -> features CSV -> validation.
#   usage: [TA_DB=data/trustadapt.db] bash scripts/run_pipeline.sh data/raw/normal_XXXX.pcap [baseline.json]
# Without a baseline the first 50 windows are the LEARNING period (use this for NORMAL captures).
# With a baseline (from a normal capture) flags are computed from the first window (use for ATTACK captures).
set -euo pipefail
PCAP="${1:?usage: run_pipeline.sh <pcap> [baseline.json]}"
BASE="${2:-}"
STEM="$(basename "${PCAP%.pcap}")"
OUT="data/processed/${STEM}_features.csv"
ARGS=(--devices lab/devices.csv)
[[ -n "$BASE" ]] && ARGS+=(--baseline-from "$BASE")
[[ -n "${TA_DB:-}" ]] && ARGS+=(--db "$TA_DB")      # optional: also write to the shared SQLite store
MTU=(); [[ -n "${TA_MTU:-}" ]] && MTU=(--mtu "$TA_MTU")   # optional: 0 = keep frames as captured; extract and validate share it
python -m trustadapt.features.extract "$PCAP" -o "$OUT" "${ARGS[@]}" "${MTU[@]}"
python -m trustadapt.features.validate "$PCAP" "$OUT" "${MTU[@]}"
