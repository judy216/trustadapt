#!/usr/bin/env bash
# pcap -> features CSV -> validation.
#   usage: bash scripts/run_pipeline.sh data/raw/normal_XXXX.pcap [baseline.json]
# Without a baseline the first 50 windows are the LEARNING period (use this for NORMAL captures).
# With a baseline (from a normal capture) flags are computed from the first window (use for ATTACK captures).
set -euo pipefail
PCAP="${1:?usage: run_pipeline.sh <pcap> [baseline.json]}"
BASE="${2:-}"
STEM="$(basename "${PCAP%.pcap}")"
OUT="data/processed/${STEM}_features.csv"
ARGS=(--devices lab/devices.csv)
[[ -n "$BASE" ]] && ARGS+=(--baseline-from "$BASE")
python -m trustadapt.features.extract "$PCAP" -o "$OUT" "${ARGS[@]}"
python -m trustadapt.features.validate "$PCAP" "$OUT"
