#!/usr/bin/env bash
# Capture lab traffic (headers only) from the isolated lab bridge.
#   usage: bash scripts/capture.sh <name> [seconds]        e.g.  bash scripts/capture.sh normal 720
# - Only the lab network (bridge trustadapt0) is sniffed: nothing from your home/university network.
# - Snap length 128 bytes = Ethernet/IP/TCP|UDP headers only. Payloads are never stored (FR-02, NFR-05).
# - Runs tcpdump in a container on the Docker host network, so it works with Docker Desktop + WSL2.
set -euo pipefail
NAME="${1:?usage: capture.sh <name> [seconds]}"
DUR="${2:-720}"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="$(pwd)/data/raw"
FILE="${NAME}_${STAMP}.pcap"
mkdir -p "$OUT_DIR"
echo "[capture] ${DUR}s on trustadapt0 -> data/raw/${FILE}"
docker run --rm --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -v "${OUT_DIR}:/out" nicolaka/netshoot \
  sh -c "tcpdump -i trustadapt0 -n -s 128 -G ${DUR} -W 1 -w /out/${FILE} && chmod a+r /out/${FILE}"
echo "[capture] done: $(ls -lh "data/raw/${FILE}" | awk '{print $5, $9}')"
