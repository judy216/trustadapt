#!/usr/bin/env bash
# One-time setup inside Ubuntu 24.04 (WSL2 on Windows, or a native Ubuntu machine).
set -euo pipefail
sudo apt-get update
sudo apt-get install -y python3-venv python3-pip git tcpdump
python3 --version                       # expect 3.12.x on Ubuntu 24.04
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
pip install pytest
pytest -q                               # self-test on synthetic traffic (about 20 s)
echo "Setup OK. Activate later with:  source .venv/bin/activate"
