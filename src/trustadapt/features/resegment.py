"""Undo TCP segmentation offload (TSO / GSO / GRO) in a capture.

Why this exists: on a Docker bridge a sender hands the kernel one big TCP write and the kernel passes it along as a single
"super frame" of up to 64 KB; the capture then records ONE packet where a physical link would carry many frames of at most
1514 bytes. The first real capture showed it: in all 72 windows of the camera the standard deviation of the packet size was
larger than is possible for frames of at most 1514 bytes, and exfiltration windows had a mean packet size of about 6,300 bytes.
Left alone this lowers packet_rate_10s and inflates the size statistics.

The fix splits every TCP frame larger than the MTU frame into the frames a normal Ethernet link would have carried, all with
the timestamp of the original (they travel back to back, well inside the 1 ms resolution of the timestamps). Assumed headers
are 66 bytes (Ethernet 14 + IPv4 20 + TCP 32 with the usual timestamp option), so a full segment carries 1448 payload bytes.
Bytes stay consistent: the split adds one header per extra segment, exactly what the wire would have carried.
Only TCP is split (that is what offload merges); UDP and ICMP frames are left as captured.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

MTU_FRAME = 1514      # largest frame on normal Ethernet: 14 header bytes + 1500 MTU
TCP_HEADERS = 66      # Ethernet 14 + IPv4 20 + TCP 32 (timestamp option)


def segment_sizes(size: int, mtu: int = MTU_FRAME) -> list[int]:
    """Frame sizes a link would carry for one captured TCP frame of `size` bytes (readable reference version)."""
    if not mtu or size <= mtu:
        return [int(size)]
    mss = mtu - TCP_HEADERS
    full, rest = divmod(int(size) - TCP_HEADERS, mss)
    sizes = [mtu] * full
    if rest:
        sizes.append(TCP_HEADERS + rest)
    return sizes


def expand_tcp_frames(pk: pd.DataFrame, is_tcp: np.ndarray, mtu: int | None = MTU_FRAME) -> tuple[pd.DataFrame, int, int]:
    """Vectorised split of oversized TCP frames in a packet table (columns fi, t, size, dir, ...).

    Returns (new table, number of frames that were split, number of packets added). Rows keep their order; the pieces
    of one frame follow each other with the same time and direction. mtu = None or 0 returns the table unchanged.
    """
    if not mtu or pk.empty:
        return pk, 0, 0
    size = pk["size"].to_numpy(dtype=np.int64)
    mss = mtu - TCP_HEADERS
    big = np.asarray(is_tcp, dtype=bool) & (size > mtu)
    if not big.any():
        return pk, 0, 0
    payload = size - TCP_HEADERS
    n = np.where(big, -(-payload // mss), 1)                      # ceil(payload / mss) pieces; 1 for normal frames
    rep = np.repeat(np.arange(len(pk)), n)
    out = pk.iloc[rep].reset_index(drop=True)
    n_rep = n[rep]
    seg = np.arange(len(out)) - (np.cumsum(n) - n)[rep]           # 0, 1, 2 ... inside each original frame
    last = seg == n_rep - 1
    new_size = np.where(n_rep > 1, np.where(last, TCP_HEADERS + payload[rep] - (n_rep - 1) * mss, mtu), size[rep])
    out["size"] = new_size
    return out, int(big.sum()), int(n.sum() - len(pk))
