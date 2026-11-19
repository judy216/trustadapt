"""Synthetic lab traffic (scapy) - lets the pipeline be tested without the Docker lab.

Three simulated IoT devices on one subnet, with fixed MACs (same as lab/docker-compose.yml):

    cam-01   02:42:0a:4d:00:11  HTTP uploads to the cloud every ~3 s + MQTT heartbeat
    therm-01 02:42:0a:4d:00:12  MQTT publish every 5 s + HTTP check every 30 s
    sensor-01 02:42:0a:4d:00:13 CoAP (UDP) request/response every 4 s

Scenarios:
    normal  720 s of normal behaviour (72 windows -> enough for the 50-window baseline)
    attack  720 s; cam-01 is "compromised": UDP flood (300-360 s), port scan (400-430 s),
            exfiltration to many new destinations (500-560 s)

Packets carry zero-filled payloads only (no real data), and are written in time order.
"""
from __future__ import annotations

import argparse
import random
from pathlib import Path

from scapy.all import IP, TCP, UDP, Ether, PcapWriter, Raw

GW_MAC, BROKER_MAC, CLOUD_MAC = "02:42:0a:4d:00:01", "02:42:0a:4d:00:02", "02:42:0a:4d:00:64"
BROKER_IP, CLOUD_IP = "10.77.0.2", "10.77.0.100"
DEVICES = {
    "cam-01":    ("02:42:0a:4d:00:11", "10.77.0.11", "camera"),
    "therm-01":  ("02:42:0a:4d:00:12", "10.77.0.12", "thermostat"),
    "sensor-01": ("02:42:0a:4d:00:13", "10.77.0.13", "sensor"),
}
T0 = 1_760_000_000.0           # fixed epoch start (multiple of 10 s) -> reproducible windows
DURATION = 720


class Builder:
    def __init__(self, seed: int = 7):
        self.pkts: list[tuple[float, object]] = []
        self.rng = random.Random(seed)
        self._port = 40000

    def port(self) -> int:
        self._port += 1
        if self._port > 60000:
            self._port = 40000
        return self._port

    def add(self, t, pkt):
        self.pkts.append((t, pkt))

    # ---- protocol helpers ------------------------------------------------------------
    def tcp(self, t, cmac, smac, cip, sip, sport, up=(), down=(), cport=None, rtt=0.002, close=True):
        """Full TCP session: handshake, request/response data, FIN."""
        cport = cport or self.port()
        e_c, e_s = Ether(src=cmac, dst=smac), Ether(src=smac, dst=cmac)
        ip_c, ip_s = IP(src=cip, dst=sip), IP(src=sip, dst=cip)
        seq_c, seq_s = 1000, 5000
        self.add(t, e_c / ip_c / TCP(sport=cport, dport=sport, flags="S", seq=seq_c))
        self.add(t + rtt, e_s / ip_s / TCP(sport=sport, dport=cport, flags="SA", seq=seq_s, ack=seq_c + 1))
        self.add(t + 2 * rtt, e_c / ip_c / TCP(sport=cport, dport=sport, flags="A", seq=seq_c + 1, ack=seq_s + 1))
        seq_c += 1
        seq_s += 1
        tt = t + 3 * rtt
        for n in up:
            self.add(tt, e_c / ip_c / TCP(sport=cport, dport=sport, flags="PA", seq=seq_c, ack=seq_s) / Raw(b"\x00" * n))
            seq_c += n
            tt += rtt
        for n in down:
            self.add(tt, e_s / ip_s / TCP(sport=sport, dport=cport, flags="PA", seq=seq_s, ack=seq_c) / Raw(b"\x00" * n))
            seq_s += n
            tt += rtt
        if close:
            self.add(tt, e_c / ip_c / TCP(sport=cport, dport=sport, flags="FA", seq=seq_c, ack=seq_s))
            self.add(tt + rtt, e_s / ip_s / TCP(sport=sport, dport=cport, flags="FA", seq=seq_s, ack=seq_c + 1))
            self.add(tt + 2 * rtt, e_c / ip_c / TCP(sport=cport, dport=sport, flags="A", seq=seq_c + 1, ack=seq_s + 1))

    def tcp_refused(self, t, cmac, smac, cip, sip, dport):
        """SYN answered by RST (closed port): a 'failed connection' (no SYN-ACK)."""
        cport = self.port()
        self.add(t, Ether(src=cmac, dst=smac) / IP(src=cip, dst=sip) / TCP(sport=cport, dport=dport, flags="S"))
        self.add(t + 0.001, Ether(src=smac, dst=cmac) / IP(src=sip, dst=cip) / TCP(sport=dport, dport=cport, flags="RA"))

    def udp(self, t, cmac, smac, cip, sip, sport, up, down=0, cport=None):
        cport = cport or self.port()
        self.add(t, Ether(src=cmac, dst=smac) / IP(src=cip, dst=sip) / UDP(sport=cport, dport=sport) / Raw(b"\x00" * up))
        if down:
            self.add(t + 0.003, Ether(src=smac, dst=cmac) / IP(src=sip, dst=cip) / UDP(sport=sport, dport=cport) / Raw(b"\x00" * down))

    # ---- normal behaviour --------------------------------------------------------------
    def normal(self, duration=DURATION):
        r = self.rng
        cam_mac, cam_ip, _ = DEVICES["cam-01"]
        th_mac, th_ip, _ = DEVICES["therm-01"]
        se_mac, se_ip, _ = DEVICES["sensor-01"]
        # camera: HTTP upload every ~3 s, MQTT heartbeat every 10 s
        t = 0.5
        while t < duration:
            self.tcp(T0 + t, cam_mac, CLOUD_MAC, cam_ip, CLOUD_IP, 80,
                     up=[1400] * r.randint(3, 5), down=[200])
            t += r.uniform(2.5, 3.5)
        t = 1.0
        while t < duration:
            self.tcp(T0 + t, cam_mac, BROKER_MAC, cam_ip, BROKER_IP, 1883, up=[80], down=[20])
            t += 10
        # thermostat: MQTT publish every 5 s (small), HTTP check every 30 s
        t = 2.0
        while t < duration:
            self.tcp(T0 + t, th_mac, BROKER_MAC, th_ip, BROKER_IP, 1883, up=[r.randint(60, 90)], down=[20])
            t += r.uniform(4.5, 5.5)
        t = 7.0
        while t < duration:
            self.tcp(T0 + t, th_mac, CLOUD_MAC, th_ip, CLOUD_IP, 80, up=[300], down=[600])
            t += 30
        # sensor: CoAP every ~4 s
        t = 1.5
        while t < duration:
            self.udp(T0 + t, se_mac, CLOUD_MAC, se_ip, CLOUD_IP, 5683, up=r.randint(40, 60), down=30)
            t += r.uniform(3.5, 4.5)

    # ---- attacks on cam-01 -----------------------------------------------------------------
    def attack(self):
        cam_mac, cam_ip, _ = DEVICES["cam-01"]
        # 1) UDP flood to the cloud: ~250 pkt/s for 60 s
        t = 300.0
        while t < 360:
            self.udp(T0 + t, cam_mac, CLOUD_MAC, cam_ip, CLOUD_IP, 9999, up=1000, cport=50000)
            t += 0.004
        # 2) port scan: 20 SYN/s against 600 ports of the cloud server (closed -> RST)
        for i, dport in enumerate(range(1000, 1600)):
            self.tcp_refused(T0 + 400 + i / 20, cam_mac, CLOUD_MAC, cam_ip, CLOUD_IP, dport)
        # 3) exfiltration: 37 never-seen destinations on port 8080, big uploads
        for i in range(37):
            self.tcp(T0 + 500 + i * 1.5, cam_mac, GW_MAC, cam_ip, f"10.77.0.{150 + i}", 8080,
                     up=[1400] * 30, down=[100])

    def write(self, path: str | Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.pkts.sort(key=lambda x: x[0])
        with PcapWriter(str(path), sync=True) as w:
            for t, p in self.pkts:
                p.time = t
                w.write(p)


def write_devices_csv(path: str | Path) -> None:
    lines = ["mac,name,type"] + [f"{m},{n},{t}" for n, (m, _, t) in DEVICES.items()]
    Path(path).write_text("\n".join(lines) + "\n")


def generate(scenario: str, out: str | Path, seed: int = 7) -> Path:
    b = Builder(seed)
    b.normal()
    if scenario == "attack":
        b.attack()
    elif scenario != "normal":
        raise ValueError("scenario must be 'normal' or 'attack'")
    b.write(out)
    return Path(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Generate synthetic IoT lab traffic (pcap)")
    ap.add_argument("scenario", choices=["normal", "attack"])
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args(argv)
    generate(a.scenario, a.out, a.seed)
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
