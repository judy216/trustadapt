"""Simulated IoT device for the isolated lab network (runs inside Docker only).

DEVICE_TYPE: camera | thermostat | sensor     (normal behaviour)
Attack modes (run inside a device container, e.g. the 'compromised' camera):
    docker compose exec cam-01 python device.py --attack flood  [--seconds 60]
    docker compose exec cam-01 python device.py --attack scan   [--seconds 30]
    docker compose exec cam-01 python device.py --attack exfil  [--seconds 60]
All traffic stays inside the lab bridge network. Payloads are zero-filled dummy bytes.
"""
import argparse
import os
import random
import socket
import time
import urllib.request

import paho.mqtt.client as mqtt

BROKER = os.environ.get("BROKER_HOST", "broker")
CLOUD = os.environ.get("CLOUD_HOST", "cloud")
NAME = os.environ.get("DEVICE_NAME", "device")
KIND = os.environ.get("DEVICE_TYPE", "sensor")


def cloud_ips():
    return sorted({i[4][0] for i in socket.getaddrinfo(CLOUD, 80, socket.AF_INET, socket.SOCK_STREAM)})


def mqtt_client():
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=NAME)
    c.connect(BROKER, 1883, keepalive=30)
    c.loop_start()
    return c


def http_post(n_bytes):
    req = urllib.request.Request(f"http://{CLOUD}/upload", data=b"\x00" * n_bytes, method="POST")
    try:
        urllib.request.urlopen(req, timeout=5).read()
    except Exception:
        pass                      # python http.server answers 501 to POST - traffic is what matters


def http_get(path="/"):
    try:
        urllib.request.urlopen(f"http://{CLOUD}{path}", timeout=5).read()
    except Exception:
        pass


def run_normal():
    c = mqtt_client()
    last_http = 0.0
    while True:
        if KIND == "camera":
            http_post(random.randint(3, 5) * 1400)
            c.publish(f"lab/{NAME}/heartbeat", b"\x00" * 60)
            time.sleep(random.uniform(2.5, 3.5))
        elif KIND == "thermostat":
            c.publish(f"lab/{NAME}/temp", b"\x00" * random.randint(40, 60))
            if time.time() - last_http > 30:
                http_get()
                last_http = time.time()
            time.sleep(random.uniform(4.5, 5.5))
        else:  # sensor
            c.publish(f"lab/{NAME}/reading", b"\x00" * random.randint(20, 40))
            time.sleep(random.uniform(3.5, 4.5))


def attack_flood(seconds):
    """UDP flood to the cloud server (~hundreds of packets/s) -> traffic_spike_flag + unusual_port_flag."""
    dst = (cloud_ips()[0], 9999)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end = time.time() + seconds
    while time.time() < end:
        s.sendto(b"\x00" * 1000, dst)
        time.sleep(0.004)


def attack_scan(seconds):
    """TCP connect scan of closed ports on the cloud server -> failed_conn_count + unusual_port_flag."""
    ip, end, port = cloud_ips()[0], time.time() + seconds, 1000
    while time.time() < end and port < 6000:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        try:
            s.connect((ip, port))
        except OSError:
            pass
        s.close()
        port += 1
        time.sleep(0.05)


def attack_exfil(seconds):
    """Upload to many never-contacted hosts on port 8080 (ext-01..ext-08, 10.77.0.151-158)
    -> new_destination_count + unusual_port_flag + large bytes_sent_rate."""
    base = socket.gethostbyname(CLOUD).rsplit(".", 1)[0]
    targets = [f"{base}.{n}" for n in range(151, 159)]
    end = time.time() + seconds
    while time.time() < end:
        for ip in targets:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            try:
                s.connect((ip, 8080))
                s.sendall(b"\x00" * 200_000)
            except OSError:
                pass
            s.close()
            time.sleep(0.5)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", choices=["flood", "scan", "exfil"])
    ap.add_argument("--seconds", type=int, default=60)
    a = ap.parse_args()
    if a.attack:
        {"flood": attack_flood, "scan": attack_scan, "exfil": attack_exfil}[a.attack](a.seconds)
    else:
        run_normal()
