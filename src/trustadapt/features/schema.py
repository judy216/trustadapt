"""Feature schema (FR-03) exactly as defined in the Week 8 report.

19 fields per device per 10 s window + `window_start` metadata.
12 of the fields form the ML input vector (order fixed by ML_FEATURES).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

WINDOW_S = 10                 # primary window length (seconds)
FAILED_CONN_WINDOW_S = 60     # extended window for failed_conn_count
BASELINE_WINDOWS = 50         # FR-04: 50 windows (~8 min) learning period
SPIKE_FACTOR = 3.0            # traffic_spike_flag: rate > 3x baseline mean ...
SPIKE_STD_FACTOR = 3.0        # ... and also > baseline mean + 3 x baseline std (keeps sparse devices from false alarms)


class TransportProtocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"


class AppProtocol(str, Enum):
    MQTT = "MQTT"
    HTTP = "HTTP"
    COAP = "CoAP"
    OTHER = "OTHER"


# nDPI is disabled (n_dissections=0) -> application protocol is inferred from port_dst only
PORT_TO_APP = {
    1883: AppProtocol.MQTT, 8883: AppProtocol.MQTT,
    80: AppProtocol.HTTP, 443: AppProtocol.HTTP,
    5683: AppProtocol.COAP, 5684: AppProtocol.COAP,
}

# NFStream reports the IP protocol number
IP_PROTO_TO_TRANSPORT = {
    6: TransportProtocol.TCP,
    17: TransportProtocol.UDP,
    1: TransportProtocol.ICMP,
    58: TransportProtocol.ICMP,   # ICMPv6
}


def app_from_port(port_dst: int) -> AppProtocol:
    """Best-effort application protocol from the destination port."""
    return PORT_TO_APP.get(int(port_dst), AppProtocol.OTHER)


# Output CSV column order: window_start + the 19 schema fields (same order as report Section 4)
FEATURE_COLUMNS = [
    "window_start",
    "device_mac", "ip_src", "ip_dst", "port_src", "port_dst",
    "protocol_type", "app_protocol",
    "packet_rate_10s", "bytes_sent_rate", "connection_count",
    "new_destination_count", "activity_time",
    "mean_packet_size", "std_packet_size",
    "mean_inter_arrival", "std_inter_arrival",
    "traffic_spike_flag", "unusual_port_flag", "failed_conn_count",
]

# The 12-value ML vector: order is fixed so Student 2's model and Student 3's SHAP use identical positions
ML_FEATURES = (
    "packet_rate_10s", "bytes_sent_rate", "connection_count",
    "new_destination_count", "activity_time", "mean_packet_size",
    "std_packet_size", "mean_inter_arrival", "std_inter_arrival",
    "traffic_spike_flag", "unusual_port_flag", "failed_conn_count",
)


@dataclass
class IoTDeviceFeatureVector:
    # Record metadata (not a feature)
    window_start: float                # epoch seconds, start of the 10 s window

    # Identifiers & protocols (not in ML vector)
    device_mac: str                    # devices table key
    ip_src: str
    ip_dst: str
    port_src: int
    port_dst: int
    protocol_type: TransportProtocol   # transport layer
    app_protocol: AppProtocol          # application layer

    # Volume, connections & activity (10 s window)
    packet_rate_10s: float             # packets/s
    bytes_sent_rate: float             # bytes/s
    connection_count: int
    new_destination_count: int
    activity_time: float               # active seconds, 0-10

    # Statistics (10 s window)
    mean_packet_size: float            # bytes
    std_packet_size: float             # bytes, standard deviation
    mean_inter_arrival: float          # ms
    std_inter_arrival: float           # ms, standard deviation

    # Derived flags & counters
    traffic_spike_flag: bool           # 0 during LEARNING
    unusual_port_flag: bool            # 0 during LEARNING
    failed_conn_count: int             # 60 s window

    ML_FEATURES = ML_FEATURES          # class constant (no annotation -> not a dataclass field)

    def to_ml_input_array(self) -> list[float]:
        """Return the 12-value numeric vector in a fixed order."""
        return [float(getattr(self, name)) for name in self.ML_FEATURES]
