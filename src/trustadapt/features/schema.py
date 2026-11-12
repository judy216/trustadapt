"""FR-03 feature schema: one IoTDeviceFeatureVector per device per 10 s window."""

from dataclasses import dataclass
from enum import Enum
from typing import ClassVar


class TransportProtocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"


class AppProtocol(str, Enum):
    MQTT = "MQTT"
    HTTP = "HTTP"
    COAP = "CoAP"
    OTHER = "OTHER"


@dataclass
class IoTDeviceFeatureVector:
    # Record metadata (not a feature)
    window_start: float            # epoch seconds, start of the 10 s window

    # Identifiers and protocols (not in ML vector)
    device_mac: str                # devices table key
    ip_src: str
    ip_dst: str
    port_src: int
    port_dst: int
    protocol_type: TransportProtocol
    app_protocol: AppProtocol

    # Volume, connections and activity (10 s window)
    packet_rate_10s: float         # packets/s
    bytes_sent_rate: float         # bytes/s
    connection_count: int
    new_destination_count: int
    activity_time: float           # active seconds, 0-10

    # Statistics (10 s window)
    mean_packet_size: float        # bytes
    std_packet_size: float         # bytes, standard deviation
    mean_inter_arrival: float      # ms
    std_inter_arrival: float       # ms, standard deviation

    # Derived flags and counters
    traffic_spike_flag: bool       # 0 during LEARNING
    unusual_port_flag: bool        # 0 during LEARNING
    failed_conn_count: int         # 60 s window

    # No annotation on purpose: ClassVar keeps it out of the dataclass fields.
    ML_FEATURES: ClassVar[tuple] = (
        "packet_rate_10s", "bytes_sent_rate", "connection_count",
        "new_destination_count", "activity_time", "mean_packet_size",
        "std_packet_size", "mean_inter_arrival", "std_inter_arrival",
        "traffic_spike_flag", "unusual_port_flag", "failed_conn_count",
    )

    def to_ml_input_array(self) -> list:
        """Return the 12-value numeric vector in the fixed ML_FEATURES order."""
        return [float(getattr(self, name)) for name in self.ML_FEATURES]
