# Access Enforcement Review (FR-07 / FR-08) - Week 9

**Owner:** Student 3 (Explainability & Access)  
**Status:** Draft for team review. Every decision below is a *proposal*; mark it Agreed or Changed in the PR.

## 1. Purpose and scope
Before writing `policy/` (FR-07) and `enforcement/` (FR-08), this review checks how the Trust Score from
`trust_score/engine.py` becomes a network decision, finds the gaps, and proposes concrete rules for the lab.
Scope: the isolated Docker lab (`trustadapt0`, `10.77.0.0/24`). No rule is applied outside the lab.

## 2. Current logic (from `trust_score/engine.py`)
| Parameter | Value | Meaning |
|---|---|---|
| `TRUST_LEVELS` | 80-100 / 50-79 / 20-49 / 0-19 | Trusted / Suspicious / Quarantined / Blocked |
| `P_MAX` | 30 | Max points lost in one 10 s window |
| `GAMMA` | 1.5 | Penalty = 30 x A^1.5 |
| `ANOMALY_THRESHOLD` | 0.3 | Window counts as anomalous when severity A > 0.3 |
| `RECOVERY_RATE` | 2 | Points regained per normal window |
| `LEARNING_INITIAL_SCORE` | 65 | Fixed score while the 50-window baseline is built |

Access text in the code today:

| Level | Code text |
|---|---|
| Trusted | Full access |
| Suspicious | Limited access to essential services only |
| Quarantined | Isolated in a separate network segment, re-verification required |
| Blocked | Fully blocked until administrator review |

Level lookup was checked at the boundaries (79.5 -> Suspicious, 49.5 -> Quarantined, 19.5 -> Blocked): correct.

## 3. Lab network (what can be allowed or blocked)
| Host | IP | Service | Used by devices |
|---|---|---|---|
| MQTT broker | 10.77.0.2 | TCP 1883 | All devices (telemetry) |
| Cloud server | 10.77.0.100 | TCP 80 (HTTP) | cam-01 (uploads) and therm-01 (a request about every 30 s); sensor-01 uses MQTT only |
| cam-01 / therm-01 / sensor-01 | 10.77.0.11 / .12 / .13 | - | The monitored IoT devices |
| Extra "internet" hosts | 10.77.0.151 - .158 | TCP 8080 | Only contacted during the exfiltration attack |

Real baseline (normal capture of 2026-11-19, 50 windows per device): `port_whitelist` is [80, 1883] for cam-01 and therm-01, and [1883] for sensor-01.

Device identity = MAC address (FR-01), e.g. cam-01 = `02:42:0a:4d:00:11`. Rules match on MAC, not IP, because an
attacker can change the IP more easily.

## 4. Proposed access policy per level
| Level | Allowed | Blocked | Why |
|---|---|---|---|
| **Trusted** | Everything in the lab | Nothing | Normal operation |
| **Suspicious** | Only the ports in the device's own baseline whitelist, to the lab servers: cam-01 and therm-01 = MQTT to broker (10.77.0.2:1883) and HTTP to cloud (10.77.0.100:80); sensor-01 = MQTT only. Plus ARP | All other IPv4 traffic (new hosts, other ports, other devices) | "Essential services" = what each device really uses in the normal capture (`port_whitelist` in the baseline JSON, 2026-11-19); it keeps working but cannot scan or exfiltrate |
| **Quarantined** | ARP only (and the verification path in F3) | All IPv4 traffic, including broker and cloud | Isolated; still visible to monitoring so it can recover |
| **Blocked** | Nothing | All traffic to and from the device | Stays blocked until an administrator releases it (F1) |

## 5. Findings and proposed decisions
### F1 - Blocked devices recover by themselves
The code text says "blocked until administrator review", but `update()` adds +2 points in every normal window, so a
device at 0 reaches Trusted after 40 normal windows (about 7 minutes) without any administrator.  
**Proposed decision:** Blocked is *latched*. The score keeps being computed and shown, but access stays Blocked
until an administrator releases the device (dashboard button or CLI). On release the device restarts at 50 (Suspicious).

### F2 - Level flapping at the boundaries
A score moving 79 -> 81 -> 79 changes the access level every 10 s, so firewall rules are rewritten every window.  
**Proposed decision (hysteresis):** go *down* immediately; go *up* only when the score is at least **5 points above**
the lower bound of the higher level (e.g. Suspicious -> Trusted at 85) **for 3 consecutive windows**.

### F3 - "Re-verification" is not defined
Quarantined requires re-verification, but no verification step exists in the lab.  
**Proposed decision:** re-verification = **30 consecutive normal windows** (5 minutes, no anomaly) while quarantined.
Then the device moves to Suspicious. An administrator can also release it manually.

### F4 - New devices start restricted
`LEARNING_INITIAL_SCORE = 65` puts every new device in Suspicious for its first ~8 minutes (50 windows).  
**Proposed decision:** keep it. Because Suspicious still allows broker + cloud (Section 4), a new device works
normally while it cannot reach anything else. This matches Zero Trust (no trust before evidence).

### F5 - Speed of the drop
One severe window (A = 1) removes 30 points: Trusted 100 -> 70 (Suspicious). About three severe windows reach Blocked.  
**Proposed decision:** keep `P_MAX = 30` for now (fast reaction to floods and scans) and re-check it with the
NFR-02 measurements in Week 13.

### F6 - Detection is not calibrated yet (blocking issue)
In the Week 9 integration check, the current detector marked about half of *normal* windows as anomalous
(A > 0.3), and normal devices fell to Blocked within 12 minutes. Enforcing now would cut off healthy devices.  
**Proposed decision:** enforcement starts in **dry-run mode** (`ENFORCE = False`): every decision is logged as
"would apply" but no rule is installed. Switch to enforcing only after Student 2 recalibrates FR-05 and the normal
scenario keeps all devices Trusted.

## 6. Enforcement design (FR-08)
* **Tool:** nftables, `bridge` family table on the lab bridge `trustadapt0`, so frames between containers are filtered.
* **Per-level MAC sets:** a device is placed in exactly one set (`suspicious` or `suspicious_mqtt` by its baseline ports, `quarantined`, `blocked`); Trusted
  devices are in no set. Changing a level = moving the MAC between sets, one atomic `nft` transaction, no rule rebuild.
* **Fail-safe:** if no feature data arrives for a device for 60 s, keep its last level (never upgrade on missing data).
  If the system stops, the installed sets stay as they are (blocked devices stay blocked).
* **Audit log (FR-14):** every level change is stored: time, MAC, old/new level, score, reason, and the feature
  contributions from the engine record. The dashboard reads this log.
* **Monitoring must continue:** a restricted device must still be captured so it can recover; Student 1 to confirm
  the capture point still sees traffic that the bridge drops.

Sketch (syntax-checked with `nft -c`; to be implemented and tested in Week 11):
```
table bridge trustadapt {
  set suspicious      { type ether_addr; }   # MQTT + HTTP devices (cam-01, therm-01)
  set suspicious_mqtt { type ether_addr; }   # MQTT-only devices (sensor-01)
  set quarantined     { type ether_addr; }
  set blocked         { type ether_addr; }
  chain forward {
    type filter hook forward priority 0; policy accept;
    ether saddr @blocked drop
    ether daddr @blocked drop
    ether saddr @quarantined ether type ip drop
    ether saddr @suspicious ip daddr 10.77.0.2   tcp dport 1883 accept
    ether saddr @suspicious ip daddr 10.77.0.100 tcp dport 80   accept
    ether saddr @suspicious ether type ip drop
    ether saddr @suspicious_mqtt ip daddr 10.77.0.2 tcp dport 1883 accept
    ether saddr @suspicious_mqtt ether type ip drop
  }
}
```
Example action: `nft add element bridge trustadapt suspicious { 02:42:0a:4d:00:11 }` (cam-01); sensor-01 goes to `suspicious_mqtt`.

## 7. Interfaces with the team
| With | What this review uses / provides | Agreed format |
|---|---|---|
| Student 1 - Data & Features | Device identity = MAC (FR-01); lab IPs and services from `lab/docker-compose.yml`; bridge `trustadapt0` | Same MACs as `devices.csv` |
| Student 2 - ML / Trust Score | Input = the record returned by `TrustScoreEngine.update()`: `new_score`, `trust_level`, `access_decision`, `contributions`, `reason` | No change to the engine needed; `policy/` applies hysteresis + latch on top of `trust_level` |
| Student 4 - Dashboard | Output for `access_levels()` in `dashboard/integrations.py` | One row per device and window: `device_mac`, `window_start`, `trust_level`, `access_decision`, `enforced` (0 = dry-run, 1 = rule applied) |
| Student 4 - Dashboard | Audit log of level changes (Section 6), and a "Release device" action for latched Blocked devices | Columns: `time`, `device_mac`, `old_level`, `new_level`, `score`, `reason`, `contributions` |
| Student 5 - Integration | Code goes to `src/trustadapt/policy/` and `src/trustadapt/enforcement/`, tests in `tests/`, via PR | Branch `feature/enforcement-<task>` |

## 8. Open questions for the team
1. Do we agree on the four decisions in Section 5 (latch, hysteresis, 30-window verification, dry-run)?
2. Should the dashboard (Student 4) get an "Release device" button for Blocked devices?
3. Student 1: does the capture still see a device's traffic after the bridge drops it?
4. Student 2: when is the recalibrated detector expected, so enforcement can leave dry-run?

## 9. Next steps
| Week | Work |
|---|---|
| 10 | SHAP groundwork in `explain/` (FR-09) |
| 11 | `policy/`: score -> level with hysteresis + latch; `enforcement/`: nftables sets, dry-run flag, audit log; agree `access_levels()` format with the dashboard |
| 13 | Test access decisions under the normal and attack scenarios |
