\# TrustAdapt



Adaptive \& Explainable Device Trust System for Zero-Trust Networks (graduation project).



Supervisor: Dr. Abdulaziz Aldribi



Team: Ebtehal Alamri, Elan Alrumihi, Fatimah Alruthea, Tasneem Alrofiei, Joud Alkharboush



\## What it does



The system learns the normal network behavior of each device, turns deviations from it into a Trust Score between 0 and 100, explains every change, and maps the score to an access level.



\## Project structure



All code is in `src/trustadapt/`, one folder per module:



\- `discovery`: device discovery (FR-01)

\- `monitoring`: traffic monitoring with NFStream (FR-02)

\- `features`: feature vector, 12 numeric values for the model (FR-03)

\- `baseline`: per-device baseline and model training (FR-04)

\- `anomaly`: anomaly detection with Isolation Forest (FR-05)

\- `trust\_score`: Trust Score formula (FR-06)

\- `policy`: mapping from trust level to access (FR-07)

\- `enforcement`: network rules with nftables (FR-08)

\- `explain`: explanation text and alerts (FR-09, FR-12)

\- `dashboard`: Streamlit dashboard (FR-10)

\- `store`: shared SQLite store used by all modules



Tests are in `tests/` and documents in `docs/`. The `data/` folder is for local datasets and pcap files and is never committed.



\## Setup



Python 3.12 or later is required.



&#x20;   python -m venv .venv

&#x20;   source .venv/bin/activate      (Linux / Git Bash: source .venv/Scripts/activate)

&#x20;   pip install -r requirements.txt



\## Working with Git



\- `main` always works. Nobody pushes to it directly.

\- One branch per task, named `feature/<module>-<task>`, for example `feature/anomaly-isolation-forest`.

\- When the task is done, open a Pull Request. Another team member reviews it, then it is merged and the branch is deleted.

\- Commit messages start with the module name, for example `anomaly: add per-device Isolation Forest`.

\- Datasets, pcap files and databases are never committed.


## Branching rules
- Never push directly to main.
- Branch name: feature/<module>-<task>, fix/<module>-<task>, docs/<topic>.
- Open a Pull Request and get one review before merging.
