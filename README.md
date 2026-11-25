# AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework (v2.0)

An end-to-end cybersecurity platform built to inspect IPsec VPN deployments across diverse configurations. Combines deterministic IKEv1/IKEv2/ESP/AH packet dissection, **NIST SP 800-77 Rev. 1 / RFC 8221 / CNSA 2.0** compliance auditing, an **Active IKE Gateway Scanner**, **7-Class Encrypted Flow ML**, context-aware remediation, and a modern **React + Vite + Tailwind + Recharts** SOC dashboard.

---

## Key Capabilities

1. **Deep Deterministic Dissection (`ike_dissector.py`):**
   - Dissects IKEv1 (Main/Aggressive Mode) and IKEv2 (`IKE_SA_INIT`, `IKE_AUTH`, `CREATE_CHILD_SA`) handshakes over IPv4 and IPv6, including NAT-T (UDP 4500) and AH (Protocol 51).
   - Audits every offered proposal for **cipher downgrade risks**, parses Notify payloads (`USE_TRANSPORT_MODE`), tracks Extended Sequence Numbers (`ESN`), and checks ESP sequence monotonicity for anti-replay anomalies.
2. **Multi-Model Encrypted ESP Traffic ML, SHAP & Anomaly Detection (`esp_feature_extractor.py`, `classifier.py`, `train_model.py`):**
   - Extracts **14 statistical flow features** plus **23 UNB ISCXFlowMeter microsecond features** without decrypting payloads.
   - **Primary Classifier (`LightGBM`):** Classifies flows into **VoIP**, **Video Streaming**, **Web Browsing**, **Messaging**, **WhatsApp**, **Email**, and **ICMP** (`100.0%` 5-fold CV on 485 windowed IPsec flows; `99.59%` Tunnel/Transport mode inference accuracy).
   - **Real-World UNB ISCX-VPN2016 Validation:** Benchmarked via 5-Fold Stratified CV across **9,793 real VPN flows** (`LightGBM: 90.18%`, `XGBoost: 89.75%`, `ExtraTrees: 84.88%`, `Neural MLP: 80.65%`) with secondary cross-check predictions per uploaded flow.
   - **True Per-Flow Explainable AI (`shap.TreeExplainer`):** Emits signed Shapley log-odds contributions for every flow prediction.
   - **Zero-Day Anomaly Detection (`IsolationForest`):** Computes unsupervised outlier scores alongside rule-based flags (`C2_BEACON_SUSPECTED`, `COVERT_LOW_ENTROPY`, `EXFILTRATION_BURST_SKEW`, `ML_OUTLIER_ANOMALY`).
3. **Active IKE Gateway Scanner (`ike_scanner.py`):**
   - Sends non-destructive UDP IKEv2 and IKEv1 cipher/DH probes to live VPN endpoints (plus local loopback targets `demo-hardened-gw` and `demo-vulnerable-gw`) to grade accepted suites (`A+` to `F`).
4. **Compliance, Dynamic Risk Scoring & Context-Aware Remediation (`compliance_engine.py`, `remediation_generator.py`):**
   - Scores deployments across 5 weighted dimensions (Crypto Strength, Key Exchange, Operational Hygiene, PQC Readiness, Traffic Exposure).
   - Generates tailored **StrongSwan (`swanctl.conf`)**, **Cisco IOS-XE CLI**, and **VyOS** patches referencing extracted peer IPs and failing rules.
5. **Modern React SOC Dashboard & Multi-Tier Reporting (`frontend/`, `report_generator.py`):**
   - Built offline with **React 18 + Vite + Tailwind CSS + Recharts + Lucide Icons**.
   - 5 analyst views: **Overview & Risk**, **IKE Inspector**, **AI Traffic Lab**, **Active IKE Scanner**, and **Compare & Remediation**.
   - Exports publication-ready **Executive PDF**, **Technical Markdown**, and **JSON** reports with SQLite session history (`datasets/sessions.db`).

---

## Repository Structure

```
IPSEC_VPN_ANALYSER/
├── backend/app/
│   ├── main.py                      # FastAPI API + serves compiled React SPA
│   ├── schemas/models.py            # Pydantic models for SA, Flows, Scans, Reports
│   └── services/
│       ├── ike_dissector.py         # IKEv1/v2, ESP, AH, IPv6, Replay & Notify parser
│       ├── compliance_engine.py     # NIST/RFC/CNSA/PQC compliance & threat matrix
│       ├── esp_feature_extractor.py # 14-feature flow extractor + covert anomalies
│       ├── classifier.py            # 7-class ExtraTrees + Mode RandomForest
│       ├── ike_scanner.py           # Active UDP IKE gateway prober + demo responders
│       ├── remediation_generator.py # Context-aware StrongSwan, Cisco, VyOS generator
│       ├── session_store.py         # SQLite session persistence
│       ├── report_generator.py      # Executive PDF + Technical Markdown reports
│       └── analyzer_service.py      # Master orchestrator
├── frontend/                        # React + Vite + Tailwind + Recharts SPA
│   ├── src/components/              # Overview, Inspector, TrafficLab, Scanner, Compare
│   └── dist/                        # Compiled offline production bundle
├── testbed/
│   ├── docker-compose.yml           # 2-node StrongSwan Alpine Linux VPN lab
│   ├── configs/peer-a & peer-b/     # StrongSwan swanctl.conf endpoint profiles
│   ├── run_live_docker_capture.py   # Boots Docker lab & captures live XFRM PCAPs
│   ├── traffic/pcap_builder.py      # Multi-profile IPv4/IPv6/AH/NAT-T generator
│   └── generate_datasets.py         # Generates 6 samples + 70-trace training corpus
├── ml_engine/train_model.py         # Clean ESP/AH training & evaluation script
├── tests/                           # Automated pytest suite
└── run.py                           # Single-command launcher (port 8000)
```

---

## Quick Start

```powershell
# 1. Regenerate dataset & retrain ML (optional; already built)
$env:PYTHONPATH="."
.\venv\Scripts\python.exe testbed/generate_datasets.py
.\venv\Scripts\python.exe ml_engine/train_model.py

# 2. Rebuild React frontend (optional; already compiled into frontend/dist)
Push-Location frontend; npm run build; Pop-Location

# 3. Run automated tests
$env:PYTHONPATH="."
.\venv\Scripts\python.exe -m pytest -v

# 4. Launch platform (serves React UI + FastAPI on port 8000)
.\venv\Scripts\python.exe run.py
```

Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser.

### Live StrongSwan Docker Captures (Optional)
Ensure Docker Desktop Linux Engine is running, then execute:
```powershell
.\venv\Scripts\python.exe testbed/run_live_docker_capture.py
```
This spins up `ipsec-peer-a` and `ipsec-peer-b`, brings up kernel XFRM tunnels via `swanctl`, drives live traffic, and saves real `.pcap` files into `datasets/real_captures/`, which automatically appear in the dashboard's **Lab Testbed Permutations** selector.
