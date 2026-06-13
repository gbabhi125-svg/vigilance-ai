# Vigilance AI — Identity Blast-Radius Engine
### Société Générale Hackathon · PS1: Identity Sprawl & Privilege Abuse Detection

---

## 🚀 Quick Start (one command)

```bash
pip install -r requirements.txt
python run.py
# → open http://localhost:5000
```

---

## 📁 Project Structure

```
vigilance_ai/
├── run.py              # ← START HERE (auto-generates data + launches server)
├── app.py              # Flask backend — all APIs
├── generate_data.py    # Synthetic dataset generator (600 identities)
├── requirements.txt    # Dependencies
├── dataset/
│   └── identities.csv  # Auto-generated
└── templates/
    └── index.html      # Full UI (single file)
```

---

## ✅ Features Implemented

### Base (all required)
- Risk scoring engine with explainable AI (SHAP-style factor breakdown)
- Stale / orphaned / over-privileged / role-change classification
- Risk levels: CRITICAL / HIGH / MEDIUM / LOW
- Remediation playbook with auto vs manual actions (P1–P4 priority)

### Level 1 — Implementation Bonus (5 pts each)
- ✅ **Real-time alert dashboard** — Live feed tab, auto-refreshes every 15s
- ✅ **Privilege graph visualization** — D3.js force-directed graph, draggable nodes
- ✅ **Automated remediation playbook** — Step-by-step with blast radius animation
- ✅ **Multi-system correlation** — Cross-system risk linking in identity graph

### Level 2 — Advanced Intelligence (10 pts each)
- ✅ **Behavioral clustering** — K-means (4 clusters), bar chart visualization
- ✅ **Breach impact simulation** — Blast radius score, lateral movement, data exposure map
- ✅ **False positive feedback loop** — Correct / FP / Missed buttons, persisted feedback
- ✅ **API integration** — Architecture ready for Okta/Azure AD (REST API layer)

### Level 3 — Enterprise Features (15 pts each)
- ✅ **Organizational anomaly detection** — Dept-level risk heatmap + anomaly classification
- ✅ **Separation of duties violations** — 5 SOD rules across role combinations
- ✅ **Compliance gap analysis** — NIST AC-2, GDPR Art.32, ISO 27001 A.9
- ✅ **DLP integration** — Per-system data sensitivity thresholds, exfiltration risk alerts

---

## 🔌 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/summary` | KPIs: totals, risk counts, feedback count |
| GET | `/api/identities?limit=100&level=CRITICAL` | Risk-ranked identity list |
| GET | `/api/identity/<id>` | Full deep-dive: graph, SHAP, blast, SOD, compliance |
| GET | `/api/clusters` | K-means behavioral clusters |
| GET | `/api/org-anomalies` | Dept-level anomalies + stats table |
| GET | `/api/timeline` | Live threat event feed |
| POST | `/api/remediate/<id>` | Execute remediation, returns new score |
| POST | `/api/feedback/<id>/<type>` | Record correct/FP/missed feedback |

---

## 📊 Dataset

600 synthetic identities with realistic anomaly distribution:
- **~16% anomalous users** (stale admins, privilege creep, orphaned accounts)
- 5 enterprise systems: Active Directory, AWS IAM, Okta, Salesforce, GCP
- 7 roles: Engineering, Finance, HR, Marketing, Sales, IT-Admin, Contractor
- Risk factors: inactive admin, role change, MFA gap, unusual location, contractor expiry
