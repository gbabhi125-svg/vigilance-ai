#!/usr/bin/env python3
"""
Vigilance AI — Risk Scoring Engine
Processes the OFFICIAL Societe Generale dataset:
  - identity_users.csv  (300 users)
  - identity_events.csv (900 events)

Produces dataset/identities.csv with the schema app.py expects.
"""

import pandas as pd
import numpy as np
import json
import os

BASE = os.path.dirname(os.path.abspath(__file__))
users  = pd.read_csv(os.path.join(BASE, 'identity_users.csv'))
events = pd.read_csv(os.path.join(BASE, 'identity_events.csv'))

events['timestamp'] = pd.to_datetime(events['timestamp'])

ev_agg = events.groupby('user_id').agg(
    n_events=('action', 'count'),
    n_admin_ops=('action', lambda s: (s == 'admin_operation').sum()),
    n_exports=('action', lambda s: (s == 'export_data').sum()),
    n_failed=('status', lambda s: (s == 'failure').sum()),
    n_unusual_hours=('time_classification', lambda s: s.isin(['unusual_hours', 'night', 'weekend']).sum()),
    n_high_sensitivity=('resource_sensitivity', lambda s: (s == 'high').sum()),
    resources=('resource', lambda s: list(set(s))),
    actions=('action', lambda s: list(set(s))),
).reset_index()

records = []

for _, u in users.iterrows():
    uid = u['user_id']
    systems_list = str(u['systems_access']).replace('_', ' ').split('|')
    systems_str = ", ".join(s.strip().replace(' ', '_') for s in systems_list)
    n_systems = len(systems_list)

    priv = u['privilege_level']
    has_admin = int(priv == 'admin')
    is_power_user = int(priv == 'power-user')
    is_service_account = int(priv == 'service-account')
    days_inactive = int(u['days_inactive'])

    ev = ev_agg[ev_agg['user_id'] == uid]
    if not ev.empty:
        ev = ev.iloc[0]
        n_events = int(ev['n_events'])
        n_admin_ops = int(ev['n_admin_ops'])
        n_exports = int(ev['n_exports'])
        n_failed = int(ev['n_failed'])
        n_unusual = int(ev['n_unusual_hours'])
        n_high_sens = int(ev['n_high_sensitivity'])
        resources = ev['resources']
    else:
        n_events = n_admin_ops = n_exports = n_failed = n_unusual = n_high_sens = 0
        resources = []

    risk = 0
    reasons = []
    mfa_gap = 0
    unusual_location = 0
    role_changed = 0
    is_contractor_expired = 0

    if has_admin and days_inactive > 30:
        w = 40
        risk += w
        reasons.append({"factor": f"Admin privilege on {systems_str.split(',')[0].strip()}, inactive {days_inactive} days", "weight": w})
    elif is_power_user and days_inactive > 40:
        w = 25
        risk += w
        reasons.append({"factor": f"Power-user privilege inactive for {days_inactive} days", "weight": w})

    if n_admin_ops >= 2:
        w = 30
        risk += w
        reasons.append({"factor": f"{n_admin_ops} admin operations recorded - elevated activity beyond normal role", "weight": w})
    elif n_admin_ops == 1 and priv == 'user':
        w = 22
        risk += w
        reasons.append({"factor": "Standard user performed an admin_operation - possible role exception", "weight": w})

    if n_unusual >= 2:
        w = 15
        risk += w
        unusual_location = 1
        reasons.append({"factor": f"{n_unusual} actions logged during unusual/night/weekend hours", "weight": w})
    elif n_unusual == 1:
        w = 7
        risk += w
        unusual_location = 1
        reasons.append({"factor": "Activity detected during unusual/off-hours window", "weight": w})

    if n_exports >= 1 and n_high_sens >= 1:
        w = 18
        risk += w
        reasons.append({"factor": f"{n_exports} data export(s) involving high-sensitivity resources ({', '.join(resources[:2])})", "weight": w})

    if n_failed >= 1:
        w = 15
        risk += w
        mfa_gap = 1
        reasons.append({"factor": f"{n_failed} failed access attempt(s) - possible authentication/MFA issue", "weight": w})

    if is_service_account and days_inactive > 20:
        w = 20
        risk += w
        reasons.append({"factor": f"Service account inactive for {days_inactive} days, no clear ownership signal", "weight": w})

    if days_inactive > 45 and n_systems >= 3 and not has_admin:
        w = 18
        risk += w
        reasons.append({"factor": f"Inactive {days_inactive} days across {n_systems} connected systems", "weight": w})

    if n_systems >= 4:
        w = 10
        risk += w
        reasons.append({"factor": f"Access spans {n_systems} systems - broad blast radius", "weight": w})

    risk = min(100, max(0, risk))

    if not reasons:
        reasons.append({"factor": "Access pattern matches expected baseline for role", "weight": 0})

    if risk >= 70:
        if is_service_account:
            classification = "Orphaned Service ID"
        elif n_admin_ops >= 1 and priv == 'user':
            classification = "Privilege Creep"
        elif has_admin and days_inactive > 30:
            classification = "Stale Account"
        else:
            classification = "Role Exception"
    elif risk >= 40:
        if days_inactive > 45:
            classification = "Stale Account"
        elif n_admin_ops >= 1:
            classification = "Role Exception"
        else:
            classification = "Privilege Creep"
    else:
        classification = "Normal"

    role = u['department']

    records.append({
        "id": uid,
        "name": u['username'],
        "role": role,
        "systems": systems_str,
        "n_systems": n_systems,
        "days_inactive": days_inactive,
        "has_admin": has_admin,
        "role_changed": role_changed,
        "mfa_gap": mfa_gap,
        "unusual_location": unusual_location,
        "is_contractor_expired": is_contractor_expired,
        "is_service_account": is_service_account,
        "risk_score": risk,
        "classification": classification,
        "reasons": json.dumps(reasons),
        "job_title": u['job_title'],
        "privilege_level": priv,
        "email": u['email'],
    })

df = pd.DataFrame(records)
df.to_csv(os.path.join(BASE, 'identities.csv'), index=False)

critical = (df['risk_score'] >= 70).sum()
high = ((df['risk_score'] >= 40) & (df['risk_score'] < 70)).sum()
stale = df['classification'].isin(['Stale Account', 'Orphaned Service ID']).sum()

print(f"Dataset built from OFFICIAL hackathon data: {len(df)} identities")
print(f"   CRITICAL (70+):  {critical}")
print(f"   HIGH (40-69):    {high}")
print(f"   Stale/Orphaned:  {stale}")
print(f"   Sample IDs: {df['id'].head(3).tolist()}")