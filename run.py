#!/usr/bin/env python3
"""
Vigilance AI — One-command startup
Run: python run.py
"""
import os, sys, subprocess

print("""
╔══════════════════════════════════════════════════════════╗
║       VIGILANCE AI — Identity Blast-Radius Engine        ║
║         Société Générale Hackathon — PS1 Track           ║
╚══════════════════════════════════════════════════════════╝
""")

# Generate data if missing
if not os.path.exists('dataset/identities.csv'):
    print("📊 Generating dataset...")
    subprocess.run([sys.executable, 'generate_data.py'], check=True)
else:
    print("✅ Dataset found")

print("\n🌐 Starting at http://localhost:5000\n")
os.execlp(sys.executable, sys.executable, 'app.py')
