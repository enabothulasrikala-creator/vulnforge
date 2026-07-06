# VulnForge — Free Deployment Guide

## Option 1: Render (Free — 750 hrs/month)
1. Push this repo to GitHub
2. Go to https://dashboard.render.com/select-repo
3. Select this repo, Render will auto-detect `render.yaml`
4. Free tier: app sleeps after 15 min inactivity, wakes on request
5. Add environment variable: `SECRET_KEY` (auto-generated)

## Option 2: Railway (Free — $5 credit, no credit card needed)
1. Push to GitHub
2. Go to https://railway.app
3. Deploy from GitHub repo
4. Set start command: `gunicorn run:app`
5. Free tier: 500 hours/month + 500MB RAM

## Option 3: Fly.io (Free — 3 shared VMs)
1. Install flyctl: `curl -L https://fly.io/install.sh | sh`
2. `fly launch` in repo root
3. `fly deploy`
4. Free tier: 3 shared-cpu-1x VMs

## Option 4: GitHub Codespaces (Free — 60 hrs/month)
1. Push to GitHub
2. Open in Codespaces
3. `python3 run.py` — runs 24/7 while you're in the codespace

## Option 5: Oracle Cloud Free Tier (Best for 24/7)
1. Sign up for Oracle Cloud Free Tier
2. Create an "Always Free" VM (ARM, 4 vCPUs, 24GB RAM)
3. Install python3, git, clone repo
4. `python3 run.py &` — runs 24/7 forever

## 24/7 Scanning Setup (Critical)
The scheduler (`scheduler.py`) runs in a background thread and rescans every 7 days.

For true 24/7 you need either:
- Oracle Cloud free VM (always on)
- GitHub Actions (runs scans as scheduled jobs — see `.github/workflows/scan.yml`)
- Local machine (keep terminal open)

## GitHub Actions — Automated Daily Scans
`.github/workflows/scan.yml` is included — it runs a scan via SSH on your server daily.
