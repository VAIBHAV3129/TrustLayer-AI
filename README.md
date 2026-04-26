# TrustLayer AI

**Real-Time Threat Intelligence System**

TrustLayer AI is an explainable AI-powered threat detection engine designed for real-time trust scoring of digital interactions. Built for hackathon demos and rapid evaluation workflows, it analyzes suspicious messages, links, and payment requests entirely offline using a deterministic scoring pipeline.

This system is designed with input validation, adversarial resistance, and controlled execution to ensure reliability in real-world environments.

TrustLayer AI is also structured for GitHub-first collaboration and public deployment, with CI, container support, production startup configuration, and a fully static GitHub Pages build included in the repository.

## Problem Statement

Digital scams often rely on urgency, fear, fake financial requests, and sensitive-data prompts. Most people can feel that something is wrong, but they cannot quickly explain why or quantify the risk. Teams need a fast, local, and transparent system that converts unstructured text into a trust signal they can act on.

## Solution Overview

TrustLayer AI delivers a cybersecurity-style web dashboard backed by TrustLayer Engine v2. The system inspects text for threat signals, assigns a trust score from 0 to 100, classifies likely threat categories, surfaces human-readable reasons, recommends next actions, and now supports batch triage for analyst-style workflows.

## How It Works

### TrustLayer Engine v2

The backend is a modular, deterministic pipeline:

1. **Feature Extraction**
   Detects structured indicators from raw text:
   - `urgency_terms`
   - `link_presence`
   - `financial_terms`
   - `threat_language`
   - `sensitive_requests`
   - `emotional_pressure`

2. **Weighted Scoring Engine**
   Applies fixed weights to the extracted features:
   - Urgency: `20`
   - Link presence: `15`
   - Financial terms: `25`
   - Threat language: `20`
   - Sensitive requests: `30`
   - Emotional pressure: `15`

   `risk_score = sum(weight * presence)`

   `trust_score = max(0, 100 - risk_score)`

3. **Classification Layer**
   Assigns a dominant category:
   - Financial terms + sensitive requests -> `Financial Fraud`
   - Link presence + urgency -> `Phishing`
   - Emotional pressure + threat language -> `Social Engineering`
   - No signals -> `Safe`
   - Otherwise -> `Unknown`

4. **Explainability Layer**
   Produces plain-language reasons such as:
   - "Urgency language detected"
   - "Suspicious link pattern found"
   - "Sensitive information requested"

5. **Confidence Score**
   Uses a deterministic confidence function with penalties for weak, short, or noisy inputs.

6. **Response Playbooks**
   Generates analyst-friendly recommended next actions based on risk and campaign category.

7. **Batch Triage**
   Supports multi-message scanning for rapid contest demos, analyst workflows, and exportable JSON reports.

## Features

- Fully local analysis with no API keys and no paid services
- Flask backend with a clean modular engine design
- Cybersecurity-inspired dashboard with dark glassmorphism styling
- Trust score, risk level, threat category, confidence, and explainability
- Recommended response actions for each detection
- Batch triage mode with exportable JSON report
- Local recent-analysis memory for smoother storytelling during demos
- Browser-native threat engine for static hosting on GitHub Pages
- Offline-capable threat logic with deterministic behavior
- Input sanitization, rate limiting, safe audit logging, and fallback handling
- Adversarial text normalization for obfuscated scam patterns like `cl1ck`, `b@nk`, and `0tp`
- GitHub Actions CI, Docker support, and cloud deployment manifests
- Demo-ready experience with sample threat loading and live UI updates

## Project Structure

```text
trustlayer-ai/
├── backend/
│   ├── app.py
│   ├── engine.py
│   ├── features.py
│   ├── scorer.py
│   ├── classifier.py
│   ├── explainer.py
│   ├── recommender.py
│   └── requirements.txt
├── docs/
│   ├── .nojekyll
│   ├── app.js
│   ├── index.html
│   └── styles.css
├── .github/
│   └── workflows/
│       └── ci.yml
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── styles.css
├── Dockerfile
├── Procfile
├── render.yaml
├── runtime.txt
├── .gitignore
├── LICENSE
└── README.md
```

## Run Locally

1. Create a virtual environment:

   ```bash
   cd trustlayer-ai
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies:

   ```bash
   pip install -r backend/requirements.txt
   ```

3. Start the application:

   ```bash
   python backend/app.py
   ```

4. Open the app:

   Visit [http://localhost:5000](http://localhost:5000)

## GitHub Pages Deployment

GitHub Pages cannot run Flask or any Python backend. To support Pages properly, this repo now includes a browser-native TrustLayer engine in `docs/`, so the app can be hosted as a static site directly from GitHub.

### Publish on GitHub Pages

1. Push this repository to GitHub.
2. Open the repository `Settings` -> `Pages`.
3. Under `Build and deployment`, choose `Deploy from a branch`.
4. Select your default branch and the `/docs` folder.
5. Save the configuration and wait for the Pages URL to appear.

The published app will run entirely in the browser with no API keys and no external AI services.


## Screenshots

<img width="1909" height="855" alt="Screen Shot 2026-04-26 at 16 55 21 PM" src="https://github.com/user-attachments/assets/01e7362f-bccf-4030-b56e-a482bacf27e1" />
<img width="1915" height="869" alt="Screen Shot 2026-04-26 at 16 55 13 PM" src="https://github.com/user-attachments/assets/ae72c081-e7b1-450c-b375-eaa66acbd86d" />
<img width="1919" height="857" alt="Screen Shot 2026-04-26 at 16 55 07 PM" src="https://github.com/user-attachments/assets/57590766-dc4c-456f-a7de-60ea06358277" />


- Dashboard overview
- High-risk phishing analysis
- Safe-content trust score result

## Tech Stack

- **Backend:** Python, Flask
- **Frontend:** Offline-friendly HTML, CSS, vanilla JavaScript
- **Engine:** Rule-based modular scoring, campaign classification, response playbooks, and a browser-native Pages runtime
- **DevOps:** GitHub Actions, Docker, Gunicorn, Render deployment manifest

## Future Scope

- Domain reputation heuristics for known shortening patterns
- Message source metadata and sender risk enrichment
- Batch ingestion and CSV triage workflows
- Analyst history, exportable reports, and team audit trails
- Lightweight local model augmentation for richer semantic patterning
