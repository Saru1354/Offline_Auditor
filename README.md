# 🔒 Offline Document Auditor Pro

**AI-Powered Contract Risk Analyzer — 100% Offline, 100% Private**

Upload a contract (PDF or image), get a risk score, a plain-English summary, flagged
clauses with fixes, and a set of tools to actually act on what's found — all without
the document ever leaving your machine.

---

## ✨ What's New

This update focused on making the tool something you actually negotiate with, not
just a one-shot scanner — plus a pass of reliability fixes and a visual refresh.

| Feature | What it does |
|---|---|
| 📚 **Clause Library benchmarks** | Every flagged clause now shows a "market standard" reference (e.g. typical refund windows, liability cap norms) instead of a generic "negotiate this" note. |
| 🖍️ **Annotated PDF export** | Highlights flagged clauses *directly on your original PDF* — color-coded by severity, with a margin note (why it matters + suggested fix) — instead of only a separate summary report. |
| ✉️ **Negotiation email drafts** | One click turns your flagged risks into a ready-to-send email asking the other party to revise specific clauses. Pick a tone (Professional / Firm / Friendly), edit inline, download as `.txt`. |
| 🔍 **Version diffing** | Re-upload an edited version of a contract you've already analyzed and see an actual line-by-line diff of what changed, plus the previous risk score for comparison. |
| 💬 **"Explain further" on demand** | Click into any flagged clause for a deeper, plain-English explanation (what it does, a realistic scenario where it hurts you, a concrete negotiation tip) — generated only when you ask, so scanning stays fast. |
| 🎬 **Smoother loading animations** | Fast Mode, Thorough Mode, and Deep AI Analysis now show an animated spinner card with shimmer/fade transitions and a settling "complete" state, instead of a flat static box. |
| 🐛 **Reliability fixes** | Fixed: annotation highlights obscuring text on the annotated PDF; the flagged-clause list silently capping at 10 even when more were found; and a bug where clicking anything inside Deep Analysis or Thorough Mode results (explain, email draft, downloads) would cause the whole results section to disappear. |

---

## Why This Exists

Every day, people sign contracts they don't understand — NDAs, rental agreements,
job offers, SaaS terms. Legal review costs real money, and most "AI legal tools"
upload your sensitive documents to the cloud. This tool is:

- **Free** — no subscriptions, no API keys
- **Private** — documents never leave your machine
- **Fast** — scans in seconds, deep AI analysis in minutes
- **Actionable** — doesn't just flag problems, helps you fix them

---

## Features

### Core Analysis
- **Fast Mode** — instant regex-based scan (20 risk patterns) across 8 categories: Payment, Termination, Liability, Rights, Data Rights, Legal Rights, Fairness, Control
- **Thorough Mode** — full section-by-section AI analysis using a local LLM, for nuanced language the rule engine can't catch
- **Risk Score** — 0–100 weighted score with color-coded severity breakdown
- **Plain English Summary** — non-lawyer explanation of what's actually risky
- **Clause Library benchmarks** — market-standard reference points attached to every flagged category

### Taking Action
- **Deep AI Analysis** (Fast Mode) — one-click LLM pass over the flagged clauses for detailed why/fix reasoning
- **"Explain further"** — on-demand, deeper plain-English breakdown of any single clause
- **Negotiation email drafts** — auto-generated, editable email raising your top concerns with the other party
- **Redlined text export** — suggested edits with strikethroughs
- **Annotated PDF export** — highlights and margin notes written directly onto your original PDF
- **Standard PDF report** — a clean, standalone summary report for sharing

### Multi-Document Tools
- **Compare Documents** — upload exactly 2 documents to see side-by-side risk scores and which is safer
- **Batch Processing** — upload 3+ documents to get a ranked list from safest to riskiest
- **Version diffing** — automatically detects when you've re-uploaded an edited version of something already analyzed, and shows exactly what changed

### Trust & Privacy
- **Document Fingerprint** — SHA-256 hash for tamper-proofing
- **History Tracking** — local SQLite database of past analyses, per logged-in user
- **No Cloud Uploads, No API Keys, No Telemetry** — everything runs on `localhost`

---

## Architecture

```
User Upload (PDF/Image)
        │
        ▼
Text Extraction (PyMuPDF / Tesseract OCR)
        │
        ▼
Rule Engine (20 patterns) ──────► Risk Score (0–100)
        │                                │
        ▼                    ┌───────────┼───────────┐
Fast Scan Result         Deep AI Analysis      Export (PDF / Redline /
                          (Local LLM)            Annotated PDF / Email)
                                │
                                ▼
                      Ollama + Phi-3 Mini
```

**Data flow:** Upload → Extract text → Rule-engine scan → Weighted risk score →
Optional deep AI pass (local LLM) → Export in whichever format you need.

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Frontend | Streamlit + custom CSS | Interactive UI |
| LLM Engine | Ollama + Phi-3 Mini (3.8B) | Local AI inference, no cloud |
| Text Extraction | PyMuPDF + Tesseract OCR | PDF parsing and image-to-text |
| PDF Annotation | PyMuPDF | Writing highlights/notes back onto the original PDF |
| AI Framework | LangChain + LangChain-Ollama | Prompt chaining and templating |
| Database | SQLite | Per-user analysis history |
| PDF Generation | fpdf2 | Standalone report export |
| Concurrency | ThreadPoolExecutor | Parallel chunk processing (Thorough Mode) |

---

## Installation

### Prerequisites
- Python 3.10+
- [Ollama](https://ollama.com) installed
- Tesseract OCR installed ([Windows installer](https://github.com/UB-Mannheim/tesseract/wiki))

### Step 1: Get the project files
Place `app.py` and `requirements.txt` in a project folder, e.g.
`offline-doc-auditor/`.

### Step 2: Open a terminal in that folder
```bash
cd path/to/offline-doc-auditor
```
(On Windows, remember it's `C:\Users\<you>\...`, not `C:\User\...`.)

### Step 3: Create a virtual environment
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

### Step 4: Install dependencies
```bash
pip install -r requirements.txt
```

### Step 5: Download the local LLM
```bash
ollama pull phi3:mini
```

### Step 6: Configure Tesseract (Windows only, if needed)
The app auto-detects Tesseract in the default Windows install location. If yours is
installed elsewhere, edit line 9 in `app.py`:
```python
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
```

### Step 7: Start Ollama
In a separate terminal:
```bash
ollama serve
```

### Step 8: Run the app
```bash
streamlit run app.py
```
The app opens at `http://localhost:8501`.

---

## Usage

### Create an account
The app requires a local login (username + password, stored hashed in SQLite) so
each person's history stays separate on a shared machine.

### Single Document Analysis
1. Upload a PDF or image contract
2. Choose **Fast Mode** (seconds) or **Thorough Mode** (a couple minutes)
3. View the risk score, category breakdown, and plain-English summary
4. Click **Deep AI Analysis** (Fast Mode) for detailed per-clause findings
5. Click **Explain further** on any clause for a deeper plain-English breakdown
6. Download: PDF Report, Redlined Text, Annotated PDF, or a Negotiation Email draft

### Compare Two Documents
Upload exactly 2 documents and click **Compare Documents** to see side-by-side
scores and which one is safer.

### Batch Processing
Upload 3+ documents to get a ranked list from safest to riskiest.

### Re-analyzing an Edited Version
If you upload a document that's a close match to something already in your
history, the app flags it and shows a **"See exactly what changed"** diff view —
useful for checking whether a counterparty actually fixed what you flagged in a
previous round.

### View / Clear History
Use the sidebar: **📊 View History** to browse past analyses, **🗑️ Clear History**
to wipe them.

---

## Performance

| Metric | Value |
|---|---|
| Fast Mode | 3–10 seconds |
| Deep AI Analysis | ~30–60 seconds |
| Thorough Mode | 2–5 minutes |
| RAM Usage | 4–6 GB (with Phi-3 Mini) |
| GPU | Not required |
| Internet | Not required after setup |

---

## Limitations

| Limitation | Notes |
|---|---|
| Phi-3 Mini is weaker than GPT-4-class models | Use Thorough Mode for complex contracts; treat flagged clauses as a starting point, not a verdict |
| OCR accuracy varies with image quality | Prefer native PDFs over scanned images when possible |
| Annotated PDF highlighting depends on exact text match | LLM-paraphrased quotes sometimes won't be found in the source PDF; the app reports how many of the flagged clauses it actually located and highlighted |
| Clause library benchmarks are general, not jurisdiction-specific | Treat them as a starting point for negotiation, not legal advice |
| No legal advice | This tool flags risks and gives a starting point for negotiation — consult a lawyer for anything that actually matters |
| English only | Multi-language support not yet implemented |

---

## Privacy & Security

| Feature | Implementation |
|---|---|
| No Cloud Uploads | All processing happens on `localhost` |
| Document Fingerprint | SHA-256 hash for integrity verification |
| No API Keys | Zero external service dependencies |
| Local Database | SQLite stored on your machine only |
| No Telemetry | No usage data collected |

**Note:** contract text is currently stored in plaintext in the local SQLite
database (`document_history.db`) to support history and version-diffing. This is
fine on a personal machine but worth knowing if the machine is shared or backed up
somewhere you don't control.

---

## License

Distributed under the MIT License. See `LICENSE` for details.

## Acknowledgments

- [Ollama](https://ollama.com) for making local LLMs accessible
- Microsoft for Phi-3 Mini
- Streamlit for rapid UI development
