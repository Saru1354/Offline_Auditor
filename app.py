import streamlit as st
import fitz
import pytesseract
from PIL import Image
import re
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import sqlite3
from io import BytesIO
from fpdf import FPDF
from fpdf.enums import XPos, YPos
import time
import platform
import shutil
import os
import secrets
import difflib

# Only override the Tesseract path on Windows, and only if the default
# install location actually exists. On macOS/Linux, pytesseract will use
# whatever `tesseract` is found on PATH (installed via brew/apt/etc).
if platform.system() == "Windows":
    _default_win_path = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
    if os.path.exists(_default_win_path):
        pytesseract.pytesseract.tesseract_cmd = _default_win_path
    elif shutil.which("tesseract"):
        pytesseract.pytesseract.tesseract_cmd = shutil.which("tesseract")
    # else: leave default; pytesseract will raise a clear "not found" error
    # instead of silently pointing at a nonexistent path.

from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate

# ==================== OLLAMA CHECK ====================
@st.cache_data(ttl=30, show_spinner=False)
def ensure_ollama_running():
    try:
        import urllib.request
        req = urllib.request.Request('http://localhost:11434/api/tags', method='GET')
        urllib.request.urlopen(req, timeout=2)
        return True
    except:
        return False

if not ensure_ollama_running():
    st.error("""
    ❌ Ollama is not running!

    Open a NEW terminal and run: ollama serve
    Then refresh this page.
    """)
    st.stop()

@st.cache_resource(show_spinner=False)
def get_llm():
    return OllamaLLM(model="phi3:mini", base_url="http://localhost:11434")

llm = get_llm()

# ==================== DATABASE ====================
DB_PATH = "document_history.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_salt TEXT NOT NULL,
                  password_hash TEXT NOT NULL,
                  created_at TIMESTAMP)''')

    c.execute("PRAGMA table_info(analyses)")
    existing_cols = [row[1] for row in c.fetchall()]

    if not existing_cols:
        # Fresh database — create with the new multi-user schema directly.
        c.execute('''CREATE TABLE analyses
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER,
                      filename TEXT,
                      doc_hash TEXT,
                      doc_text TEXT,
                      risk_score INTEGER,
                      risk_count INTEGER,
                      analysis_date TIMESTAMP,
                      risks_json TEXT,
                      UNIQUE(user_id, doc_hash))''')
    elif 'user_id' not in existing_cols:
        # Old (pre-login) schema exists. Migrate: recreate with the new
        # schema and carry old rows forward as "unowned" (user_id NULL)
        # rather than losing history.
        c.execute('''CREATE TABLE analyses_new
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER,
                      filename TEXT,
                      doc_hash TEXT,
                      doc_text TEXT,
                      risk_score INTEGER,
                      risk_count INTEGER,
                      analysis_date TIMESTAMP,
                      risks_json TEXT,
                      UNIQUE(user_id, doc_hash))''')
        c.execute('''INSERT INTO analyses_new
                     (filename, doc_hash, risk_score, risk_count, analysis_date, risks_json)
                     SELECT filename, doc_hash, risk_score, risk_count, analysis_date, risks_json
                     FROM analyses''')
        c.execute('DROP TABLE analyses')
        c.execute('ALTER TABLE analyses_new RENAME TO analyses')
    elif 'doc_text' not in existing_cols:
        # user_id already present but doc_text missing (partial migration state)
        c.execute('ALTER TABLE analyses ADD COLUMN doc_text TEXT')

    conn.commit()
    conn.close()

init_db()

# ==================== AUTH HELPERS ====================
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    return salt, pw_hash

def create_user(username, password):
    username = username.strip()
    salt, pw_hash = hash_password(password)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password_salt, password_hash, created_at) VALUES (?, ?, ?, ?)',
                   (username, salt, pw_hash, datetime.now()))
        conn.commit()
        return True, "Account created successfully."
    except sqlite3.IntegrityError:
        return False, "That username is already taken."
    finally:
        conn.close()

def verify_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, password_salt, password_hash FROM users WHERE username = ?', (username.strip(),))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    user_id, salt, stored_hash = row
    _, computed_hash = hash_password(password, salt)
    if secrets.compare_digest(computed_hash, stored_hash):
        return user_id
    return None

RISK_PATTERNS = [
    (r'\b(non[- ]?refundable|no[- ]?refund)\b', 'Payment', 'HIGH'),
    (r'\b(unlimited|any|at any time)\b.*\b(right|access|terminate)\b', 'Termination', 'HIGH'),
    (r'\b(indemnif|hold harmless)\b', 'Liability', 'HIGH'),
    (r'\b(waive|waiver)\b.*\b(right|claim|liability)\b', 'Rights', 'MEDIUM'),
    (r'\b(no[- ]?notice|without notice)\b', 'Termination', 'HIGH'),
    (r'\b(perpetual|irrevocable|forever)\b', 'Data Rights', 'HIGH'),
    (r'\b(sole discretion|solely determined)\b', 'Fairness', 'MEDIUM'),
    (r'\b(auto[- ]?renew|automatically renew)\b', 'Payment', 'MEDIUM'),
    (r'\b(late fee|penalty|interest)\b.*\d+%', 'Payment', 'HIGH'),
    (r'\b(class action|jury trial)\b.*\b(waive|waived|prohibited)\b', 'Legal Rights', 'HIGH'),
    (r'\b(binding arbitration|arbitrate)\b', 'Legal Rights', 'MEDIUM'),
    (r'\b(assign|transfer)\b.*\b(without consent|freely)\b', 'Control', 'MEDIUM'),
    (r'\b(confidential|proprietary)\b.*\b(indefinitely|perpetual)\b', 'Data Rights', 'HIGH'),
    (r'\b(liquidated damages|penalty clause)\b', 'Payment', 'HIGH'),
    (r'\b(force majeure)\b.*\b(including but not limited to)\b', 'Liability', 'LOW'),
    (r'\b(gross negligence|willful misconduct)\b.*\b(exclude|limit|cap)\b', 'Liability', 'HIGH'),
    (r'\b(consequential|incidental|special|punitive)\b.*\b(damages)\b', 'Liability', 'MEDIUM'),
    (r'\b(entire agreement|supersedes)\b.*\b(prior|oral|representation)\b', 'Fairness', 'LOW'),
    (r'\b(modify|amend)\b.*\b(unilaterally|solely|without consent)\b', 'Fairness', 'HIGH'),
    (r'\b(third[- ]?party|vendor|integration)\b.*\b(beneficiary|liability)\b', 'Liability', 'MEDIUM'),
]

# ==================== CLAUSE LIBRARY ====================
# A small curated reference of "market standard" terms per risk category.
# This isn't legal advice and isn't jurisdiction-specific — it's meant to
# give the user a concrete benchmark ("here's roughly what's normal") to
# push back with, instead of a generic "negotiate this" placeholder.
CLAUSE_LIBRARY = {
    'Payment': {
        'fix': 'Negotiate fair payment terms with mutual approval.',
        'benchmark': 'Market standard: refund windows of 14-30 days; auto-renewal notice of '
                      '30-60 days before the renewal date; late fees typically capped around '
                      '1-1.5%/month.',
    },
    'Termination': {
        'fix': 'Require equal notice period for both parties.',
        'benchmark': 'Market standard: symmetric termination rights with roughly 30 days '
                      'notice for both sides; "termination for convenience" is usually mutual, '
                      'not one-sided.',
    },
    'Liability': {
        'fix': 'Limit liability to reasonable, mutual caps.',
        'benchmark': 'Market standard: liability caps set at fees paid in the prior 12 months, '
                      'applied to both parties equally, with carve-outs only for gross '
                      'negligence, willful misconduct, or confidentiality breaches.',
    },
    'Data Rights': {
        'fix': 'Restrict data usage to specific, time-limited purposes.',
        'benchmark': 'Market standard: data/IP licenses run for the contract term plus a short '
                      'wind-down (30-90 days), not "perpetual" or "irrevocable"; confidentiality '
                      'obligations typically last 2-5 years post-termination, not indefinitely.',
    },
    'Legal Rights': {
        'fix': 'Preserve right to legal action and jury trial.',
        'benchmark': 'Mandatory arbitration and class-action waivers face real legal scrutiny '
                      'in many jurisdictions and are restricted outright in some consumer/'
                      'employment contexts — flag for review rather than accepting by default.',
    },
    'Fairness': {
        'fix': 'Require mutual consent for any modifications.',
        'benchmark': 'Market standard: unilateral "sole discretion" modification rights should '
                      'be replaced with advance written notice (commonly 30 days) and, for '
                      'material changes, an opt-out or termination right.',
    },
    'Control': {
        'fix': 'Ensure both parties must agree to assignments.',
        'benchmark': 'Market standard: assignment of the agreement to a third party typically '
                      'requires written consent, not unilateral transfer, except to an affiliate '
                      'or successor in an acquisition.',
    },
    'General': {
        'fix': 'Review and negotiate this clause before signing.',
        'benchmark': 'No specific market-standard benchmark on file for this clause type — flag '
                      'for manual legal review.',
    },
}

def get_clause_benchmark(category):
    return CLAUSE_LIBRARY.get(category, CLAUSE_LIBRARY['General'])['benchmark']

# ==================== CLEAN PROFESSIONAL CSS ====================
st.markdown("""
<style>
    /* Clean light professional theme */
    .stApp {
        background-color: #fafafa;
    }

    /* Clean header */
    .app-header {
        background: #ffffff;
        border-bottom: 1px solid #e5e7eb;
        padding: 1.5rem 2rem;
        margin: -1rem -1rem 2rem -1rem;
    }

    /* Cards - clean and minimal */
    .card {
        background: #ffffff;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        padding: 1.5rem;
        margin: 1rem 0;
    }

    .card:hover {
        border-color: #d1d5db;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }

    /* Metric boxes */
    .metric-box {
        background: #ffffff;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        padding: 1.5rem;
        text-align: center;
    }

    .metric-value {
        font-size: 2.5rem;
        font-weight: 700;
        color: #111827;
    }

    .metric-label {
        font-size: 0.875rem;
        color: #6b7280;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    /* Severity badges - clean */
    .badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    .badge-high {
        background: #fef2f2;
        color: #dc2626;
        border: 1px solid #fecaca;
    }

    .badge-medium {
        background: #fffbeb;
        color: #d97706;
        border: 1px solid #fde68a;
    }

    .badge-low {
        background: #f0fdf4;
        color: #16a34a;
        border: 1px solid #bbf7d0;
    }

    /* Risk item */
    .risk-item {
        background: #ffffff;
        border: 1px solid #e5e7eb;
        border-left: 4px solid #e5e7eb;
        border-radius: 6px;
        padding: 1rem 1.25rem;
        margin: 0.75rem 0;
    }

    .risk-item.high { border-left-color: #dc2626; }
    .risk-item.medium { border-left-color: #d97706; }
    .risk-item.low { border-left-color: #16a34a; }

    /* Buttons - clean */
    .stButton > button {
        background: #111827;
        color: white;
        border: none;
        border-radius: 6px;
        padding: 0.625rem 1.25rem;
        font-weight: 500;
        font-size: 0.875rem;
    }

    .stButton > button:hover {
        background: #374151;
    }

    /* Secondary button */
    .stButton > button[kind="secondary"] {
        background: #ffffff;
        color: #374151;
        border: 1px solid #d1d5db;
    }

    /* Sidebar */
    .css-1d391kg {
        background: #ffffff;
        border-right: 1px solid #e5e7eb;
    }

    /* File uploader */
    .stFileUploader {
        background: #ffffff;
        border: 2px dashed #d1d5db;
        border-radius: 8px;
        padding: 2rem;
    }

    .stFileUploader:hover {
        border-color: #9ca3af;
    }

    /* Summary box */
    .summary-box {
        background: #f9fafb;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        padding: 1.25rem;
    }

    /* Section headers */
    h1, h2, h3 {
        color: #111827;
        font-weight: 600;
    }

    h2 {
        font-size: 1.25rem;
        margin-bottom: 1rem;
    }

    h3 {
        font-size: 1rem;
        color: #374151;
    }

    /* Text */
    p, li {
        color: #4b5563;
        line-height: 1.6;
    }

    /* Code blocks */
    code {
        background: #f3f4f6;
        padding: 0.125rem 0.375rem;
        border-radius: 4px;
        font-size: 0.875rem;
        color: #111827;
    }

    /* Expander */
    .streamlit-expanderHeader {
        background: #ffffff;
        border: 1px solid #e5e7eb;
        border-radius: 6px;
    }

    /* Progress bar */
    .stProgress > div > div {
        background: linear-gradient(90deg, #111827 0%, #4b5563 50%, #111827 100%);
        background-size: 200% 100%;
        animation: shimmer-sweep 1.4s linear infinite;
        transition: width 0.45s cubic-bezier(0.4, 0, 0.2, 1);
        border-radius: 999px;
    }
    .stProgress > div {
        border-radius: 999px;
        overflow: hidden;
    }

    /* ===== Smooth animated loading card (replaces flat static boxes) ===== */
    @keyframes spin-smooth {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
    }
    @keyframes shimmer-sweep {
        0% { background-position: -200px 0; }
        100% { background-position: 200px 0; }
    }
    @keyframes card-fade-in {
        from { opacity: 0; transform: translateY(-3px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes dot-bounce {
        0%, 80%, 100% { transform: translateY(0); opacity: 0.35; }
        40% { transform: translateY(-3px); opacity: 1; }
    }

    .loader-card {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        background: linear-gradient(90deg, #f3f4f6 25%, #eceef1 37%, #f3f4f6 63%);
        background-size: 400px 100%;
        animation: shimmer-sweep 1.8s ease-in-out infinite, card-fade-in 0.3s ease-out;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        padding: 0.85rem 1.1rem;
        margin: 0.5rem 0;
        transition: all 0.3s ease;
    }
    .loader-card.done {
        background: #f0fdf4;
        border-color: #bbf7d0;
        animation: card-fade-in 0.3s ease-out;
    }
    .loader-ring {
        width: 18px;
        height: 18px;
        border-radius: 50%;
        flex-shrink: 0;
        background: conic-gradient(from 0deg, #111827, #d1d5db 65%, transparent 66%);
        -webkit-mask: radial-gradient(farthest-side, transparent calc(100% - 3px), #000 calc(100% - 3px));
        mask: radial-gradient(farthest-side, transparent calc(100% - 3px), #000 calc(100% - 3px));
        animation: spin-smooth 0.85s linear infinite;
    }
    .loader-check {
        width: 18px;
        height: 18px;
        flex-shrink: 0;
        font-size: 1rem;
        line-height: 1;
    }
    .loader-text {
        font-size: 0.875rem;
        font-weight: 500;
        color: #374151;
    }
    .loader-sub {
        font-size: 0.75rem;
        color: #6b7280;
        margin-top: 0.15rem;
    }
    .loader-dots span {
        display: inline-block;
        animation: dot-bounce 1.1s infinite ease-in-out;
    }
    .loader-dots span:nth-child(2) { animation-delay: 0.15s; }
    .loader-dots span:nth-child(3) { animation-delay: 0.3s; }

    /* Divider */
    hr {
        border-color: #e5e7eb;
        margin: 2rem 0;
    }

    /* Progress info box (legacy — kept for elements not yet migrated) */
    .progress-info {
        background: #f3f4f6;
        border-radius: 6px;
        padding: 0.75rem 1rem;
        margin: 0.5rem 0;
        font-size: 0.875rem;
        color: #374151;
        animation: card-fade-in 0.3s ease-out;
    }

    /* Duplicate file notice */
    .duplicate-notice {
        background: #eff6ff;
        border: 1px solid #bfdbfe;
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# ==================== AUTH GATE ====================
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
    st.session_state.username = None

if not st.session_state.user_id:
    st.markdown("""
    <div class="app-header">
        <h1 style="margin:0;font-size:1.75rem;font-weight:700;color:#111827;">
            🔒 Offline Document Auditor Pro
        </h1>
        <p style="margin:0.5rem 0 0 0;font-size:0.875rem;color:#6b7280;">
            Sign in to continue — analyses and history are kept private to your account
        </p>
    </div>
    """, unsafe_allow_html=True)

    tab_login, tab_register = st.tabs(["🔑 Login", "🆕 Create Account"])

    with tab_login:
        with st.form("login_form"):
            login_username = st.text_input("Username")
            login_password = st.text_input("Password", type="password")
            login_submitted = st.form_submit_button("Login", use_container_width=True)
            if login_submitted:
                if not login_username or not login_password:
                    st.error("Enter both username and password.")
                else:
                    uid = verify_user(login_username, login_password)
                    if uid:
                        st.session_state.user_id = uid
                        st.session_state.username = login_username.strip()
                        st.rerun()
                    else:
                        st.error("Invalid username or password.")

    with tab_register:
        with st.form("register_form"):
            reg_username = st.text_input("Choose a username")
            reg_password = st.text_input("Choose a password", type="password")
            reg_password_confirm = st.text_input("Confirm password", type="password")
            reg_submitted = st.form_submit_button("Create Account", use_container_width=True)
            if reg_submitted:
                if not reg_username or not reg_password:
                    st.error("Fill in all fields.")
                elif len(reg_password) < 6:
                    st.error("Password must be at least 6 characters.")
                elif reg_password != reg_password_confirm:
                    st.error("Passwords don't match.")
                else:
                    ok, msg = create_user(reg_username, reg_password)
                    if ok:
                        st.success(msg + " You can log in now from the Login tab.")
                    else:
                        st.error(msg)

    st.stop()

def truncate_response(text, max_lines=10):
    lines = [l for l in text.split('\n') if l.strip()]
    if len(lines) > max_lines:
        return '\n'.join(lines[:max_lines]) + "\n\n...[output truncated]"
    return text

def get_doc_hash(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

def save_analysis(user_id, filename, doc_hash, doc_text, risk_score, risk_count, risks_list):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT OR REPLACE INTO analyses 
                 (user_id, filename, doc_hash, doc_text, risk_score, risk_count, analysis_date, risks_json)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
              (user_id, filename, doc_hash, doc_text, risk_score, risk_count, datetime.now(), json.dumps(risks_list)))
    conn.commit()
    conn.close()

def get_history(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM analyses WHERE user_id = ? ORDER BY analysis_date DESC', (user_id,))
    rows = c.fetchall()
    conn.close()
    return rows

def clear_history(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM analyses WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()

def find_similar_previous_doc(user_id, doc_text, current_hash, threshold=0.85):
    """Look through this user's history for a document that's substantially
    the same text but with a different hash — i.e. an edited version of
    something already analyzed. Exact-hash duplicates are handled separately
    by the cache-hit path, so this only fires on near-matches."""
    if not doc_text:
        return None
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT filename, doc_hash, doc_text, risk_score, analysis_date
                 FROM analyses
                 WHERE user_id = ? AND doc_hash != ? AND doc_text IS NOT NULL''',
              (user_id, current_hash))
    rows = c.fetchall()
    conn.close()

    best_match = None
    best_ratio = 0.0
    # autojunk=False: difflib's default autojunk heuristic treats characters
    # that recur very frequently as "junk" and ignores them when the text is
    # long — contracts are full of repeated boilerplate phrasing, which can
    # tank the similarity score to near-zero even for a barely-edited
    # document. Disabling it gives an honest ratio at some CPU cost, which
    # is fine at this document scale.
    matcher = difflib.SequenceMatcher(None, autojunk=False)
    matcher.set_seq2(doc_text)
    for filename, old_hash, old_text, old_score, old_date in rows:
        if not old_text:
            continue
        matcher.set_seq1(old_text)
        if matcher.quick_ratio() < threshold:
            continue
        ratio = matcher.ratio()
        if ratio >= threshold and ratio > best_ratio:
            best_ratio = ratio
            best_match = {
                'filename': filename,
                'old_hash': old_hash,
                'risk_score': old_score,
                'date': old_date,
                'similarity': ratio,
                'old_text': old_text,
            }
    return best_match

def calculate_risk_score(risks_list):
    if not risks_list:
        return 0
    severity_weights = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    total_weight = sum(severity_weights.get(r.get('severity', 'LOW'), 1) for r in risks_list)
    max_possible = len(risks_list) * 3
    return min(100, int((total_weight / max(max_possible, 1)) * 100))

def get_plain_summary(risks_list, doc_text):
    if not risks_list:
        return "This document appears to be relatively fair with no major red flags detected."
    risk_summary = "\n".join([f"- {r.get('category', 'Risk')}: {r.get('text', r.get('quote', 'Unknown clause'))[:100]}..." for r in risks_list[:5]])
    prompt = PromptTemplate.from_template("""
    Summarize these contract risks in 2-3 simple sentences that a non-lawyer can understand.
    Be direct and actionable. Mention the worst risk first.
    Risks:
    {risks}
    Summary:
    """)
    chain = prompt | llm
    try:
        return chain.invoke({"risks": risk_summary})
    except:
        first_cat = risks_list[0].get('category', 'Unknown') if risks_list else 'Unknown'
        second_cat = risks_list[1].get('category', 'other clauses') if len(risks_list) > 1 else 'other clauses'
        return f"Document contains {len(risks_list)} potential risks. Key concerns: {first_cat} and {second_cat}."

def sanitize_pdf_text(text):
    """Prepare text for the core (Latin-1 only) FPDF fonts.

    The previous approach did `.encode('ascii', 'ignore')`, which silently
    deletes anything non-ASCII — smart quotes, em/en dashes, currency
    symbols (Rs, EUR, GBP), accented names, ellipses, etc. all just vanished
    with no trace, which can quietly change the meaning of a quoted
    clause (e.g. a currency-amount penalty clause losing its number).

    This first maps common unicode punctuation/currency to readable ASCII
    equivalents, then only drops whatever's left that truly can't be
    represented (e.g. non-Latin scripts), so the report stays close to
    the source instead of silently losing content.
    """
    if not text:
        return ""
    replacements = {
        '\u2018': "'", '\u2019': "'",   # smart single quotes
        '\u201c': '"', '\u201d': '"',   # smart double quotes
        '\u2013': '-', '\u2014': '--',  # en dash, em dash
        '\u2026': '...',                # ellipsis
        '\u20b9': 'Rs.', '\u20ac': 'EUR', '\u00a3': 'GBP', '\u00a5': 'JPY',
        '\u00a0': ' ',                  # non-breaking space
        '\u2022': '-',                  # bullet
    }
    for uni_char, ascii_equiv in replacements.items():
        text = text.replace(uni_char, ascii_equiv)
    return text.encode('ascii', 'ignore').decode('ascii')

def generate_pdf_report(filename, doc_text, risks_list, risk_score, plain_summary, doc_hash=None):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 18)
    pdf.cell(0, 12, 'DOCUMENT RISK ANALYSIS REPORT', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.set_font('Arial', '', 10)
    pdf.cell(0, 6, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.cell(0, 6, f'Document: {filename}', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.ln(4)

    pdf.set_fill_color(248, 248, 248)
    pdf.rect(10, pdf.get_y(), 190, 30, 'F')
    pdf.set_xy(15, pdf.get_y() + 4)
    pdf.set_font('Arial', 'B', 13)
    # Explicitly reset x back to the left margin (not just "next line") after
    # this cell — leaving x wherever this short line happened to end is what
    # caused "Not enough horizontal space" crashes on the multi_cell() calls
    # further down.
    pdf.cell(0, 8, f'Overall Risk Score: {risk_score}/100', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_x(pdf.l_margin)

    if risk_score >= 70:
        pdf.set_text_color(220, 38, 38)
        level = "HIGH RISK - Significant concerns identified"
    elif risk_score >= 40:
        pdf.set_text_color(217, 119, 6)
        level = "MEDIUM RISK - Review recommended"
    else:
        pdf.set_text_color(22, 163, 74)
        level = "LOW RISK - Generally acceptable terms"

    pdf.set_font('Arial', 'B', 11)
    pdf.cell(0, 8, level, border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_x(pdf.l_margin)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(6)

    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 8, 'EXECUTIVE SUMMARY', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_x(pdf.l_margin)
    pdf.set_font('Arial', '', 9)
    clean_summary = sanitize_pdf_text(plain_summary)
    pdf.multi_cell(0, 5, clean_summary, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_x(pdf.l_margin)
    pdf.ln(4)

    if risks_list:
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 8, 'IDENTIFIED RISKS', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_x(pdf.l_margin)
        pdf.ln(2)

        for i, risk in enumerate(risks_list[:15], 1):
            sev = risk.get('severity', 'LOW')
            if sev == 'HIGH':
                pdf.set_text_color(220, 38, 38)
            elif sev == 'MEDIUM':
                pdf.set_text_color(217, 119, 6)
            else:
                pdf.set_text_color(22, 163, 74)

            pdf.set_font('Arial', 'B', 10)
            cat = sanitize_pdf_text(risk.get('category', 'Risk'))
            pdf.cell(0, 7, f'{i}. {cat} [{sev}]', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_x(pdf.l_margin)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font('Arial', '', 9)

            if risk.get('quote'):
                quote = sanitize_pdf_text(risk['quote'])
                pdf.set_font('Arial', 'I', 8)
                pdf.multi_cell(0, 4, f'Quote: "{quote}"', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_x(pdf.l_margin)
                pdf.set_font('Arial', '', 9)

            if risk.get('why'):
                why = sanitize_pdf_text(risk['why'])
                pdf.multi_cell(0, 4, f'Impact: {why}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_x(pdf.l_margin)

            if risk.get('fix'):
                fix = sanitize_pdf_text(risk['fix'])
                pdf.set_text_color(22, 163, 74)
                pdf.multi_cell(0, 4, f'Suggested Fix: {fix}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_x(pdf.l_margin)
                pdf.set_text_color(0, 0, 0)

            if risk.get('benchmark'):
                benchmark = sanitize_pdf_text(risk['benchmark'])
                pdf.set_font('Arial', 'I', 8)
                pdf.set_text_color(80, 80, 80)
                pdf.multi_cell(0, 4, f'Benchmark: {benchmark}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_x(pdf.l_margin)
                pdf.set_font('Arial', '', 9)
                pdf.set_text_color(0, 0, 0)

            pdf.ln(2)

    pdf.ln(6)
    pdf.set_font('Arial', 'B', 10)
    pdf.cell(0, 8, 'DOCUMENT FINGERPRINT (SHA-256)', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_x(pdf.l_margin)
    pdf.set_font('Courier', '', 7)
    if not doc_hash:
        # Fallback only if no hash was supplied (shouldn't normally happen)
        doc_hash = hashlib.sha256(doc_text.encode()).hexdigest()
    pdf.multi_cell(0, 4, doc_hash, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_x(pdf.l_margin)
    pdf.set_font('Arial', '', 8)
    pdf.cell(0, 5, 'This fingerprint proves the document has not been tampered with since analysis.', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_y(-25)
    pdf.set_font('Arial', 'I', 7)
    pdf.set_text_color(128, 128, 128)
    pdf.cell(0, 8, 'Generated by Offline Document Auditor Pro - 100% Local AI Analysis', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')

    # fpdf2's pdf.output() returns a bytearray directly in current versions
    # (the old "dest='S'" + .encode('latin-1') pattern is for older/legacy
    # fpdf and throws AttributeError on a bytearray). Handle both so this
    # keeps working regardless of the exact fpdf2 version installed.
    pdf_output = pdf.output()
    if isinstance(pdf_output, (bytes, bytearray)):
        return bytes(pdf_output)
    return pdf_output.encode('latin-1')

# ==================== ANNOTATED PDF (WRITE-BACK ONTO ORIGINAL) ====================
def generate_annotated_pdf(original_pdf_bytes, risks_list):
    """Highlight flagged clauses directly on the original PDF, with a
    margin note carrying the category/severity/why/fix, instead of a
    separate summary report. This is what you'd actually send to a lawyer
    or counterparty since it shows the risk in its real context.

    LLM-produced quotes are sometimes paraphrased and won't match the
    source text verbatim, so PyMuPDF's search_for() can legitimately miss
    some. Rather than fail silently, this returns how many of the total
    flagged risks were actually located and highlighted so the caller can
    surface that to the user.
    """
    doc = fitz.open(stream=original_pdf_bytes, filetype="pdf")
    color_map = {
        'HIGH': (0.86, 0.20, 0.20),
        'MEDIUM': (0.85, 0.55, 0.10),
        'LOW': (0.09, 0.55, 0.29),
    }
    located = 0
    total = 0
    for risk in risks_list:
        quote = (risk.get('quote') or risk.get('text') or '').strip()
        if not quote:
            continue
        total += 1
        # Rule-engine hits carry the whole matched sentence, which can be
        # long; search on a shorter leading fragment (same rough length as
        # an LLM-produced quote) since search_for() needs a contiguous,
        # verbatim substring and shorter strings are more likely to survive
        # PDF text-extraction quirks (hyphenation, wrapped lines, etc).
        search_text = quote if len(quote) <= 90 else quote[:80]
        color = color_map.get(risk.get('severity', 'LOW'), (0.5, 0.5, 0.5))
        note_lines = [f"[{risk.get('severity', 'LOW')}] {risk.get('category', 'Risk')}"]
        if risk.get('why'):
            note_lines.append(f"Why: {risk['why']}")
        if risk.get('fix'):
            note_lines.append(f"Suggested fix: {risk['fix']}")
        if risk.get('benchmark'):
            note_lines.append(f"Benchmark: {risk['benchmark']}")
        note = "\n".join(note_lines)

        found_this_risk = False
        for page in doc:
            try:
                rects = page.search_for(search_text)
            except Exception:
                rects = []
            if not rects:
                continue
            found_this_risk = True
            for rect in rects:
                try:
                    annot = page.add_highlight_annot(rect)
                    annot.set_colors(stroke=color)
                    # Highlights default to fully opaque in some viewers, which
                    # blocks the underlying text instead of tinting it. Force
                    # a translucent opacity so the flagged text stays readable.
                    annot.set_opacity(0.35)
                    annot.set_info(title="Document Auditor", content=note)
                    annot.update()
                except Exception:
                    continue
        if found_this_risk:
            located += 1

    out_bytes = doc.tobytes(garbage=3, deflate=True)
    doc.close()
    return out_bytes, located, total

# ==================== ON-DEMAND CLAUSE EXPLANATION ====================
def explain_clause_deep(quote, why, category):
    """Only called when the user explicitly clicks 'Explain further' — this
    keeps Fast Mode fast (no LLM call up front for every flagged clause)
    while still offering Thorough-Mode-style depth exactly where wanted."""
    prompt = PromptTemplate.from_template("""
You are explaining a contract clause to someone with no legal background.

Category: {category}
Clause: "{quote}"
Initial note: {why}

In 3-4 short plain-English sentences, cover: (1) what this clause actually
does in practice, (2) a realistic scenario where it could hurt the person
signing, and (3) one concrete, specific negotiation tip. Write it as a
single short paragraph — no headers, no bullet points, no markdown.
""")
    chain = prompt | llm
    try:
        result = chain.invoke({
            "category": category or "General",
            "quote": quote or "(clause text unavailable)",
            "why": why or "Not specified.",
        })
        return truncate_response(result, max_lines=8)
    except Exception as e:
        return f"Could not generate a detailed explanation: {str(e)}"

def render_explain_button(quote, why, category, key):
    """Shared 'Explain further' button + cached-result display, used across
    the Fast Mode scan list, Deep AI Analysis, and Thorough Mode results."""
    cache_key = f"explain_cache_{key}"
    if st.button("🔍 Explain further", key=f"explain_btn_{key}"):
        with st.spinner("Getting a deeper explanation..."):
            st.session_state[cache_key] = explain_clause_deep(quote, why, category)
    if cache_key in st.session_state:
        st.info(st.session_state[cache_key])

# ==================== NEGOTIATION EMAIL GENERATOR ====================
def generate_negotiation_email(filename, risks_list, tone="Professional"):
    """Turn flagged risks + suggested fixes into a ready-to-send message,
    closing the loop from 'here's what's wrong' to 'here's what to do
    about it' using the exact risks already in memory."""
    if not risks_list:
        return "Subject: Contract review\n\nNo significant risks were flagged, so there's nothing specific to raise before signing."

    def sev_rank(r):
        return {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(r.get('severity', 'LOW'), 1)

    top = sorted(risks_list, key=sev_rank, reverse=True)[:5]
    bullets = "\n".join(
        f"- ({r.get('severity', 'LOW')}) {r.get('category', 'Risk')}: "
        f"{(r.get('why') or r.get('text') or r.get('quote') or '').strip()[:200]}"
        for r in top
    )

    tone_instruction = {
        "Professional": "polite, professional, and collaborative",
        "Firm": "firm and direct, making clear these terms are not acceptable as-is",
        "Friendly": "warm, friendly, and non-confrontational, framed as a quick clarifying ask",
    }.get(tone, "polite and professional")

    prompt = PromptTemplate.from_template("""
Write a {tone_instruction} email to the other party of a contract titled "{filename}".
The email should raise the concerns below and ask that those clauses be revised
before signing. Do not invent any facts, numbers, or terms beyond what's listed
below. Keep it under 180 words total.

Format: first line is "Subject: ..." then a blank line, then the email body.
End the email with a brief offer to hop on a call to discuss.

Concerns to raise:
{bullets}
""")
    chain = prompt | llm
    try:
        result = chain.invoke({
            "tone_instruction": tone_instruction,
            "filename": filename,
            "bullets": bullets,
        })
        return truncate_response(result, max_lines=40)
    except Exception as e:
        return f"Could not generate the email draft: {str(e)}"

def render_negotiation_email_ui(filename, risks_list, key_prefix):
    """Shared 'draft a negotiation email' block: tone picker, generate
    button, editable draft, and a .txt download — used across the cached,
    Fast Mode, and Thorough Mode results sections."""
    st.markdown("<h4 style='margin:1.5rem 0 0.5rem 0;'>✉️ Draft a Negotiation Email</h4>", unsafe_allow_html=True)
    cache_key = f"negotiation_email_{key_prefix}"
    tone = st.selectbox(
        "Tone", ["Professional", "Firm", "Friendly"],
        key=f"tone_{key_prefix}",
    )
    if st.button("✉️ Draft negotiation email", key=f"draft_email_{key_prefix}", use_container_width=True):
        with st.spinner("Drafting email..."):
            st.session_state[cache_key] = generate_negotiation_email(filename, risks_list, tone=tone)
    if cache_key in st.session_state:
        edited = st.text_area("Draft (edit before sending):", value=st.session_state[cache_key], height=220, key=f"email_text_{key_prefix}")
        st.download_button(
            "📥 Download Email Draft (.txt)", edited,
            f"negotiation_email_{filename.replace('.pdf', '')}.txt",
            "text/plain", use_container_width=True, key=f"email_dl_{key_prefix}",
        )

def extract_text(file):
    file_bytes = file.getvalue()
    if file.type == "application/pdf":
        if not file_bytes.startswith(b'%PDF'):
            st.error("❌ Invalid PDF file. Please upload a real PDF, not a renamed text file.")
            return None
        doc = fitz.open(stream=file_bytes, filetype="pdf")
        text = ""
        for page in doc:
            page_text = page.get_text()
            if page_text.strip():
                text += page_text + "\n\n"
            else:
                pix = page.get_pixmap()
                img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                text += pytesseract.image_to_string(img) + "\n\n"
        return text.strip()
    elif file.type.startswith('image/'):
        img = Image.open(BytesIO(file_bytes))
        return pytesseract.image_to_string(img).strip()
    else:
        st.error("❌ Unsupported file type. Please upload PDF or image files only.")
        return None

def find_risky_clauses(text):
    sentences = re.split(r'(?<=[.!?])\s+', text)
    risky = []
    seen = set()
    for sentence in sentences:
        sentence = sentence.strip()
        if len(sentence) < 20 or sentence in seen:
            continue
        seen.add(sentence)
        for pattern, category, severity in RISK_PATTERNS:
            if re.search(pattern, sentence, re.IGNORECASE):
                risky.append({
                    'text': sentence,
                    'category': category,
                    'severity': severity,
                    'benchmark': get_clause_benchmark(category),
                })
                break
    return risky

def parse_risk_block(block):
    risk_data = {'quote': '', 'why': '', 'severity': 'LOW', 'category': 'General', 'fix': '', 'benchmark': ''}
    block = block.strip()
    if not block or len(block) < 10:
        return risk_data

    lines = [l.strip() for l in block.split('\n') if l.strip()]
    block_upper = block.upper()
    if 'HIGH' in block_upper:
        risk_data['severity'] = 'HIGH'
    elif 'MEDIUM' in block_upper:
        risk_data['severity'] = 'MEDIUM'
    elif 'LOW' in block_upper:
        risk_data['severity'] = 'LOW'

    quote_match = re.search(r'"([^"]{5,200})"', block)
    if quote_match:
        risk_data['quote'] = quote_match.group(1)[:100]
    else:
        for line in lines:
            clean = re.sub(r'\*\*?\*?', '', line).strip()
            if len(clean) > 15 and not any(k in clean.upper() for k in ['RISK:', 'WHY:', 'SEVERITY:', 'CATEGORY:', 'FIX:', 'HIGH', 'MEDIUM', 'LOW']):
                risk_data['quote'] = clean[:100]
                break

    why_found = False
    for line in lines:
        clean = re.sub(r'\*\*?\*?', '', line).strip()
        if any(k in clean.upper() for k in ['RISK:', 'QUOTE:', 'SEVERITY:', 'CATEGORY:', 'FIX:', 'HIGH', 'MEDIUM', 'LOW']):
            continue
        if len(clean) > 20 and clean != risk_data['quote']:
            risk_data['why'] = clean[:200]
            why_found = True
            break

    if not why_found:
        risk_data['why'] = 'This clause contains potentially unfair terms. Review carefully before signing.'

    cat_match = re.search(r'CATEGORY[:\s]+([A-Za-z\s/]+)', block, re.IGNORECASE)
    if cat_match:
        risk_data['category'] = cat_match.group(1).strip()[:50]
    else:
        text_lower = block.lower()
        if any(w in text_lower for w in ['payment', 'fee', 'refund', 'rent', 'money', 'charge']):
            risk_data['category'] = 'Payment'
        elif any(w in text_lower for w in ['terminate', 'notice', 'renew', 'suspension']):
            risk_data['category'] = 'Termination'
        elif any(w in text_lower for w in ['data', 'confidential', 'privacy', 'license']):
            risk_data['category'] = 'Data Rights'
        elif any(w in text_lower for w in ['liability', 'indemnif', 'damages', 'harm']):
            risk_data['category'] = 'Liability'
        elif any(w in text_lower for w in ['waive', 'right', 'jury', 'class action']):
            risk_data['category'] = 'Legal Rights'
        else:
            risk_data['category'] = 'General'

    # Try multiple patterns to extract FIX (handles markdown ** and various formats)
    fix_patterns = [
        r'\*\*FIX:\*\*\s*([^\n]{5,200})',
        r'\*\*FIX\*\*[:\s]+([^\n]{5,200})',
        r'FIX[:\s]+([^\n]{5,200})',
        r'SUGGESTED[:\s]+([^\n]{5,200})',
        r'ALTERNATIVE[:\s]+([^\n]{5,200})',
        r'FIXED[:\s]+([^\n]{5,200})',
        r'RECOMMENDATION[:\s]+([^\n]{5,200})',
    ]
    for pattern in fix_patterns:
        fix_match = re.search(pattern, block, re.IGNORECASE)
        if fix_match:
            risk_data['fix'] = fix_match.group(1).strip().strip('*').strip()[:100]
            break

    # Fallback: look for lines that start with fix-like keywords
    if not risk_data['fix']:
        for line in lines:
            clean = re.sub(r'\*\*?\*?', '', line).strip()
            lower = clean.lower()
            if any(lower.startswith(k) for k in ['fix:', 'suggested:', 'alternative:', 'replace with', 'change to', 'should be', 'must be', 'instead,', 'recommend:']):
                risk_data['fix'] = clean[:100]
                break

    # Last fallback: use a generic fix based on category if still empty
    if not risk_data['fix']:
        risk_data['fix'] = CLAUSE_LIBRARY.get(risk_data['category'], CLAUSE_LIBRARY['General'])['fix']

    # Always attach a market-standard benchmark note for this category,
    # regardless of whether the LLM supplied its own FIX text — this gives
    # the user something concrete to cite back at the other party instead
    # of a vague "review this clause."
    risk_data['benchmark'] = get_clause_benchmark(risk_data['category'])

    return risk_data

def apply_redline(doc_text, parsed_risks):
    """Apply strikethrough+suggestion redlines to doc_text for each risk's quote.

    LLM-produced quotes often don't match the source text byte-for-byte
    (paraphrasing, smart quotes, extra whitespace), so a plain str.replace()
    silently does nothing for those. This tries progressively looser
    matching, and if a quote truly can't be located, the suggestion is
    still surfaced in an "Unmatched Suggestions" section instead of being
    silently dropped.
    """
    redlined = doc_text
    unmatched = []

    for risk in parsed_risks:
        quote = (risk.get('quote') or '').strip()
        fix = (risk.get('fix') or '').strip()
        if not quote or not fix:
            continue

        replacement = f"~~{quote}~~ **[SUGGEST: {fix}]**"

        if quote in redlined:
            redlined = redlined.replace(quote, replacement)
            continue

        # Fuzzy fallback: match ignoring case and collapsing whitespace
        pattern = re.escape(quote)
        pattern = re.sub(r'\\ ', r'\\s+', pattern)
        match = re.search(pattern, redlined, re.IGNORECASE)
        if match:
            redlined = redlined[:match.start()] + f"~~{match.group(0)}~~ **[SUGGEST: {fix}]**" + redlined[match.end():]
        else:
            unmatched.append((risk.get('category', 'Risk'), quote, fix))

    if unmatched:
        redlined += "\n\n" + "=" * 60
        redlined += "\nUNMATCHED SUGGESTIONS\n"
        redlined += "(these quotes could not be located verbatim in the document,\n"
        redlined += "likely due to LLM paraphrasing — review manually)\n"
        redlined += "=" * 60 + "\n"
        for category, quote, fix in unmatched:
            redlined += f"\n[{category}] Quote: \"{quote}\"\n  Suggested fix: {fix}\n"

    return redlined

# ==================== PROGRESS TRACKING HELPERS ====================
def render_loader(message, submessage=None):
    """Animated 'in progress' card: spinning ring, shimmering background,
    bouncing ellipsis. Used in place of the flat static st.spinner()/
    progress-info boxes for Fast, Thorough, and Deep Analysis modes."""
    sub_html = f'<div class="loader-sub">{submessage}</div>' if submessage else ''
    return f'''
    <div class="loader-card">
        <div class="loader-ring"></div>
        <div>
            <div class="loader-text">{message}<span class="loader-dots"><span>.</span><span>.</span><span>.</span></span></div>
            {sub_html}
        </div>
    </div>
    '''

def render_loader_done(message, submessage=None):
    """Completed state for render_loader — swaps the spinner for a
    checkmark and settles into a calm green card instead of just
    vanishing, so the transition reads as finished rather than abrupt."""
    sub_html = f'<div class="loader-sub">{submessage}</div>' if submessage else ''
    return f'''
    <div class="loader-card done">
        <div class="loader-check">✅</div>
        <div>
            <div class="loader-text">{message}</div>
            {sub_html}
        </div>
    </div>
    '''

def update_progress_ui(progress_bar, status_text, completed, total, start_time, label="Processing"):
    """Update progress bar and status text with percentage and ETA."""
    pct = int((completed / total) * 100)
    elapsed = time.time() - start_time
    if completed > 0:
        avg_time = elapsed / completed
        remaining = avg_time * (total - completed)
        eta_str = f"~{int(remaining)}s remaining"
    else:
        eta_str = "calculating..."

    progress_bar.progress(pct / 100, text=f"{label}... {pct}% ({completed}/{total}) | {eta_str}")
    status_text.markdown(
        render_loader(
            f"{label} — {pct}% complete",
            f"⏱️ Elapsed: {int(elapsed)}s &nbsp;|&nbsp; ⏳ {eta_str} &nbsp;|&nbsp; {completed} of {total} chunks",
        ),
        unsafe_allow_html=True,
    )

# ==================== UI ====================
st.markdown("""
<div class="app-header">
    <h1 style="margin:0;font-size:1.75rem;font-weight:700;color:#111827;">
        🔒 Offline Document Auditor Pro
    </h1>
    <p style="margin:0.5rem 0 0 0;font-size:0.875rem;color:#6b7280;">
        100% Local AI — Professional Document Analysis
    </p>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown(f"""
    <div style="padding:0 0 1rem 0;border-bottom:1px solid #e5e7eb;margin-bottom:1rem;">
        <h3 style="margin:0;font-size:1rem;color:#111827;">👤 {st.session_state.username}</h3>
    </div>
    """, unsafe_allow_html=True)
    if st.button("🚪 Logout", use_container_width=True):
        st.session_state.user_id = None
        st.session_state.username = None
        st.session_state.show_history = False
        st.rerun()

    st.markdown("""
    <div style="padding:1rem 0 1rem 0;border-bottom:1px solid #e5e7eb;margin-bottom:1rem;">
        <h3 style="margin:0;font-size:1rem;color:#111827;">Features</h3>
    </div>
    """, unsafe_allow_html=True)

    features = ["Risk Scoring", "Plain English Summary", "PDF Export", "Document Fingerprinting", 
                "Historical Tracking", "Batch Processing", "Comparison Mode"]
    for feat in features:
        st.write(f"✓ {feat}")

    st.divider()

    if st.button("📊 View History", use_container_width=True):
        st.session_state.show_history = True
    if st.button("🗑️ Clear History", type="secondary", use_container_width=True):
        clear_history(st.session_state.user_id)
        st.success("History cleared!")
        st.session_state.show_history = False
        st.rerun()

st.markdown("""
<div class="card" style="text-align:center;padding:2rem;">
    <h3 style="margin:0 0 0.5rem 0;color:#374151;">Upload Documents</h3>
    <p style="margin:0;color:#6b7280;font-size:0.875rem;">PDF or image files. Your documents never leave this machine.</p>
</div>
""", unsafe_allow_html=True)

uploaded_files = st.file_uploader("", type=["pdf", "png", "jpg", "jpeg"], accept_multiple_files=True, label_visibility="collapsed")

if uploaded_files:
    for uploaded_file in uploaded_files:
        st.markdown(f'''
        <div class="card">
            <h3 style="margin:0 0 1rem 0;">📄 {uploaded_file.name}</h3>
        </div>
        ''', unsafe_allow_html=True)

        file_bytes = uploaded_file.getvalue()
        doc_hash = get_doc_hash(file_bytes)

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT * FROM analyses WHERE doc_hash = ? AND user_id = ?', (doc_hash, st.session_state.user_id))
        existing = c.fetchone()
        conn.close()

        if existing:
            force_reanalyze = st.checkbox(
                f"🔄 Re-analyze instead of using cached result",
                key=f"reanalyze_{doc_hash}_{uploaded_file.name}",
                help="Cached result was from a previous run (possibly a different mode, or before rule/pattern updates). Check this to run a fresh analysis."
            )
        else:
            force_reanalyze = False

        if existing and not force_reanalyze:
            st.info(f"⚠️ This document was analyzed on {existing[7]}. Showing cached results.")
            risks_list = json.loads(existing[8])
            risk_score = existing[5]

            cols = st.columns(3)
            with cols[0]:
                st.markdown(f'''
                <div class="metric-box">
                    <div class="metric-value" style="color:{'#dc2626' if risk_score >= 70 else '#d97706' if risk_score >= 40 else '#16a34a'};">{risk_score}</div>
                    <div class="metric-label">Risk Score</div>
                </div>
                ''', unsafe_allow_html=True)
            with cols[1]:
                st.markdown(f'''
                <div class="metric-box">
                    <div class="metric-value">{len(risks_list)}</div>
                    <div class="metric-label">Total Risks</div>
                </div>
                ''', unsafe_allow_html=True)
            with cols[2]:
                st.markdown(f'''
                <div class="metric-box">
                    <div class="metric-value" style="font-size:1.5rem;">CACHED</div>
                    <div class="metric-label">Status</div>
                </div>
                ''', unsafe_allow_html=True)

            for i, risk in enumerate(risks_list):
                with st.expander(f"⚠️ {risk.get('category', 'Risk')}"):
                    st.write(f"**Severity:** {risk.get('severity', 'LOW')}")
                    st.write(f"**Quote:** {risk.get('quote', '')}")
                    st.write(f"**Why:** {risk.get('why', '')}")
                    if risk.get('fix'):
                        st.write(f"**💡 Suggested Fix:** {risk['fix']}")
                    if risk.get('benchmark'):
                        st.caption(f"📚 {risk['benchmark']}")
                    render_explain_button(risk.get('quote', ''), risk.get('why', ''), risk.get('category', 'Risk'), key=f"cached_{doc_hash}_{i}")

            # Allow re-downloading the cached report
            col1, col2, col3 = st.columns(3)
            with col1:
                try:
                    # Try session state first, then re-extract
                    session_key = f"doc_text_{doc_hash}"
                    if session_key in st.session_state:
                        doc_text_cached = st.session_state[session_key]
                    else:
                        uploaded_file.seek(0)
                        doc_text_cached = extract_text(uploaded_file) or ""
                    plain_summary_cached = get_plain_summary(risks_list, doc_text_cached)
                    pdf_bytes = generate_pdf_report(uploaded_file.name, doc_text_cached, risks_list, risk_score, plain_summary_cached, doc_hash=doc_hash)
                    st.download_button("📥 Download PDF Report", pdf_bytes, f"risk_report_{uploaded_file.name.replace('.pdf', '')}.pdf", "application/pdf", use_container_width=True)
                except Exception as e:
                    st.error(f"PDF generation failed: {str(e)}")
            with col2:
                st.write("**Document Fingerprint:**")
                st.code(doc_hash)
            with col3:
                if uploaded_file.type == "application/pdf":
                    try:
                        uploaded_file.seek(0)
                        annotated_bytes, located, total = generate_annotated_pdf(uploaded_file.getvalue(), risks_list)
                        st.download_button(
                            "🖍️ Download Annotated PDF",
                            annotated_bytes,
                            f"annotated_{uploaded_file.name}",
                            "application/pdf",
                            use_container_width=True,
                        )
                        st.caption(f"Highlighted {located}/{total} flagged clauses at their real location.")
                    except Exception as e:
                        st.error(f"Annotated PDF generation failed: {str(e)}")
                else:
                    st.caption("Annotated PDF is only available for PDF uploads.")

            render_negotiation_email_ui(uploaded_file.name, risks_list, key_prefix=f"cached_{doc_hash}")
            continue

        extract_loader = st.empty()
        extract_loader.markdown(render_loader("Extracting text from document"), unsafe_allow_html=True)
        doc_text = extract_text(uploaded_file)
        extract_loader.empty()

        if doc_text is None:
            continue

        # Store in session state for potential re-use (cached report downloads)
        st.session_state[f"doc_text_{doc_hash}"] = doc_text

        # This document's hash didn't match any exact cache hit above, but it
        # might still be an edited version of something already analyzed —
        # check text similarity against this user's history and warn if so.
        similar_doc = find_similar_previous_doc(st.session_state.user_id, doc_text, doc_hash)
        if similar_doc:
            st.warning(
                f"⚠️ **This looks like an edited version of a previously analyzed document:** "
                f"**{similar_doc['filename']}** (analyzed {similar_doc['date']}, "
                f"~{similar_doc['similarity']*100:.0f}% text match, previous risk score: "
                f"{similar_doc['risk_score']}/100). The fingerprint has changed because the "
                f"content was modified — re-analyzing below to catch any newly introduced risks."
            )
            with st.expander("🔍 See exactly what changed since that version"):
                old_lines = (similar_doc.get('old_text') or '').splitlines()
                new_lines = doc_text.splitlines()
                diff = list(difflib.unified_diff(
                    old_lines, new_lines,
                    fromfile=f"{similar_doc['filename']} (previous, score {similar_doc['risk_score']}/100)",
                    tofile=f"{uploaded_file.name} (current)",
                    lineterm='', n=1,
                ))
                changed_lines = [l for l in diff if l.startswith(('+', '-')) and not l.startswith(('+++', '---'))]
                if changed_lines:
                    st.code('\n'.join(changed_lines[:150]), language='diff')
                    if len(changed_lines) > 150:
                        st.caption(f"...and {len(changed_lines) - 150} more changed lines (truncated for display).")
                else:
                    st.write("No line-level text differences detected — likely only whitespace or formatting changed.")
                st.caption("Green (+) lines are new/changed text in this version; red (-) lines were removed or replaced. Run the analysis below to see the new risk score and compare it against the previous one.")

        st.write(f"**Document length:** {len(doc_text)} characters")

        mode = st.radio("Analysis Mode", ["⚡ Fast Mode", "🔍 Thorough Mode"], key=f"mode_{uploaded_file.name}", horizontal=True)

        if "Fast" in mode:
            scan_loader = st.empty()
            scan_loader.markdown(render_loader("Scanning for risks", "Running the 20-pattern rule engine"), unsafe_allow_html=True)
            risky_clauses = find_risky_clauses(doc_text)
            scan_loader.empty()

            risk_count = len(risky_clauses)
            risk_score = calculate_risk_score(risky_clauses)

            cols = st.columns(3)
            with cols[0]:
                color = "#dc2626" if risk_score >= 70 else "#d97706" if risk_score >= 40 else "#16a34a"
                st.markdown(f'''
                <div class="metric-box">
                    <div class="metric-value" style="color:{color};">{risk_score}</div>
                    <div class="metric-label">Risk Score / 100</div>
                </div>
                ''', unsafe_allow_html=True)
            with cols[1]:
                st.markdown(f'''
                <div class="metric-box">
                    <div class="metric-value">{risk_count}</div>
                    <div class="metric-label">Risks Found</div>
                </div>
                ''', unsafe_allow_html=True)
            with cols[2]:
                status_color = "#dc2626" if risk_score >= 70 else "#d97706" if risk_score >= 40 else "#16a34a"
                status_text = "HIGH RISK" if risk_score >= 70 else "MEDIUM RISK" if risk_score >= 40 else "LOW RISK"
                st.markdown(f'''
                <div class="metric-box">
                    <div class="metric-value" style="color:{status_color};font-size:1.5rem;">{status_text}</div>
                    <div class="metric-label">Assessment</div>
                </div>
                ''', unsafe_allow_html=True)

            if risky_clauses:
                categories = {}
                for r in risky_clauses:
                    cat = r['category']
                    categories[cat] = categories.get(cat, 0) + 1

                st.markdown("<h3 style='margin:1.5rem 0 0.5rem 0;'>Risk Breakdown</h3>", unsafe_allow_html=True)
                cols = st.columns(min(len(categories), 4))
                for i, (cat, count) in enumerate(categories.items()):
                    with cols[i % 4]:
                        st.markdown(f'''
                        <div class="metric-box" style="padding:1rem;">
                            <div style="font-size:1.5rem;font-weight:700;color:#111827;">{count}</div>
                            <div style="font-size:0.75rem;color:#6b7280;text-transform:uppercase;">{cat}</div>
                        </div>
                        ''', unsafe_allow_html=True)

            # ===== PROGRESS TRACKING FOR SUMMARY =====
            summary_status = st.empty()
            summary_status.markdown(render_loader("Generating plain-English summary"), unsafe_allow_html=True)

            start_time = time.time()
            plain_summary = get_plain_summary(risky_clauses, doc_text)

            summary_status.markdown(
                render_loader_done("Summary complete", f"⏱️ {time.time() - start_time:.1f}s"),
                unsafe_allow_html=True,
            )

            st.markdown(f'''
            <div class="summary-box">
                <h4 style="margin:0 0 0.5rem 0;color:#374151;">📝 Plain English Summary</h4>
                <p style="margin:0;color:#4b5563;">{plain_summary}</p>
            </div>
            ''', unsafe_allow_html=True)

            if risky_clauses:
                st.markdown(f"<h3 style='margin:1.5rem 0 0.5rem 0;'>Flagged Clauses ({len(risky_clauses)})</h3>", unsafe_allow_html=True)
                for i, clause in enumerate(risky_clauses, 1):
                    with st.expander(f"Clause {i} — {clause['category']} ({clause['severity']})"):
                        st.write(f'"{clause["text"][:300]}..."')
                        if clause.get('benchmark'):
                            st.caption(f"📚 {clause['benchmark']}")
                        render_explain_button(clause['text'][:300], '', clause['category'], key=f"rule_{doc_hash}_{i}")

                if uploaded_file.type == "application/pdf":
                    if st.button("🖍️ Download Annotated PDF (rule-scan highlights)", key=f"annotate_rule_{uploaded_file.name}", use_container_width=True):
                        try:
                            annotated_bytes, located, total = generate_annotated_pdf(uploaded_file.getvalue(), risky_clauses)
                            st.download_button(
                                "📥 Save Annotated PDF",
                                annotated_bytes,
                                f"annotated_{uploaded_file.name}",
                                "application/pdf",
                                key=f"annotate_rule_dl_{uploaded_file.name}",
                                use_container_width=True,
                            )
                            st.caption(f"Highlighted {located}/{total} flagged clauses at their real location. Run Deep AI Analysis first for richer margin notes (why/fix).")
                        except Exception as e:
                            st.error(f"Annotated PDF generation failed: {str(e)}")

                deep_btn = st.button(f"🚀 Deep AI Analysis", key=f"deep_{uploaded_file.name}", use_container_width=True)
                deep_cache_key = f"deep_analysis_{doc_hash}"

                if deep_btn:
                    # An explicit click always regenerates a fresh analysis.
                    st.session_state.pop(deep_cache_key, None)

                # IMPORTANT: gate on "button clicked OR already have cached
                # results" rather than the bare button return value. A plain
                # `if st.button(...):` only stays True for the single rerun
                # where it was clicked — clicking anything *inside* this
                # block (the tone picker, "Explain further", "Draft
                # negotiation email", a download button) triggers a rerun
                # where the button reads False again, which would silently
                # collapse this entire section, including the email UI.
                if deep_btn or deep_cache_key in st.session_state:
                    if deep_cache_key not in st.session_state:
                        # ===== PROGRESS TRACKING FOR DEEP AI ANALYSIS =====
                        deep_status = st.empty()
                        deep_progress = st.progress(0, text="Initializing AI analysis...")
                        start_time = time.time()
                        deep_status.markdown(render_loader("Preparing flagged clauses for AI review"), unsafe_allow_html=True)

                        combined = "\n\n".join([f"{i+1}. [{r['category']}] {r['text'][:400]}" for i, r in enumerate(risky_clauses[:12])])

                        prompt = PromptTemplate.from_template("""
                        Analyze these contract clauses. Output in this format:
                        **RISK:** [One-line summary]
                        **QUOTE:** "[Key phrase, max 8 words]"
                        **WHY:** [One sentence impact]
                        **SEVERITY:** [HIGH/MEDIUM/LOW]
                        **CATEGORY:** [Payment/Termination/Liability/Rights/Data Rights/Legal Rights/Fairness/Control]
                        **FIX:** [Suggested fair alternative, max 10 words]
                        Rules:
                        - Maximum 8 risks total
                        - No introductions, no conclusions
                        - If no risks: "No significant risks."
                        Clauses:
                        {clauses}
                        """)

                        chain = prompt | llm
                        try:
                            # Simulate progress steps
                            deep_progress.progress(0.25, text="Sending to local LLM...")
                            deep_status.markdown(render_loader("AI analyzing flagged clauses", "Waiting on the local model (Phi-3 Mini)"), unsafe_allow_html=True)
                            time.sleep(0.5)

                            result = chain.invoke({"clauses": combined[:5000]})

                            deep_progress.progress(0.75, text="Processing response...")
                            deep_status.markdown(render_loader("Processing the model's response"), unsafe_allow_html=True)
                            time.sleep(0.3)

                            result = truncate_response(result, max_lines=50)

                            deep_progress.progress(1.0, text="Analysis complete!")
                            elapsed = time.time() - start_time
                            deep_status.markdown(render_loader_done("Deep AI Analysis complete", f"⏱️ {elapsed:.1f}s"), unsafe_allow_html=True)
                        except Exception as e:
                            deep_progress.empty()
                            st.error(f"AI analysis failed: {str(e)}")
                            result = "No significant risks."

                        risk_blocks = re.split(r'\*\*RISK:\*\*|\*\*Risk:\*\*|\bRISK:\b|\bRisk:\b', result)
                        parsed_risks = []

                        for block in risk_blocks[1:]:
                            if len(block.strip()) < 10:
                                continue
                            risk_data = parse_risk_block(block)
                            if risk_data['quote'] or risk_data['why']:
                                parsed_risks.append(risk_data)

                        if not parsed_risks and "No significant risks" not in result:
                            st.session_state[f"deep_raw_fallback_{doc_hash}"] = result

                        save_analysis(st.session_state.user_id, uploaded_file.name, doc_hash, doc_text, risk_score, len(parsed_risks), parsed_risks)
                        st.session_state[deep_cache_key] = {'result': result, 'parsed_risks': parsed_risks}

                    # From here on, always render from the cached results —
                    # whether they were just computed above or reused from a
                    # previous run — so nested-widget clicks never lose them.
                    cached = st.session_state[deep_cache_key]
                    result = cached['result']
                    parsed_risks = cached['parsed_risks']

                    st.markdown("<h3 style='margin:1.5rem 0 0.5rem 0;'>🚨 Detailed Risk Analysis</h3>", unsafe_allow_html=True)

                    for d_idx, risk_data in enumerate(parsed_risks):
                        sev = risk_data['severity']
                        badge = f'<span class="badge badge-{sev.lower()}">{sev}</span>'
                        st.markdown(f'''
                        <div class="risk-item {sev.lower()}">
                            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
                                <h4 style="margin:0;color:#111827;">{risk_data["category"]}</h4>
                                {badge}
                            </div>
                            <p style="margin:0.25rem 0;font-style:italic;color:#4b5563;">"{risk_data["quote"]}"</p>
                            <p style="margin:0.25rem 0;color:#4b5563;"><strong>Why it matters:</strong> {risk_data["why"]}</p>
                            {f'<p style="margin:0.25rem 0;color:#16a34a;"><strong>💡 Suggested Fix:</strong> {risk_data["fix"]}</p>' if risk_data["fix"] else ''}
                        </div>
                        ''', unsafe_allow_html=True)
                        render_explain_button(risk_data.get('quote', ''), risk_data.get('why', ''), risk_data.get('category', 'Risk'), key=f"deepitem_{doc_hash}_{d_idx}")

                    if not parsed_risks and "No significant risks" not in result:
                        st.warning("Could not parse structured output. Raw response:")
                        st.code(result)

                    col1, col2 = st.columns(2)
                    with col1:
                        try:
                            pdf_bytes = generate_pdf_report(uploaded_file.name, doc_text, parsed_risks, risk_score, plain_summary, doc_hash=doc_hash)
                            st.download_button("📥 Download PDF Report", pdf_bytes, f"risk_report_{uploaded_file.name.replace('.pdf', '')}.pdf", "application/pdf", use_container_width=True)
                        except Exception as e:
                            st.error(f"PDF generation failed: {str(e)}")

                    with col2:
                        redlined = apply_redline(doc_text, parsed_risks)
                        st.download_button("📥 Download Redlined Text", redlined, f"redlined_{uploaded_file.name.replace('.pdf', '')}.txt", "text/plain", use_container_width=True)

                    render_negotiation_email_ui(uploaded_file.name, parsed_risks, key_prefix=f"deep_{doc_hash}")
            else:
                st.success("✅ No obvious red flags detected.")
                save_analysis(st.session_state.user_id, uploaded_file.name, doc_hash, doc_text, 0, 0, [])

        elif "Thorough" in mode:
            thorough_btn = st.button(f"🚀 Start Thorough Analysis", key=f"thorough_{uploaded_file.name}", use_container_width=True)
            thorough_cache_key = f"thorough_analysis_{doc_hash}"

            if thorough_btn:
                st.session_state.pop(thorough_cache_key, None)

            # Same sticky-cache fix as Deep AI Analysis above: a bare
            # `if st.button(...):` would collapse this whole section (and
            # the negotiation email UI inside it) the moment any nested
            # widget triggers a rerun.
            if thorough_btn or thorough_cache_key in st.session_state:
                if thorough_cache_key not in st.session_state:
                    init_loader = st.empty()
                    init_loader.markdown(render_loader("Preparing document", "Splitting into overlapping chunks"), unsafe_allow_html=True)
                    chunk_size = 1500
                    overlap = 100
                    chunks = []
                    start = 0
                    while start < len(doc_text):
                        end = min(start + chunk_size, len(doc_text))
                        chunks.append(doc_text[start:end])
                        start = end - overlap if end < len(doc_text) else end
                    init_loader.empty()

                    # ===== PROGRESS TRACKING FOR THOROUGH ANALYSIS =====
                    progress_bar = st.progress(0, text="Initializing thorough analysis...")
                    status_text = st.empty()
                    status_text.markdown(render_loader("Analyzing entire document", f"0 of {len(chunks)} chunks"), unsafe_allow_html=True)
                    start_time = time.time()
                    all_risks = []

                    def analyze_chunk(args):
                        i, chunk = args
                        prompt = PromptTemplate.from_template("""
                        You are a legal risk analyzer. Review this contract section.
                        STRICT RULES:
                        - Maximum 2 risks per section
                        - Each risk must follow this EXACT format:
                        **RISK:** [One-line summary]
                        **QUOTE:** "[Exact text, max 8 words]"
                        **WHY:** [One sentence]
                        **SEVERITY:** [HIGH/MEDIUM/LOW]
                        **CATEGORY:** [Payment/Termination/Liability/Rights/Data Rights/Legal Rights/Fairness/Control]
                        - No introductions, no conclusions
                        - If no risks: "No significant risks."
                        Section {section_num} of {total_sections}:
                        {text}
                        """)
                        chain = prompt | llm
                        try:
                            result = chain.invoke({"text": chunk, "section_num": i + 1, "total_sections": len(chunks)})
                            return truncate_response(result, max_lines=12)
                        except Exception as e:
                            return f"Error: {str(e)}"

                    with ThreadPoolExecutor(max_workers=2) as executor:
                        completed = 0
                        # ============ FIX APPLIED HERE ============
                        for i, result in enumerate(executor.map(analyze_chunk, enumerate(chunks))):
                        # ==========================================
                            if "No significant risks" not in result and "Error:" not in result:
                                all_risks.append({'section': i + 1, 'raw': result})
                            completed += 1
                            update_progress_ui(progress_bar, status_text, completed, len(chunks), start_time, "Thorough AI Analysis")

                    progress_bar.empty()
                    total_elapsed = time.time() - start_time
                    status_text.markdown(
                        render_loader_done(
                            "Thorough Analysis complete",
                            f"⏱️ {total_elapsed:.1f}s total &nbsp;|&nbsp; {total_elapsed/len(chunks):.1f}s/chunk avg &nbsp;|&nbsp; {len(chunks)} chunks processed",
                        ),
                        unsafe_allow_html=True,
                    )

                    parsed_risks = []
                    for risk in all_risks:
                        # A single chunk can contain up to 2 "**RISK:**" blocks
                        # (per the prompt's "Maximum 2 risks per section" rule).
                        # Split them out individually instead of parsing the
                        # whole raw chunk as one block, which would merge or
                        # drop the second risk.
                        risk_blocks = re.split(r'\*\*RISK:\*\*|\*\*Risk:\*\*|\bRISK:\b|\bRisk:\b', risk['raw'])
                        # If the LLM didn't use the expected "**RISK:**" marker at all,
                        # fall back to treating the whole raw response as one block
                        # rather than silently discarding it.
                        blocks_to_parse = risk_blocks[1:] if len(risk_blocks) > 1 else risk_blocks
                        for block in blocks_to_parse:
                            if len(block.strip()) < 10:
                                continue
                            risk_data = parse_risk_block(block)
                            if risk_data['quote'] or risk_data['why']:
                                parsed_risks.append(risk_data)

                    risk_score = calculate_risk_score(parsed_risks)
                    risk_count = len(parsed_risks)
                    plain_summary = get_plain_summary(parsed_risks, doc_text)

                    save_analysis(st.session_state.user_id, uploaded_file.name, doc_hash, doc_text, risk_score, risk_count, parsed_risks)
                    st.session_state[thorough_cache_key] = {
                        'parsed_risks': parsed_risks,
                        'risk_score': risk_score,
                        'risk_count': risk_count,
                        'plain_summary': plain_summary,
                    }

                # From here on, always render from cached results so nested
                # widget clicks (explain buttons, email drafting, downloads)
                # never lose this section.
                cached = st.session_state[thorough_cache_key]
                parsed_risks = cached['parsed_risks']
                risk_score = cached['risk_score']
                risk_count = cached['risk_count']
                plain_summary = cached['plain_summary']

                cols = st.columns(3)
                with cols[0]:
                    color = "#dc2626" if risk_score >= 70 else "#d97706" if risk_score >= 40 else "#16a34a"
                    st.markdown(f'''
                    <div class="metric-box">
                        <div class="metric-value" style="color:{color};">{risk_score}</div>
                        <div class="metric-label">Risk Score / 100</div>
                    </div>
                    ''', unsafe_allow_html=True)
                with cols[1]:
                    st.markdown(f'''
                    <div class="metric-box">
                        <div class="metric-value">{risk_count}</div>
                        <div class="metric-label">Risks Found</div>
                    </div>
                    ''', unsafe_allow_html=True)
                with cols[2]:
                    status_color = "#dc2626" if risk_score >= 70 else "#d97706" if risk_score >= 40 else "#16a34a"
                    status_text = "HIGH RISK" if risk_score >= 70 else "MEDIUM RISK" if risk_score >= 40 else "LOW RISK"
                    st.markdown(f'''
                    <div class="metric-box">
                        <div class="metric-value" style="color:{status_color};font-size:1.5rem;">{status_text}</div>
                        <div class="metric-label">Assessment</div>
                    </div>
                    ''', unsafe_allow_html=True)

                st.markdown(f'''
                <div class="summary-box">
                    <h4 style="margin:0 0 0.5rem 0;color:#374151;">📝 Plain English Summary</h4>
                    <p style="margin:0;color:#4b5563;">{plain_summary}</p>
                </div>
                ''', unsafe_allow_html=True)

                if parsed_risks:
                    st.markdown(f"<h3 style='margin:1.5rem 0 0.5rem 0;'>🚨 Risk Analysis ({len(parsed_risks)})</h3>", unsafe_allow_html=True)
                    for t_idx, risk in enumerate(parsed_risks):
                        sev = risk['severity']
                        badge = f'<span class="badge badge-{sev.lower()}">{sev}</span>'
                        st.markdown(f'''
                        <div class="risk-item {sev.lower()}">
                            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
                                <h4 style="margin:0;color:#111827;">{risk["category"]}</h4>
                                {badge}
                            </div>
                            <p style="margin:0.25rem 0;font-style:italic;color:#4b5563;">"{risk["quote"]}"</p>
                            <p style="margin:0.25rem 0;color:#4b5563;">{risk["why"]}</p>
                        </div>
                        ''', unsafe_allow_html=True)
                        render_explain_button(risk.get('quote', ''), risk.get('why', ''), risk.get('category', 'Risk'), key=f"thorough_{doc_hash}_{t_idx}")

                col1, col2, col3 = st.columns(3)
                with col1:
                    try:
                        pdf_bytes = generate_pdf_report(uploaded_file.name, doc_text, parsed_risks, risk_score, plain_summary, doc_hash=doc_hash)
                        st.download_button("📥 Download PDF Report", pdf_bytes, f"risk_report_{uploaded_file.name.replace('.pdf', '')}.pdf", "application/pdf", use_container_width=True)
                    except Exception as e:
                        st.error(f"PDF generation failed: {str(e)}")

                with col2:
                    st.write("**Document Fingerprint:**")
                    st.code(doc_hash)

                with col3:
                    if uploaded_file.type == "application/pdf" and parsed_risks:
                        try:
                            annotated_bytes, located, total = generate_annotated_pdf(uploaded_file.getvalue(), parsed_risks)
                            st.download_button(
                                "🖍️ Download Annotated PDF",
                                annotated_bytes,
                                f"annotated_{uploaded_file.name}",
                                "application/pdf",
                                use_container_width=True,
                            )
                            st.caption(f"Highlighted {located}/{total} flagged clauses at their real location.")
                        except Exception as e:
                            st.error(f"Annotated PDF generation failed: {str(e)}")
                    else:
                        st.caption("Annotated PDF is only available for PDF uploads with flagged risks.")

                render_negotiation_email_ui(uploaded_file.name, parsed_risks, key_prefix=f"thorough_{doc_hash}")

    if st.session_state.get('show_history', False):
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("📚 Analysis History")
        history = get_history(st.session_state.user_id)
        if not history:
            st.info("No previous analyses found.")
        else:
            for row in history:
                with st.expander(f"{row[2]} — {row[7]}"):
                    st.write(f"**Risk Score:** {row[5]}/100")
                    st.write(f"**Risks Found:** {row[6]}")
                    st.write(f"**Document Hash:** `{row[3][:16]}...`")
                    if uploaded_files:
                        for uf in uploaded_files:
                            if get_doc_hash(uf.getvalue()) == row[3]:
                                st.warning("⚠️ This is the same document!")
        st.markdown('</div>', unsafe_allow_html=True)

    if uploaded_files and len(uploaded_files) == 2:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("📊 Document Comparison")
        if st.button("Compare Documents", use_container_width=True):
            file1, file2 = uploaded_files[0], uploaded_files[1]
            text1 = extract_text(file1)
            text2 = extract_text(file2)
            if text1 is None or text2 is None:
                st.error("Could not extract text from one or both documents.")
            else:
                risks1 = find_risky_clauses(text1)
                risks2 = find_risky_clauses(text2)
                score1 = calculate_risk_score(risks1)
                score2 = calculate_risk_score(risks2)

                cols = st.columns(2)
                with cols[0]:
                    color = "#dc2626" if score1 >= 70 else "#d97706" if score1 >= 40 else "#16a34a"
                    st.markdown(f'''
                    <div class="metric-box">
                        <h4 style="margin:0 0 0.5rem 0;">{file1.name}</h4>
                        <div class="metric-value" style="color:{color};">{score1}</div>
                        <div class="metric-label">{len(risks1)} risks found</div>
                    </div>
                    ''', unsafe_allow_html=True)
                with cols[1]:
                    color = "#dc2626" if score2 >= 70 else "#d97706" if score2 >= 40 else "#16a34a"
                    st.markdown(f'''
                    <div class="metric-box">
                        <h4 style="margin:0 0 0.5rem 0;">{file2.name}</h4>
                        <div class="metric-value" style="color:{color};">{score2}</div>
                        <div class="metric-label">{len(risks2)} risks found</div>
                    </div>
                    ''', unsafe_allow_html=True)

                if score1 < score2:
                    st.success(f"✅ **{file1.name}** is the safer choice.")
                elif score2 < score1:
                    st.success(f"✅ **{file2.name}** is the safer choice.")
                else:
                    st.info("Both documents have similar risk levels.")
        st.markdown('</div>', unsafe_allow_html=True)

    if uploaded_files and len(uploaded_files) > 2:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("📦 Batch Processing")
        st.write(f"Processing {len(uploaded_files)} documents...")

        batch_results = []
        for uf in uploaded_files:
            text = extract_text(uf)
            if text is not None:
                risks = find_risky_clauses(text)
                score = calculate_risk_score(risks)
                batch_results.append({'name': uf.name, 'score': score, 'risks': len(risks)})

        batch_results.sort(key=lambda x: x['score'])

        st.write("**Ranked by Safety (Safest First)**")
        for i, doc in enumerate(batch_results, 1):
            color = "#16a34a" if doc['score'] < 40 else "#d97706" if doc['score'] < 70 else "#dc2626"
            st.markdown(f'''
            <div class="risk-item" style="border-left-color:{color};">
                <div style="display:flex;justify-content:space-between;align-items:center;">
                    <span style="font-weight:600;color:#111827;">#{i} {doc["name"]}</span>
                    <span style="color:{color};font-weight:600;">{doc["score"]}/100</span>
                </div>
                <div style="font-size:0.875rem;color:#6b7280;margin-top:0.25rem;">{doc["risks"]} risks found</div>
            </div>
            ''', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
