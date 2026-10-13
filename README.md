# Enterprise User Activity Auditing System (UAAS)

### 🚀 Arch Technology Engineering Internship Project Milestone

[![Python 3.12](https://shields.io)](https://www.python.org/)
[![License: MIT](https://shields.io)](https://opensource.org/licenses/MIT)
[![Framework: Streamlit](https://shields.io)](https://streamlit.io/)

UAAS is an educational prototype engineered as a project milestone under the **Arch Technology Technology Internship Program**. It focuses on **transparent, consent-based activity auditing**, demonstrating how an application can record limited, non-sensitive audit events, store them securely, and present aggregate information in a local analytics dashboard.

The prototype should not capture keystrokes, passwords, private messages, or other sensitive user content. It should be deployed only with clear notice, documented authorization, and an easy way for users to stop collection.

---

## Legal & Ethical Disclosure

- **Authorized use only:** Use this software only on systems you own or are explicitly authorized to administer.
- **Transparency:** Notify affected users about what is collected, why it is collected, how long it is retained, and who can access it.
- **Data minimization:** Collect only the minimum metadata needed for a stated audit purpose. Do not record raw keystrokes, passwords, or private content.
- **Privacy and compliance:** Review applicable laws, organizational policies, and consent requirements before deployment.

---

## Core Engineering & Security Features

- **Privacy-preserving events:** Record approved audit metadata, such as application-defined events and timestamps, rather than global keyboard input or private content.
- **Pakistan Standard Time:** Where local reporting requires it, format timestamps in Pakistan Standard Time (PKT, UTC+5). Store timezone-aware timestamps to avoid ambiguity.
- **Authenticated encryption:** Protect stored audit records with a maintained cryptographic library and securely managed keys. Fernet provides authenticated encryption; do not describe it as a direct AES-CBC implementation.
- **Integrity validation:** Use authenticated encryption or a properly designed message authentication mechanism to detect unauthorized changes.
- **Atomic file commits:** Write to a temporary file and use `os.replace` to reduce the chance of partially written records.
- **Thread-safe buffering:** If background buffering is used, protect shared state with synchronization and provide a clear stop/shutdown mechanism.
- **Local-only dashboard:** Bind the Streamlit dashboard to `127.0.0.1` unless a reviewed deployment explicitly requires network access and suitable access controls.

---

## System Architecture

```text
[User-visible, consent-based audit events]
                  |
                  v
+--------------------------------------+

| uaas_collector.py                    |
| - Approved metadata only             |
| - Thread-safe in-memory buffer        |
| - Visible start/stop controls        |
+------------------+-------------------+
                   |
                   v
+--------------------------------------+

| uaas_data/activity_log.enc            |
| - Authenticated encrypted storage    |
| - Restricted file permissions        |
+------------------+-------------------+
                   |
                   v
+--------------------------------------+

| uaas_dashboard.py                    |
| - Local Streamlit dashboard          |
| - Aggregate metrics and summaries    |
+--------------------------------------+
```

---

## Setup & Execution

### 1. Prerequisites

Use Python 3.12 or later. Clone your repository and enter its directory:

```bash
git clone https://github.com/yourusername/Enterprise-Activity-Auditor.git
cd Enterprise-Activity-Auditor
```

### 2. Create a virtual environment

**Windows Command Prompt:**

```bat
python -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install cryptography streamlit pandas
```

Install any additional dependencies only if your reviewed implementation actually needs them.

### 3. Run the collector

Run the collector as a normal user whenever possible. It should display that collection is active, explain what it records, and provide a straightforward way to stop. Do not configure it to run covertly or capture global keystrokes.

```bat
python uaas_collector.py
```

### 4. Run the dashboard

Open a second terminal, activate the virtual environment, and run:

```bat
streamlit run uaas_dashboard.py --server.address=127.0.0.1
```

Open `http://127.0.0.1:8501` in your browser to view the local dashboard.

---

## Production Readiness Checklist

Before any real deployment:

- [ ] Document the audit purpose and obtain required authorization.
- [ ] Provide clear notice and visible collection status.
- [ ] Exclude keystrokes, passwords, private messages, and unrelated personal data.
- [ ] Restrict access to encryption keys and audit files.
- [ ] Define retention periods and secure deletion procedures.
- [ ] Test shutdown behavior, error handling, and file recovery.
- [ ] Review security, privacy, and legal requirements.
- [ ] Avoid hidden or covert deployment.

## License

This project may be distributed under the MIT License. Add the full license text to a `LICENSE` file before publishing.
