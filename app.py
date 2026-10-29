"""
IIIT Dharwad — Zero-Trust Student Attendance System
Single-file Streamlit application (SQLite persistence).
"""

from __future__ import annotations

import hashlib
import io
import secrets
import sqlite3
import string
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_TITLE = "IIIT Dharwad Attendance"
INSTITUTE = "Indian Institute of Information Technology Dharwad"
ALLOWED_DOMAIN = "@iiitdwd.ac.in"
MOCK_LOGIN_OTP = "1234"
DB_PATH = Path(__file__).resolve().parent / "attendance.db"
OTP_LENGTH = 5
JOIN_CODE_LENGTH = 6
OTP_TTL_SECONDS = 15
OTP_ALPHABET = "".join(c for c in (string.ascii_uppercase + string.digits) if c not in "01OI")
ANTI_PROXY_JS = """
<script>
document.addEventListener('visibilitychange', function() {
  if (document.hidden) {
    // Call Streamlit to force session termination
    window.parent.postMessage({type: 'streamlit:setComponentValue', value: 'TAB_SWITCHED'}, '*');
  }
});
</script>
"""

# ---------------------------------------------------------------------------
# Page config & theme
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title=APP_TITLE,
    page_icon="🎓",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@600;700&display=swap');
      html, body, [class*="css"] { font-family: 'IBM Plex Sans', sans-serif; }
      .stApp { background: linear-gradient(180deg, #07111f 0%, #0d1b2e 40%, #10233a 100%); }
      .block-container { padding-top: 1.4rem; max-width: 1200px; }
      h1, h2, h3 { letter-spacing: -0.02em; color: #f4f7fb !important; }
      [data-testid="stSidebar"] { background: #081525; border-right: 1px solid #1c3350; }
      .hero-kicker { color: #7dd3fc; font-weight: 600; letter-spacing: 0.12em; text-transform: uppercase; font-size: 0.78rem; }
      .card { background: #12243a; border: 1px solid #23405f; border-radius: 16px; padding: 1.15rem 1.25rem; margin-bottom: 0.85rem; }
      .join-code { font-family: 'IBM Plex Mono', monospace; font-size: 1.8rem; letter-spacing: 0.28em; color: #fbbf24; }
      .otp-hero { font-family: 'IBM Plex Mono', monospace; font-size: 4.4rem; letter-spacing: 0.35em; color: #f8fafc; text-align: center; margin: 0.4rem 0; }
      .otp-sub { text-align: center; color: #94a3b8; }
      .banner-danger {
        background: #7f1d1d; border: 1px solid #f87171; color: #fff;
        padding: 0.95rem 1.1rem; border-radius: 12px; font-weight: 600;
      }
      .muted { color: #94a3b8; }
      .metric-chip { display: inline-block; background: #1e3a5f; color: #e2e8f0; padding: 0.2rem 0.65rem; border-radius: 999px; font-size: 0.82rem; }
      div[data-testid="stMetricValue"] { color: #f8fafc; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'professor', 'student')),
                roll_number TEXT,
                fingerprint_hash TEXT
            );
            CREATE TABLE IF NOT EXISTS courses (
                course_id TEXT PRIMARY KEY,
                course_name TEXT NOT NULL,
                professor_email TEXT NOT NULL,
                join_code TEXT UNIQUE NOT NULL,
                FOREIGN KEY (professor_email) REFERENCES users(email)
            );
            CREATE TABLE IF NOT EXISTS enrollments (
                course_id TEXT NOT NULL,
                student_email TEXT NOT NULL,
                joined_at TEXT NOT NULL,
                PRIMARY KEY (course_id, student_email),
                FOREIGN KEY (course_id) REFERENCES courses(course_id),
                FOREIGN KEY (student_email) REFERENCES users(email)
            );
            CREATE TABLE IF NOT EXISTS attendance_sessions (
                session_id TEXT PRIMARY KEY,
                course_id TEXT NOT NULL,
                date TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                current_otp TEXT,
                otp_expires_at REAL,
                FOREIGN KEY (course_id) REFERENCES courses(course_id)
            );
            CREATE TABLE IF NOT EXISTS attendance_records (
                session_id TEXT NOT NULL,
                student_email TEXT NOT NULL,
                status INTEGER NOT NULL DEFAULT 0 CHECK(status IN (0, 1)),
                marked_at TEXT,
                PRIMARY KEY (session_id, student_email),
                FOREIGN KEY (session_id) REFERENCES attendance_sessions(session_id),
                FOREIGN KEY (student_email) REFERENCES users(email)
            );
            """
        )


def query_df(sql: str, params: tuple = ()) -> pd.DataFrame:
    with db() as conn:
        return pd.read_sql_query(sql, conn, params=params)


def fetchone(sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
    with db() as conn:
        return conn.execute(sql, params).fetchone()


def fetchall(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    with db() as conn:
        return conn.execute(sql, params).fetchall()


def execute(sql: str, params: tuple = ()) -> None:
    with db() as conn:
        conn.execute(sql, params)


# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def today_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def detect_role(email: str) -> str:
    local = email.split("@", 1)[0].lower()
    if "admin" in local:
        return "admin"
    if "prof" in local or "faculty" in local:
        return "professor"
    return "student"


def extract_roll_number(email: str, role: str) -> Optional[str]:
    if role != "student":
        return None
    local = email.split("@", 1)[0]
    return local.upper()


def display_name_from_email(email: str, role: str) -> str:
    local = email.split("@", 1)[0]
    if role == "student":
        return extract_roll_number(email, role) or local
    cleaned = local.replace(".", " ").replace("_", " ").replace("-", " ")
    return " ".join(part.capitalize() for part in cleaned.split())


def hash_fingerprint(email: str, secret: str) -> str:
    payload = f"{email.strip().lower()}::{secret.strip()}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def random_code(length: int) -> str:
    return "".join(secrets.choice(OTP_ALPHABET) for _ in range(length))


def unique_join_code() -> str:
    for _ in range(50):
        code = random_code(JOIN_CODE_LENGTH)
        if fetchone("SELECT 1 FROM courses WHERE join_code = ?", (code,)) is None:
            return code
    return uuid.uuid4().hex[:JOIN_CODE_LENGTH].upper()


def upsert_user(email: str, name: str, role: str, roll_number: Optional[str]) -> None:
    existing = fetchone("SELECT email FROM users WHERE email = ?", (email,))
    if existing:
        execute(
            "UPDATE users SET name = ?, role = ?, roll_number = ? WHERE email = ?",
            (name, role, roll_number, email),
        )
        return
    execute(
        "INSERT INTO users (email, name, role, roll_number, fingerprint_hash) VALUES (?, ?, ?, ?, NULL)",
        (email, name, role, roll_number),
    )


def set_fingerprint(email: str, secret: str) -> str:
    digest = hash_fingerprint(email, secret)
    execute("UPDATE users SET fingerprint_hash = ? WHERE email = ?", (digest, email))
    return digest


def mock_network_check() -> bool:
    """Campus network attestation — always passes in the demo build."""
    return True


# ---------------------------------------------------------------------------
# Attendance OTP
# ---------------------------------------------------------------------------


def generate_otp() -> str:
    return random_code(OTP_LENGTH)


def rotate_session_otp(session_id: str, force: bool = False) -> sqlite3.Row:
    row = fetchone("SELECT * FROM attendance_sessions WHERE session_id = ?", (session_id,))
    if row is None:
        raise ValueError("Unknown attendance session")
    now = time.time()
    expired = row["otp_expires_at"] is None or now >= float(row["otp_expires_at"])
    if force or expired or not row["current_otp"]:
        otp = generate_otp()
        expires = now + OTP_TTL_SECONDS
        execute(
            "UPDATE attendance_sessions SET current_otp = ?, otp_expires_at = ? WHERE session_id = ?",
            (otp, expires, session_id),
        )
        row = fetchone("SELECT * FROM attendance_sessions WHERE session_id = ?", (session_id,))
    return row  # type: ignore[return-value]


def otp_seconds_remaining(expires_at: Optional[float]) -> int:
    if not expires_at:
        return 0
    return max(0, int(float(expires_at) - time.time()))


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------


def init_session() -> None:
    defaults: dict[str, Any] = {
        "authenticated": False,
        "email": None,
        "name": None,
        "role": None,
        "roll_number": None,
        "otp_sent": False,
        "pending_email": "",
        "view": "home",
        "selected_course_id": None,
        "mark_session_id": None,
        "tab_switched": False,
        "proxy_terminated": False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def logout() -> None:
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    init_session()
    st.rerun()


# ---------------------------------------------------------------------------
# Anti-proxy component
# ---------------------------------------------------------------------------


def inject_anti_proxy_guard() -> Optional[str]:
    """Inject the exact visibilitychange watcher requested for zero-trust demos."""
    html = f"""<!DOCTYPE html>
<html><head></head><body>
{ANTI_PROXY_JS}
<script>
  (function() {{
    function send(type, data) {{
      const payload = Object.assign({{ isStreamlitMessage: true, type: type }}, data);
      window.parent.postMessage(payload, "*");
    }}
    window.addEventListener("load", function() {{
      send("streamlit:componentReady", {{ apiVersion: 1 }});
      send("streamlit:setFrameHeight", {{ height: 0 }});
    }});
  }})();
</script>
</body></html>"""
    return components.html(html, height=0)


def handle_tab_switch(signal: Optional[str]) -> None:
    if signal == "TAB_SWITCHED":
        st.session_state.tab_switched = True
        st.session_state.proxy_terminated = True
        st.session_state.mark_session_id = None
        st.session_state.view = "home"


# ---------------------------------------------------------------------------
# Auth UI
# ---------------------------------------------------------------------------


def render_login() -> None:
    col_left, col_right = st.columns([1.15, 1], gap="large")
    with col_left:
        st.markdown('<div class="hero-kicker">Zero-Trust · Classroom Attendance</div>', unsafe_allow_html=True)
        st.title(APP_TITLE)
        st.caption(INSTITUTE)
        st.write(
            "Email-only campus login. Roles are inferred from the address: "
            "`admin` → Admin, `prof`/`faculty` → Professor, otherwise Student."
        )
        st.markdown(
            """
            <div class="card">
              <strong>Demo credentials</strong>
              <p class="muted" style="margin-bottom:0.4rem">Any <code>@iiitdwd.ac.in</code> mailbox. Login OTP is always <code>1234</code>.</p>
              <p class="muted" style="margin:0">
                admin@iiitdwd.ac.in · prof.cs@iiitdwd.ac.in · 25bcs053@iiitdwd.ac.in
              </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_right:
        st.subheader("Campus sign-in")
        email = st.text_input(
            "Institute email",
            value=st.session_state.pending_email,
            placeholder="25bcs053@iiitdwd.ac.in",
        ).strip().lower()

        if st.button("Send OTP", type="primary", use_container_width=True):
            if not email.endswith(ALLOWED_DOMAIN) or email == ALLOWED_DOMAIN:
                st.error(f"Only {ALLOWED_DOMAIN} accounts can sign in.")
            else:
                st.session_state.otp_sent = True
                st.session_state.pending_email = email
                st.success(f"Mock OTP dispatched to {email}. Use code {MOCK_LOGIN_OTP}.")

        if st.session_state.otp_sent:
            otp = st.text_input("Enter 4-digit OTP", max_chars=4, type="password")
            if st.button("Verify & continue", use_container_width=True):
                if otp != MOCK_LOGIN_OTP:
                    st.error("Invalid OTP. Demo code is 1234.")
                else:
                    role = detect_role(email)
                    roll = extract_roll_number(email, role)
                    name = display_name_from_email(email, role)
                    upsert_user(email, name, role, roll)
                    st.session_state.authenticated = True
                    st.session_state.email = email
                    st.session_state.name = name
                    st.session_state.role = role
                    st.session_state.roll_number = roll
                    st.session_state.view = "home"
                    st.rerun()


# ---------------------------------------------------------------------------
# Shared chrome
# ---------------------------------------------------------------------------


def sidebar_chrome() -> None:
    with st.sidebar:
        st.markdown(f"**{APP_TITLE}**")
        st.caption(st.session_state.email)
        st.markdown(
            f'<span class="metric-chip">{st.session_state.role.title()}</span>',
            unsafe_allow_html=True,
        )
        if st.session_state.roll_number:
            st.caption(f"Roll · {st.session_state.roll_number}")
        st.divider()
        if st.button("Home", use_container_width=True):
            st.session_state.view = "home"
            st.session_state.selected_course_id = None
            st.session_state.mark_session_id = None
            st.rerun()
        if st.button("Logout", use_container_width=True):
            logout()


# ---------------------------------------------------------------------------
# Professor portal
# ---------------------------------------------------------------------------


def professor_create_course() -> None:
    st.subheader("Create a course")
    with st.form("create_course"):
        course_name = st.text_input("Course name", placeholder="CS301 — Operating Systems")
        submitted = st.form_submit_button("Create course", type="primary")
    if submitted:
        name = course_name.strip()
        if not name:
            st.error("Course name is required.")
            return
        course_id = uuid.uuid4().hex[:10]
        join_code = unique_join_code()
        execute(
            "INSERT INTO courses (course_id, course_name, professor_email, join_code) VALUES (?, ?, ?, ?)",
            (course_id, name, st.session_state.email, join_code),
        )
        st.success("Course created.")
        st.markdown(
            f'<div class="card">Share this join code with students<br>'
            f'<div class="join-code">{join_code}</div></div>',
            unsafe_allow_html=True,
        )


def professor_course_list() -> None:
    courses = fetchall(
        "SELECT * FROM courses WHERE professor_email = ? ORDER BY course_name",
        (st.session_state.email,),
    )
    if not courses:
        st.info("No courses yet. Create one to get a Classroom-style join code.")
        return
    st.subheader("Your courses")
    for course in courses:
        enrolled = fetchone(
            "SELECT COUNT(*) AS n FROM enrollments WHERE course_id = ?",
            (course["course_id"],),
        )["n"]
        cols = st.columns([3, 1.2, 1.1, 1])
        cols[0].markdown(f"**{course['course_name']}**  \n`{course['join_code']}` · {enrolled} enrolled")
        if cols[1].button("Open", key=f"open_{course['course_id']}"):
            st.session_state.selected_course_id = course["course_id"]
            st.session_state.view = "course"
            st.rerun()
        if cols[2].button("Copy code", key=f"code_{course['course_id']}"):
            st.toast(f"Join code: {course['join_code']}")
        cols[3].caption(course["course_id"])


@st.fragment(run_every=1)
def professor_live_otp(session_id: str, course_name: str) -> None:
    row = rotate_session_otp(session_id)
    remaining = otp_seconds_remaining(row["otp_expires_at"])
    st.markdown(
        f'<div class="card"><div class="otp-sub">PROJECTOR CODE · {course_name}</div>'
        f'<div class="otp-hero">{row["current_otp"]}</div>'
        f'<div class="otp-sub">Refreshes in <strong>{remaining}s</strong> · 5-character rolling OTP</div></div>',
        unsafe_allow_html=True,
    )
    st.progress(remaining / OTP_TTL_SECONDS if OTP_TTL_SECONDS else 0.0)


def professor_session_roster(session_id: str, course_id: str) -> None:
    roster = query_df(
        """
        SELECT
            u.email AS student_email,
            u.name,
            u.roll_number,
            COALESCE(ar.status, 0) AS status,
            ar.marked_at
        FROM enrollments e
        JOIN users u ON u.email = e.student_email
        LEFT JOIN attendance_records ar
            ON ar.student_email = e.student_email AND ar.session_id = ?
        WHERE e.course_id = ?
        ORDER BY u.roll_number, u.email
        """,
        (session_id, course_id),
    )
    if roster.empty:
        st.warning("No students enrolled yet.")
        return

    present = int((roster["status"] == 1).sum())
    st.metric("Present", f"{present} / {len(roster)}")

    edited = st.data_editor(
        roster.assign(present=roster["status"].astype(int) == 1)[
            ["student_email", "name", "roll_number", "present", "marked_at"]
        ],
        column_config={
            "student_email": st.column_config.TextColumn("Email", disabled=True),
            "name": st.column_config.TextColumn("Name", disabled=True),
            "roll_number": st.column_config.TextColumn("Roll", disabled=True),
            "present": st.column_config.CheckboxColumn("Present (override)"),
            "marked_at": st.column_config.TextColumn("Marked at", disabled=True),
        },
        hide_index=True,
        use_container_width=True,
        key=f"roster_{session_id}",
    )

    if st.button("Save professor overrides", type="primary"):
        for _, row in edited.iterrows():
            status = 1 if bool(row["present"]) else 0
            marked_at = utcnow_iso() if status == 1 else None
            execute(
                """
                INSERT INTO attendance_records (session_id, student_email, status, marked_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(session_id, student_email)
                DO UPDATE SET status = excluded.status,
                              marked_at = excluded.marked_at
                """,
                (session_id, row["student_email"], status, marked_at),
            )
        st.success("Overrides saved.")
        st.rerun()

    export_df = edited.copy()
    export_df["status"] = export_df["present"].map(lambda v: "Present" if v else "Absent")
    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        export_df.drop(columns=["present"]).to_excel(writer, index=False, sheet_name="Attendance")
    st.download_button(
        "Export Excel",
        data=buffer.getvalue(),
        file_name=f"attendance_{course_id}_{today_iso()}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


def professor_course_detail(course_id: str) -> None:
    course = fetchone("SELECT * FROM courses WHERE course_id = ?", (course_id,))
    if course is None or course["professor_email"] != st.session_state.email:
        st.error("Course not found.")
        return

    st.title(course["course_name"])
    st.markdown(
        f'<div class="card">Join code <span class="join-code">{course["join_code"]}</span></div>',
        unsafe_allow_html=True,
    )

    active = fetchone(
        "SELECT * FROM attendance_sessions WHERE course_id = ? AND is_active = 1 ORDER BY date DESC",
        (course_id,),
    )

    c1, c2, c3 = st.columns(3)
    if c1.button("Initialize Attendance", type="primary", disabled=active is not None):
        execute(
            "UPDATE attendance_sessions SET is_active = 0 WHERE course_id = ?",
            (course_id,),
        )
        session_id = uuid.uuid4().hex
        now = time.time()
        execute(
            """
            INSERT INTO attendance_sessions
                (session_id, course_id, date, is_active, current_otp, otp_expires_at)
            VALUES (?, ?, ?, 1, ?, ?)
            """,
            (session_id, course_id, today_iso(), generate_otp(), now + OTP_TTL_SECONDS),
        )
        students = fetchall(
            "SELECT student_email FROM enrollments WHERE course_id = ?",
            (course_id,),
        )
        for student in students:
            execute(
                """
                INSERT OR IGNORE INTO attendance_records (session_id, student_email, status, marked_at)
                VALUES (?, ?, 0, NULL)
                """,
                (session_id, student["student_email"]),
            )
        st.success("Attendance session is live.")
        st.rerun()

    if active and c2.button("End session"):
        execute(
            "UPDATE attendance_sessions SET is_active = 0 WHERE session_id = ?",
            (active["session_id"],),
        )
        st.rerun()

    if c3.button("← All courses"):
        st.session_state.view = "home"
        st.session_state.selected_course_id = None
        st.rerun()

    if active:
        st.caption(f"Live session · {active['date']} · `{active['session_id'][:8]}`")
        professor_live_otp(active["session_id"], course["course_name"])
        st.subheader("Session attendance")
        professor_session_roster(active["session_id"], course_id)
    else:
        st.info("No active session. Initialize attendance to project a rolling OTP.")
        history = query_df(
            """
            SELECT session_id, date, is_active, current_otp
            FROM attendance_sessions
            WHERE course_id = ?
            ORDER BY date DESC
            """,
            (course_id,),
        )
        if not history.empty:
            st.subheader("Past sessions")
            st.dataframe(history, use_container_width=True, hide_index=True)
            pick = st.selectbox("Review / export a past session", history["session_id"].tolist())
            if pick:
                professor_session_roster(pick, course_id)


def render_professor() -> None:
    if st.session_state.view == "course" and st.session_state.selected_course_id:
        professor_course_detail(st.session_state.selected_course_id)
        return
    st.title("Professor portal")
    st.caption("Google Classroom–style courses, rolling OTPs, live roster, Excel export.")
    professor_create_course()
    st.divider()
    professor_course_list()


# ---------------------------------------------------------------------------
# Student portal
# ---------------------------------------------------------------------------


def student_join_course() -> None:
    st.subheader("Join a course")
    with st.form("join_course"):
        join_code = st.text_input("6-character join code").strip().upper()
        fingerprint = st.text_input(
            "Fingerprint token (mock biometric)",
            type="password",
            help="Any secret phrase. It is hashed and stored against your campus email.",
        )
        submitted = st.form_submit_button("Join course", type="primary")
    if not submitted:
        return
    if len(join_code) != JOIN_CODE_LENGTH:
        st.error("Join codes are 6 characters.")
        return
    if not fingerprint.strip():
        st.error("Fingerprint confirmation is required (zero-trust enrollment).")
        return
    course = fetchone("SELECT * FROM courses WHERE join_code = ?", (join_code,))
    if course is None:
        st.error("Unknown join code.")
        return
    existing = fetchone(
        "SELECT 1 FROM enrollments WHERE course_id = ? AND student_email = ?",
        (course["course_id"], st.session_state.email),
    )
    set_fingerprint(st.session_state.email, fingerprint)
    if existing:
        st.info(f"Already enrolled in {course['course_name']}. Fingerprint updated.")
        return
    execute(
        "INSERT INTO enrollments (course_id, student_email, joined_at) VALUES (?, ?, ?)",
        (course["course_id"], st.session_state.email, utcnow_iso()),
    )
    st.success(f"Joined {course['course_name']}.")


def student_active_banners() -> None:
    rows = fetchall(
        """
        SELECT s.session_id, c.course_id, c.course_name
        FROM enrollments e
        JOIN courses c ON c.course_id = e.course_id
        JOIN attendance_sessions s ON s.course_id = c.course_id AND s.is_active = 1
        WHERE e.student_email = ?
        """,
        (st.session_state.email,),
    )
    for row in rows:
        already = fetchone(
            "SELECT status FROM attendance_records WHERE session_id = ? AND student_email = ?",
            (row["session_id"], st.session_state.email),
        )
        if already and already["status"] == 1:
            st.success(f"Attendance already marked for {row['course_name']}.")
            continue
        cols = st.columns([4, 1])
        cols[0].markdown(
            f'<div class="banner-danger">⚠️ Attendance is initialized for {row["course_name"]}! '
            f"Click here to mark attendance</div>",
            unsafe_allow_html=True,
        )
        if cols[1].button("Mark now", key=f"mark_{row['session_id']}", type="primary"):
            st.session_state.mark_session_id = row["session_id"]
            st.session_state.view = "mark"
            st.session_state.tab_switched = False
            st.rerun()


def student_course_dashboard() -> None:
    courses = query_df(
        """
        SELECT c.course_name, c.join_code, u.name AS professor, e.joined_at
        FROM enrollments e
        JOIN courses c ON c.course_id = e.course_id
        JOIN users u ON u.email = c.professor_email
        WHERE e.student_email = ?
        ORDER BY c.course_name
        """,
        (st.session_state.email,),
    )
    st.subheader("Enrolled courses")
    if courses.empty:
        st.info("You are not enrolled in any course yet.")
    else:
        st.dataframe(courses, use_container_width=True, hide_index=True)


def student_mark_attendance(session_id: str) -> None:
    session = fetchone("SELECT * FROM attendance_sessions WHERE session_id = ?", (session_id,))
    if session is None or not session["is_active"]:
        st.error("This attendance window is closed.")
        return
    course = fetchone("SELECT * FROM courses WHERE course_id = ?", (session["course_id"],))
    enrolled = fetchone(
        "SELECT 1 FROM enrollments WHERE course_id = ? AND student_email = ?",
        (session["course_id"], st.session_state.email),
    )
    if not enrolled:
        st.error("You are not enrolled in this course.")
        return

    signal = inject_anti_proxy_guard()
    handle_tab_switch(signal)
    if st.session_state.proxy_terminated or st.session_state.tab_switched:
        st.error("Zero-trust guard: tab switch detected. Attendance session terminated.")
        st.warning("Return to the dashboard and wait for the professor if a new window is opened.")
        return

    user = fetchone("SELECT * FROM users WHERE email = ?", (st.session_state.email,))
    st.title(f"Mark attendance · {course['course_name']}")
    st.caption("Stay on this tab. Switching away is treated as a proxy attempt.")

    st.text_input("Name", value=st.session_state.name, disabled=True)
    st.text_input("Roll number", value=st.session_state.roll_number or "", disabled=True)
    otp_input = st.text_input("Current 5-character OTP", max_chars=OTP_LENGTH).strip().upper()
    fingerprint = st.text_input("Re-verify fingerprint token", type="password")

    if st.button("Submit attendance", type="primary"):
        if st.session_state.tab_switched:
            st.error("Tab switch detected — submission blocked.")
            return
        live = rotate_session_otp(session_id)
        if not live["is_active"]:
            st.error("Session ended.")
            return
        if time.time() >= float(live["otp_expires_at"] or 0) or otp_input != (live["current_otp"] or "").upper():
            st.error("OTP is invalid or expired. Read the projector code and try again.")
            return
        if not user["fingerprint_hash"]:
            st.error("No enrolled fingerprint. Join the course with a fingerprint token first.")
            return
        if hash_fingerprint(st.session_state.email, fingerprint) != user["fingerprint_hash"]:
            st.error("Fingerprint mismatch.")
            return
        if not mock_network_check():
            st.error("Campus network check failed.")
            return
        execute(
            """
            INSERT INTO attendance_records (session_id, student_email, status, marked_at)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(session_id, student_email)
            DO UPDATE SET status = 1, marked_at = excluded.marked_at
            """,
            (session_id, st.session_state.email, utcnow_iso()),
        )
        st.success("Marked Present. You may close this page.")
        st.balloons()


def render_student() -> None:
    if st.session_state.proxy_terminated and st.session_state.view != "mark":
        st.error("A previous attendance attempt was terminated after a tab-visibility change.")
        if st.button("Dismiss warning"):
            st.session_state.proxy_terminated = False
            st.rerun()

    if st.session_state.view == "mark" and st.session_state.mark_session_id:
        student_mark_attendance(st.session_state.mark_session_id)
        return

    st.title("Student portal")
    st.caption(f"Signed in as {st.session_state.name} · {st.session_state.roll_number}")
    student_active_banners()
    student_join_course()
    st.divider()
    student_course_dashboard()


# ---------------------------------------------------------------------------
# Admin portal
# ---------------------------------------------------------------------------


def render_admin() -> None:
    st.title("Admin portal")
    st.caption("Institute-wide visibility for the Zero-Trust attendance deployment.")

    users_n = fetchone("SELECT COUNT(*) AS n FROM users")["n"]
    courses_n = fetchone("SELECT COUNT(*) AS n FROM courses")["n"]
    present_n = fetchone("SELECT COUNT(*) AS n FROM attendance_records WHERE status = 1")["n"]
    live_n = fetchone("SELECT COUNT(*) AS n FROM attendance_sessions WHERE is_active = 1")["n"]
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Users", users_n)
    m2.metric("Courses", courses_n)
    m3.metric("Live sessions", live_n)
    m4.metric("Present marks", present_n)

    tabs = st.tabs(["Users", "Courses", "Live sessions", "Attendance log"])
    with tabs[0]:
        st.dataframe(
            query_df("SELECT email, name, role, roll_number, fingerprint_hash FROM users ORDER BY role, email"),
            use_container_width=True,
            hide_index=True,
        )
    with tabs[1]:
        st.dataframe(
            query_df(
                """
                SELECT c.course_id, c.course_name, c.join_code, c.professor_email,
                       COUNT(e.student_email) AS enrolled
                FROM courses c
                LEFT JOIN enrollments e ON e.course_id = c.course_id
                GROUP BY c.course_id
                ORDER BY c.course_name
                """
            ),
            use_container_width=True,
            hide_index=True,
        )
    with tabs[2]:
        st.dataframe(
            query_df(
                """
                SELECT s.session_id, c.course_name, s.date, s.current_otp, s.otp_expires_at, s.is_active
                FROM attendance_sessions s
                JOIN courses c ON c.course_id = s.course_id
                WHERE s.is_active = 1
                """
            ),
            use_container_width=True,
            hide_index=True,
        )
    with tabs[3]:
        log = query_df(
            """
            SELECT ar.session_id, c.course_name, ar.student_email, u.roll_number,
                   ar.status, ar.marked_at
            FROM attendance_records ar
            JOIN attendance_sessions s ON s.session_id = ar.session_id
            JOIN courses c ON c.course_id = s.course_id
            JOIN users u ON u.email = ar.student_email
            ORDER BY ar.marked_at DESC
            """
        )
        st.dataframe(log, use_container_width=True, hide_index=True)
        if not log.empty:
            buffer = io.BytesIO()
            with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
                log.to_excel(writer, index=False, sheet_name="AllAttendance")
            st.download_button(
                "Export full attendance log (Excel)",
                data=buffer.getvalue(),
                file_name=f"iiitdwd_attendance_log_{today_iso()}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    init_db()
    init_session()
    if not st.session_state.authenticated:
        render_login()
        return
    sidebar_chrome()
    role = st.session_state.role
    if role == "admin":
        render_admin()
    elif role == "professor":
        render_professor()
    else:
        render_student()


main()
