# IIIT Dharwad Zero-Trust Student Attendance

Single-file Streamlit demo (`app.py`) with SQLite persistence. Campus emails, rolling classroom OTPs, mock fingerprint confirmation, and a tab-visibility anti-proxy guard.

## Run

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

SQLite creates `attendance.db` next to `app.py` on first launch.

## Demo login

Any `@iiitdwd.ac.in` address. Login OTP is always `1234`.

| Email | Portal |
| --- | --- |
| `admin@iiitdwd.ac.in` | Admin |
| `prof.cs@iiitdwd.ac.in` or `faculty.os@iiitdwd.ac.in` | Professor |
| `25bcs053@iiitdwd.ac.in` | Student (roll `25BCS053`) |

## Flow

1. Professor creates a course and shares the 6-character join code.
2. Student joins with the code and a fingerprint token (hashed at rest).
3. Professor initializes attendance: a 5-character OTP refreshes every 15 seconds.
4. Student sees a red banner, enters the projector OTP, re-verifies fingerprint.
5. Switching tabs on the mark-attendance page terminates the attempt (`visibilitychange`).
6. Professor reviews the roster, overrides present/absent, and exports Excel.
