#!/usr/bin/env python3
"""
CG Email Audit — Standalone Gmail IMAP Export
══════════════════════════════════════════════════════════════════════════════
No Google Cloud. No OAuth. No pip installs. Pure Python standard library.

Requires: Python 3.6+  (nothing else)

Before running — generate a Gmail App Password (one-time, 2 min):
  1. Go to myaccount.google.com → Security
  2. Enable 2-Step Verification (if not already on)
  3. Search "App Passwords" → Select app: Mail, Device: Mac
  4. Google gives you a 16-character password — use that when prompted

Run:
  python fetch_emails.py

Output:
  cg_email_audit.csv
══════════════════════════════════════════════════════════════════════════════
"""

import imaplib
import email
import email.header
import email.utils
import csv
import getpass
import re
import html as html_lib
import time
import sys
from datetime import datetime, timezone

# ── Configuration ─────────────────────────────────────────────────────────────
IMAP_HOST   = 'imap.gmail.com'
IMAP_PORT   = 993
ACCOUNT     = 'kumarabilash6@gmail.com'
TARGET      = 'casagrandtudorowners@gmail.com'
DATE_SINCE  = '01-May-2024'
DATE_BEFORE = '01-Jul-2026'
OUTPUT_CSV  = 'cg_email_audit.csv'
# ─────────────────────────────────────────────────────────────────────────────

CSV_FIELDS = [
    'Thread ID',
    'Thread Position',
    'Message ID',
    'Date',
    'Direction',
    'From',
    'To',
    'CC',
    'Subject',
    'Body',
    'Has Attachment',
    'Attachment Names',
]


# ── Header decoding ───────────────────────────────────────────────────────────

def decode_header_value(raw):
    """Decode RFC2047-encoded header value (handles =?utf-8?...?= etc.)."""
    if not raw:
        return ''
    parts = email.header.decode_header(raw)
    out = []
    for chunk, charset in parts:
        if isinstance(chunk, bytes):
            out.append(chunk.decode(charset or 'utf-8', errors='replace'))
        else:
            out.append(chunk)
    return ' '.join(out).strip()


def get_addresses(header_val):
    """Return a clean comma-separated address string from a To/CC/From header."""
    if not header_val:
        return ''
    decoded = decode_header_value(header_val)
    return decoded


# ── Body extraction ───────────────────────────────────────────────────────────

def strip_html(raw):
    """Convert HTML to plain text — strips tags, decodes entities."""
    clean = re.sub(r'<style[^>]*>.*?</style>', ' ', raw, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r'<script[^>]*>.*?</script>', ' ', clean, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r'<br\s*/?>', '\n', clean, flags=re.IGNORECASE)
    clean = re.sub(r'<p[^>]*>', '\n', clean, flags=re.IGNORECASE)
    clean = re.sub(r'<[^>]+>', ' ', clean)
    clean = html_lib.unescape(clean)
    clean = re.sub(r'[ \t]+', ' ', clean)
    clean = re.sub(r'\n{3,}', '\n\n', clean)
    return clean.strip()


def extract_body(msg):
    """
    Walk the MIME tree and return best available plain-text body.
    Priority: text/plain > text/html (stripped).
    """
    plain = ''
    html_body = ''

    if msg.is_multipart():
        for part in msg.walk():
            ct   = part.get_content_type()
            disp = str(part.get('Content-Disposition', ''))
            if 'attachment' in disp:
                continue
            charset = part.get_content_charset() or 'utf-8'
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                text = payload.decode(charset, errors='replace')
                if ct == 'text/plain' and not plain:
                    plain = text
                elif ct == 'text/html' and not html_body:
                    html_body = strip_html(text)
            except Exception:
                continue
    else:
        charset = msg.get_content_charset() or 'utf-8'
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                text = payload.decode(charset, errors='replace')
                if msg.get_content_type() == 'text/html':
                    plain = strip_html(text)
                else:
                    plain = text
        except Exception:
            pass

    return (plain or html_body).strip()


# ── Attachment detection ──────────────────────────────────────────────────────

def extract_attachments(msg):
    """Return list of attachment filenames found in the message."""
    names = []
    for part in msg.walk():
        disp = str(part.get('Content-Disposition', ''))
        fname = part.get_filename()
        if fname:
            names.append(decode_header_value(fname))
        elif 'attachment' in disp:
            ct = part.get_content_type()
            if ct not in ('text/plain', 'text/html'):
                names.append(f'[unnamed: {ct}]')
    return names


# ── Date parsing ──────────────────────────────────────────────────────────────

def parse_date(date_str):
    if not date_str:
        return ''
    try:
        dt = email.utils.parsedate_to_datetime(date_str)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return date_str.strip()


def date_sort_key(date_str):
    """Return a datetime for sorting — falls back to datetime.min."""
    try:
        dt = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S UTC')
        return dt
    except Exception:
        return datetime.min


# ── Direction classification ──────────────────────────────────────────────────

def determine_direction(from_addr, to_addr, cc_addr=''):
    target = TARGET.lower()
    if target in from_addr.lower():
        return 'INBOUND (From Community Account)'
    if target in to_addr.lower() or target in cc_addr.lower():
        return 'OUTBOUND (To Community Account)'
    return 'RELATED (Thread Context)'


# ── Thread reconstruction ─────────────────────────────────────────────────────

def build_thread_map(messages):
    """
    Reconstruct email threads using standard Message-ID / References / In-Reply-To headers.

    Returns a dict:  message_id → thread_root_id

    Logic:
      - If a message has References, the FIRST entry is the thread root.
      - If no References but has In-Reply-To, that's the parent (we resolve to root).
      - If neither, the message is its own root.
    """
    mid_to_root = {}   # message_id → thread_root_id
    mid_to_refs = {}   # message_id → (references list, in-reply-to)

    for msg_data in messages:
        mid   = msg_data['raw_message_id']
        refs  = msg_data['references']
        irt   = msg_data['in_reply_to']
        mid_to_refs[mid] = (refs, irt)

    def find_root(mid, visited=None):
        if visited is None:
            visited = set()
        if mid in visited:
            return mid   # cycle guard
        visited.add(mid)
        if mid in mid_to_root:
            return mid_to_root[mid]
        refs, irt = mid_to_refs.get(mid, ([], ''))
        if refs:
            root = find_root(refs[0], visited)
            mid_to_root[mid] = root
            return root
        if irt and irt in mid_to_refs:
            root = find_root(irt, visited)
            mid_to_root[mid] = root
            return root
        mid_to_root[mid] = mid
        return mid

    for msg_data in messages:
        find_root(msg_data['raw_message_id'])

    return mid_to_root


# ── IMAP fetch logic ──────────────────────────────────────────────────────────

def search_uids(conn):
    """Search [Gmail]/All Mail for emails to/from TARGET in the date range."""
    # Select All Mail to capture both sent and received
    status, _ = conn.select('"[Gmail]/All Mail"', readonly=True)
    if status != 'OK':
        print('[ERROR] Could not select [Gmail]/All Mail. Trying INBOX...')
        conn.select('INBOX', readonly=True)

    search_criteria = (
        f'(OR FROM "{TARGET}" TO "{TARGET}") '
        f'SINCE "{DATE_SINCE}" BEFORE "{DATE_BEFORE}"'
    )
    print(f'\nSearch: {search_criteria}')

    status, data = conn.uid('search', None, search_criteria)
    if status != 'OK' or not data or not data[0]:
        return []

    uids = data[0].split()
    print(f'Found {len(uids)} matching email(s).\n')
    return uids


def fetch_message(conn, uid):
    """Fetch a single message by UID. Returns raw bytes or None."""
    try:
        status, data = conn.uid('fetch', uid, '(RFC822)')
        if status != 'OK' or not data or data[0] is None:
            return None
        for part in data:
            if isinstance(part, tuple):
                return part[1]
        return None
    except Exception as e:
        print(f'  [WARN] Could not fetch UID {uid.decode()}: {e}')
        return None


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print('═' * 65)
    print('  CG Email Audit — Standalone Gmail IMAP Export')
    print(f'  Account  : {ACCOUNT}')
    print(f'  Target   : {TARGET}')
    print(f'  Range    : {DATE_SINCE} → {DATE_BEFORE}')
    print(f'  Output   : {OUTPUT_CSV}')
    print('═' * 65)
    print()
    print('Enter your Gmail App Password for kumarabilash6@gmail.com')
    print('(Generate at: myaccount.google.com → Security → App Passwords)')
    print()

    app_password = getpass.getpass('App Password: ').replace(' ', '')

    # ── Connect & authenticate ────────────────────────────────────────────────
    print('\nConnecting to imap.gmail.com...')
    try:
        conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
        conn.login(ACCOUNT, app_password)
        print('✔ Authenticated successfully.\n')
    except imaplib.IMAP4.error as e:
        print(f'\n[ERROR] Login failed: {e}')
        print('Make sure you are using an App Password, not your regular Gmail password.')
        sys.exit(1)

    # ── Search ────────────────────────────────────────────────────────────────
    uids = search_uids(conn)
    if not uids:
        print('No emails found for the given criteria.')
        conn.logout()
        return

    # ── Fetch & parse all messages ────────────────────────────────────────────
    raw_messages = []
    total = len(uids)

    for i, uid in enumerate(uids, start=1):
        uid_str = uid.decode()
        print(f'  Fetching [{i:>4}/{total}] UID {uid_str}', end='\r', flush=True)

        raw = fetch_message(conn, uid)
        if not raw:
            continue

        try:
            msg = email.message_from_bytes(raw)
        except Exception as e:
            print(f'\n  [WARN] Could not parse UID {uid_str}: {e}')
            continue

        # Standard headers
        date_str    = parse_date(msg.get('Date', ''))
        subject     = decode_header_value(msg.get('Subject', '(No Subject)'))
        from_addr   = get_addresses(msg.get('From', ''))
        to_addr     = get_addresses(msg.get('To', ''))
        cc_addr     = get_addresses(msg.get('Cc', ''))
        msg_id      = msg.get('Message-ID', f'uid-{uid_str}').strip()
        in_reply_to = msg.get('In-Reply-To', '').strip()
        references  = [r.strip() for r in msg.get('References', '').split() if r.strip()]

        body        = extract_body(msg)
        attachments = extract_attachments(msg)
        direction   = determine_direction(from_addr, to_addr, cc_addr)

        raw_messages.append({
            'uid'            : uid_str,
            'raw_message_id' : msg_id,
            'in_reply_to'    : in_reply_to,
            'references'     : references,
            'date'           : date_str,
            'subject'        : subject,
            'from'           : from_addr,
            'to'             : to_addr,
            'cc'             : cc_addr,
            'body'           : body,
            'attachments'    : attachments,
            'direction'      : direction,
        })

        time.sleep(0.03)   # gentle rate limit

    conn.logout()
    print(f'\n\n✔ Fetched {len(raw_messages)} emails. Building threads...\n')

    # ── Thread reconstruction ─────────────────────────────────────────────────
    mid_to_root = build_thread_map(raw_messages)

    # Assign a short readable Thread ID (1, 2, 3...) instead of raw Message-ID
    unique_roots   = []
    seen_roots     = {}
    for m in raw_messages:
        root = mid_to_root.get(m['raw_message_id'], m['raw_message_id'])
        if root not in seen_roots:
            seen_roots[root] = len(seen_roots) + 1
            unique_roots.append(root)

    # Group messages by thread root, sort within each thread by date
    threads = {}
    for m in raw_messages:
        root = mid_to_root.get(m['raw_message_id'], m['raw_message_id'])
        threads.setdefault(root, []).append(m)

    for root in threads:
        threads[root].sort(key=lambda x: date_sort_key(x['date']))

    # ── Build CSV rows ────────────────────────────────────────────────────────
    rows = []
    for root in unique_roots:
        thread_num = seen_roots[root]
        thread_id  = f'THREAD-{thread_num:04d}'
        msgs       = threads[root]

        for pos, m in enumerate(msgs, start=1):
            rows.append({
                'Thread ID'       : thread_id,
                'Thread Position' : pos,
                'Message ID'      : m['raw_message_id'],
                'Date'            : m['date'],
                'Direction'       : m['direction'],
                'From'            : m['from'],
                'To'              : m['to'],
                'CC'              : m['cc'],
                'Subject'         : m['subject'],
                'Body'            : m['body'],
                'Has Attachment'  : 'Yes' if m['attachments'] else 'No',
                'Attachment Names': ' | '.join(m['attachments']),
            })

    # ── Write CSV ─────────────────────────────────────────────────────────────
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    # ── Summary ───────────────────────────────────────────────────────────────
    inbound  = sum(1 for r in rows if 'INBOUND'  in r['Direction'])
    outbound = sum(1 for r in rows if 'OUTBOUND' in r['Direction'])
    related  = sum(1 for r in rows if 'RELATED'  in r['Direction'])
    with_att = sum(1 for r in rows if r['Has Attachment'] == 'Yes')

    print('═' * 65)
    print(f'  ✔ Saved → {OUTPUT_CSV}')
    print('─' * 65)
    print(f'  Threads             : {len(unique_roots)}')
    print(f'  Total emails        : {len(rows)}')
    print(f'  Inbound             : {inbound}')
    print(f'  Outbound            : {outbound}')
    print(f'  Related (thread ctx): {related}')
    print(f'  With attachments    : {with_att}')
    print('═' * 65)


if __name__ == '__main__':
    main()
