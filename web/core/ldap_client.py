# app/core/ldap_client.py
import os
from typing import Tuple, List, Optional

from ldap3 import Server, Connection, ALL, SUBTREE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
from ldap3.utils.conv import escape_filter_chars
from ldap3.core.exceptions import LDAPExceptionError, LDAPBindError, LDAPInvalidFilterError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CLIENT_MODE = os.getenv("CLIENT_MODE", "openldap").lower()
BASE_DN = os.getenv("BASE_DN", "dc=techfusion,dc=corp")

LDAP_URI_OPENLDAP = os.getenv("LDAP_URI_OPENLDAP", os.getenv("LDAP_URI", "ldap://openldap:389"))
BIND_DN = os.getenv("BIND_DN", "cn=admin," + BASE_DN)
BIND_PW = os.getenv("BIND_PW", "admin")

# ---------------------------------------------------------------------------
# Connection & Helpers
# ---------------------------------------------------------------------------
def _conn(client_mode: Optional[str] = None) -> Connection:
    mode = (client_mode or CLIENT_MODE)
    uri = LDAP_URI_OPENLDAP
    user_dn = BIND_DN
    pw = BIND_PW

    # prefer explicit bind so we can handle strongerAuthRequired / TLS fallbacks
    use_ssl = uri.lower().startswith("ldaps://")
    server = Server(uri, get_info=ALL, use_ssl=use_ssl)
    conn = Connection(server, user=user_dn, password=pw, auto_bind=False)

    try:
        # first attempt: simple bind
        if conn.bind():
            return conn

        # if bind failed, try StartTLS (if not already using LDAPS)
        if not use_ssl:
            try:
                if conn.start_tls():
                    if conn.bind():
                        return conn
            except Exception:
                # ignore and try LDAPS fallback
                pass

        # LDAPS fallback: if URI uses ldap:// try ldaps://
        if uri.lower().startswith("ldap://"):
            try:
                ldaps_uri = uri.replace("ldap://", "ldaps://", 1)
                server2 = Server(ldaps_uri, get_info=ALL, use_ssl=True)
                conn2 = Connection(server2, user=user_dn, password=pw, auto_bind=False)
                if conn2.bind():
                    return conn2
            except Exception:
                pass

        # nothing worked — raise a clear bind error with server result
        desc = (conn.result or {}).get("description", "") or conn.result
        raise LDAPBindError(f"bind failed: {desc}")

    except LDAPBindError:
        raise
    except Exception as e:
        # rewrap other exceptions for clarity
        raise LDAPExceptionError(f"_conn error: {e}")

def _safe_val(v: str) -> str:
    return escape_filter_chars(v or "", encoding=None)

def _is_bare_star(s: str) -> bool:
    return (s or "").strip() == "*"

def _legacy_repair(raw_filter: str) -> str:
    """
    Emulate the tolerant 'legacy' behavior by returning only the first balanced
    LDAP expression and ignoring any trailing/unbalanced garbage. This mirrors
    how some older servers/drivers behaved, which is useful for demo.
    """
    if not raw_filter:
        return raw_filter
    s = raw_filter.strip()
    start = s.find("(")
    if start == -1:
        return s

    bal = 0
    end = None
    for i, ch in enumerate(s[start:], start=start):
        if ch == "(":
            bal += 1
        elif ch == ")":
            bal -= 1
            if bal == 0:
                end = i
                break

    if end is not None:
        return s[start:end + 1]
    # never balanced – close it up (so we at least return a valid expr)
    return s + (")" * max(bal, 0))

def _choose_value(value: str, safeness: str) -> str:
    """
    Decide whether to escape or keep raw depending on safeness:
      - escape-all => escape every value
      - off => return raw
      - no-star => return raw (but caller must check for bare '*')
    """
    if safeness == "escape-all":
        return _safe_val(value)
    return value or ""

def _attempt_user_bind(user_dn: str, password: str, client_mode: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """
    Try to bind as the provided user DN. Return (True, None) on success,
    otherwise (False, error_message). This mirrors the admin _conn approach:
    - try simple bind
    - try StartTLS then bind (if not using LDAPS)
    - try LDAPS fallback
    """
    if not user_dn:
        return False, "no_dn"

    mode = (client_mode or CLIENT_MODE)
    uri = LDAP_URI_OPENLDAP
    use_ssl = uri.lower().startswith("ldaps://")

    # primary server
    server = Server(uri, get_info=ALL, use_ssl=use_ssl)
    conn = Connection(server, user=user_dn, password=password, auto_bind=False)
    try:
        if conn.bind():
            conn.unbind()
            return True, None

        # try StartTLS then bind (if not already using LDAPS)
        if not use_ssl:
            try:
                if conn.start_tls():
                    if conn.bind():
                        conn.unbind()
                        return True, None
            except Exception:
                pass

        # LDAPS fallback
        if uri.lower().startswith("ldap://"):
            try:
                ldaps_uri = uri.replace("ldap://", "ldaps://", 1)
                server2 = Server(ldaps_uri, get_info=ALL, use_ssl=True)
                conn2 = Connection(server2, user=user_dn, password=password, auto_bind=False)
                if conn2.bind():
                    conn2.unbind()
                    return True, None
            except Exception:
                pass

        desc = (conn.result or {}).get("description") or conn.result
        return False, f"bind_failed:{desc}"
    except Exception as e:
        return False, f"bind_exception:{e}"
    finally:
        try:
            conn.unbind()
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Exercise 01: Login Bypass
# ---------------------------------------------------------------------------
def e01_auth_login(
    uid: str,
    pw: str,
    client_mode: Optional[str] = None,
    safeness: str = "off",
) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
    """
    Exercise 01: Login Bypass
    
    Returns: (ok, dn, filter_used, error_message)
    
    Vulnerability:
    Constructs an AND filter (&(uid=U)(userPassword=P)) where U and P are user inputs.
    Allows injection into the uid field to bypass password checks (e.g. using closing parenthesis).
    
    Safeness modes:
    - escape-all: Escapes input, performs search then bind (safe).
    - no-star: Blocks bare wildcards.
    - off: Vulnerable raw filter construction.
    """
    c = _conn(client_mode)
    filt = None
    try:
        effective_mode = (client_mode or CLIENT_MODE)

        # Safe mode: escape uid, simple lookup
        if safeness == "escape-all":
            filt = f"(uid={_safe_val(uid)})"
            try:
                ok = c.search(BASE_DN, filt, SUBTREE, attributes=[])
            except LDAPExceptionError as e:
                return False, None, filt, f"search_error:{e}"
            if not ok or len(c.entries) == 0:
                return False, None, filt, "no_matching_entry"
            dn = c.entries[0].entry_dn
            bound, bind_err = _attempt_user_bind(dn, pw, client_mode=client_mode)
            if not bound:
                return False, None, filt, f"bind_error:{bind_err}"
            return True, dn, filt, None

        # no-star: block bare wildcard values
        if safeness == "no-star":
            if _is_bare_star(uid) or _is_bare_star(pw):
                return False, None, "(blocked)", "input_rejected:bare_wildcard"

        U = _choose_value(uid, safeness)
        P = _choose_value(pw, safeness)
        base_filter = f"(&(uid={U})(userPassword={P}))"

        # Legacy tolerant repair
        if effective_mode == "openldap-legacy":
            filt = _legacy_repair(base_filter)
        else:
            filt = base_filter

        try:
            ok = c.search(BASE_DN, filt, SUBTREE, attributes=[])
        except LDAPExceptionError as e:
            return False, None, filt, f"search_error:{e}"

        if not ok:
            return False, None, filt, f"search_error:{c.result.get('description')}"
        if len(c.entries) == 0:
            return False, None, filt, None

        dn = c.entries[0].entry_dn
        return True, dn, filt, None

    except LDAPExceptionError as e:
        return False, None, filt, f"ldap_error:{e}"
    except Exception as e:
        return False, None, filt, f"error:{e}"
    finally:
        try:
            c.unbind()
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Exercise 02: File Browser
# ---------------------------------------------------------------------------
def list_departments(client_mode: Optional[str] = None) -> List[str]:
    """
    Helper for E02: Return department names by enumerating OUs directly under ou=Departments.
    """
    c = _conn(client_mode)
    try:
        base = f"ou=Departments,{BASE_DN}"
        flt = "(objectClass=organizationalUnit)"
        ok = c.search(base, flt, SUBTREE, attributes=["ou"])
        if not ok:
            return []
        names = []
        for e in c.entries:
            dn_lower = e.entry_dn.lower()
            parts = [p.strip() for p in dn_lower.split(",")]
            # only OUs whose immediate parent is ou=Departments (ou=<Dept>,ou=Departments,...)
            if len(parts) >= 2 and parts[1] == "ou=departments":
                ou_attr = e.entry_attributes_as_dict.get("ou")
                if isinstance(ou_attr, (list, tuple)) and ou_attr:
                    names.append(str(ou_attr[0]))
                elif ou_attr:
                    names.append(str(ou_attr))
        return sorted(set(x for x in names if x and x.lower() != "departments"))
    finally:
        c.unbind()

def e02_search_files(q: str = "", client_mode: str = "openldap", safeness: str = "off", verbosity: str = "quiet",
                 user_dn: Optional[str] = None, user_department: Optional[str] = None, department: Optional[str] = None):
    """
    Exercise 02: File Browser
    
    Returns: (filter_string, list_of_dicts, error_or_None)
    
    Vulnerability:
    Constructs a filter by concatenating clauses:
    (&(objectClass=fileObject)(department=<dept>)(classification=public)(cn=*<q>*))
    
    Allows injection into 'department' or 'q' to alter the filter logic (e.g. accessing confidential files).
    
    Safeness modes:
    - escape-all: Escapes inputs.
    - no-star: Blocks bare wildcards in 'q'.
    - off: Vulnerable concatenation.
    """
    q_raw = (q or "").strip()
    # department preference: explicit parameter -> user_department -> session-provided -> default "HR"
    dept_raw = (department or user_department or "").strip()
    if not dept_raw:
        dept_raw = "HR"

    # block bare-star for no-star mode (applies to q only)
    if safeness == "no-star" and _is_bare_star(q_raw):
        return "(blocked)", [], "input_rejected:bare_wildcard"

    # choose escaping
    def maybe_escape(x: str) -> str:
        if safeness == "escape-all":
            return _safe_val(x)
        return x or ""

    q_val = maybe_escape(q_raw)
    dept_val = maybe_escape(dept_raw)

    # Build ordered clauses: objectClass -> department -> classification -> cn (optional)
    clauses = []
    # department clause is mandatory
    clauses.append(f"(department={dept_val})")
    # classification fixed to public (as requested)
    clauses.append("(classification=public)")
    # cn clause only if q provided
    if q_val:
        clauses.append(f"(cn=*{q_val}*)")

    # final filter - objectClass first, then the ordered clauses
    flt = f"(&(objectClass=fileObject){''.join(clauses)})"

    # legacy repair if requested
    if (client_mode or CLIENT_MODE).startswith("openldap-legacy"):
        flt = _legacy_repair(flt)

    # perform LDAP search rooted at ou=Files,{BASE_DN}
    search_base = f"ou=Files,{BASE_DN}"
    c = None
    try:
        c = _conn(client_mode)
        try:
            ok = c.search(search_base, flt, SUBTREE, attributes=["cn", "filePath", "classification", "description", "owner", "department"])
        except LDAPExceptionError as e:
            return flt, [], f"search_error:{e}"
        if not ok:
            return flt, [], None

        results = []
        for e in c.entries:
            attrs = getattr(e, "entry_attributes_as_dict", {}) or {}
            def first(x):
                if isinstance(x, (list, tuple)) and len(x) > 0:
                    return str(x[0])
                return str(x or "")
            results.append({
                "cn": first(attrs.get("cn", "")),
                "filePath": first(attrs.get("filePath", "")),
                "classification": first(attrs.get("classification", "")),
                "description": first(attrs.get("description", "")),
                "owner": first(attrs.get("owner", "")),
                "department": first(attrs.get("department", "")),
            })
        return flt, results, None
    except LDAPExceptionError as e:
        return flt, [], f"ldap_error:{e}"
    except Exception as e:
        return flt, [], f"error:{e}"
    finally:
        try:
            if c:
                c.unbind()
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Exercise 03: Devices
# ---------------------------------------------------------------------------
def e03_search_devices(
    device_type: str = "printer",
    client_mode: Optional[str] = None,
    safeness: str = "off",
    username: Optional[str] = None
) -> Tuple[str, List, Optional[str]]:
    """
    Exercise 03: Device search with OR clause injection
    
    Returns: (filter_used, list_of_entries, error_message)
    
    Public devices (printers): No ownership check
    Personal devices (computers/phones): Ownership check required
    When username is provided, we attempt to resolve the user's full DN and
    use it in the owner clause; if resolution fails, we fall back to the raw username.
    
    Safeness modes:
    - escape-all: Escapes all special LDAP characters
    - no-star: Blocks bare wildcards (*)
    - off: No protection (vulnerable)
    """
    c = _conn(client_mode)
    filt = None
    
    try:
        effective_mode = (client_mode or CLIENT_MODE)
        raw_device_type = (device_type or "").strip()
        
        # Check safeness for bare wildcards
        if safeness == "no-star" and _is_bare_star(raw_device_type):
            return "(blocked)", [], "input_rejected:bare_wildcard"
        
        # Apply escaping based on safeness mode
        if safeness == "escape-all":
            device_type_val = _safe_val(raw_device_type)
            username_val = _safe_val(username) if username else None
        else:
            device_type_val = _choose_value(raw_device_type, safeness)
            username_val = _choose_value(username, safeness) if username else None

        # Try to resolve full DN of the owner (by uid) for stronger matching
        owner_dn_val = None
        if username:
            try:
                # Always escape for DN lookup to avoid filter injection during resolution
                user_lookup_filter = f"(uid={_safe_val(username)})"
                # search across the directory (users live under Departments/*/Users)
                if c.search(BASE_DN, user_lookup_filter, SUBTREE, attributes=[]):
                    if len(c.entries) > 0:
                        owner_dn_val = str(c.entries[0].entry_dn)
            except Exception:
                owner_dn_val = None

        # Build filter based on device type
        base_dn = "ou=Devices,dc=techfusion,dc=corp"
        
        # Determine device category and build appropriate filter
        if raw_device_type.startswith("printer"):
            # Public devices - no ownership check
            # Always includes scanners (often integrated with printers)
            filt = f"(|(deviceType={device_type_val})(deviceType=scanner))"
            
        elif raw_device_type.startswith("computer"):
            # Personal devices - requires ownership
            # Always includes virtual machines
            if username_val:
                owner_clause_val = _safe_val(owner_dn_val) if owner_dn_val else username_val
                filt = f"(&(|(deviceType={device_type_val})(deviceType=virtual-machine))(owner={owner_clause_val}))"
            else:
                filt = f"(|(deviceType={device_type_val})(deviceType=virtual-machine))"
                
        elif raw_device_type.startswith("mobile-phone"):
            # Personal devices - requires ownership
            # Always includes landlines
            if username_val:
                owner_clause_val = _safe_val(owner_dn_val) if owner_dn_val else username_val
                filt = f"(&(|(deviceType={device_type_val})(deviceType=landline))(owner={owner_clause_val}))"
            else:
                filt = f"(|(deviceType={device_type_val})(deviceType=landline))"
        else:
            # Generic search for other device types
            filt = f"(deviceType={device_type_val})"
        
        # Apply legacy repair if needed
        if effective_mode == "openldap-legacy":
            filt = _legacy_repair(filt)
        
        # Execute search
        try:
            ok = c.search(base_dn, filt, SUBTREE, attributes=[ALL_ATTRIBUTES])
        except LDAPExceptionError as e:
            return filt, [], f"search_error:{e}"
        
        if not ok:
            return filt, [], f"search_error:{c.result.get('description')}"
        
        return filt, list(c.entries) if ok else [], None
        
    except LDAPExceptionError as e:
        return filt or "(error)", [], f"ldap_error:{e}"
    except Exception as e:
        return filt or "(error)", [], f"error:{e}"
    finally:
        try:
            c.unbind()
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Exercise 04: Blind AND
# ---------------------------------------------------------------------------
def list_groups(client_mode: Optional[str] = None, safeness: str = "escape-all") -> List[str]:
    """
    Helper for E04: Return list of group common names (cn) under ou=Groups.
    """
    c = _conn(client_mode)
    try:
        group_base = f"ou=Groups,{BASE_DN}"
        flt = "(objectClass=groupOfNames)"
        ok = c.search(group_base, flt, SUBTREE, attributes=["cn"])
        if not ok:
            return []
        names = []
        for e in c.entries:
            try:
                cn_attr = e.entry_attributes_as_dict.get("cn")
                if isinstance(cn_attr, (list, tuple)) and cn_attr:
                    names.append(str(cn_attr[0]))
                elif cn_attr:
                    names.append(str(cn_attr))
            except Exception:
                continue
        return sorted(set(names))
    finally:
        c.unbind()

def e04_group_members_lab(
    group_cn: str,
    department: Optional[str] = None,
    client_mode: Optional[str] = None,
    safeness: str = "escape-all"
) -> Tuple[str, List, Optional[str], Optional[str]]:
    """
    Exercise 04: Blind Probe AND
    
    Returns: (user_filter_used, list_of_user_entries, error, group_dn)
    
    Vulnerability:
    Finds members of a group. Allows injection into the 'department' parameter.
    The filter is constructed as:
    (& (objectClass=inetOrgPerson) (labMemberOf=<group_dn>) (departmentNumber=<dept>) )
    
    Safeness modes:
    - escape-all: Escapes department input.
    - no-star: Blocks bare wildcards.
    - off: Vulnerable raw filter construction.
    """
    raw = (group_cn or "").strip()
    if not raw:
        return "(objectClass=inetOrgPerson)", [], "no_group_supplied", None

    # escape CN for group lookup
    cn_val = _safe_val(raw) if safeness == "escape-all" else raw
    group_base = f"ou=Groups,{BASE_DN}"
    group_filter = f"(&(objectClass=groupOfNames)(cn={cn_val}))"

    c = _conn(client_mode)
    try:
        ok = c.search(group_base, group_filter, SUBTREE, attributes=[])
        if not ok or len(c.entries) == 0:
            return group_filter, [], "group_not_found", None

        group_dn = c.entries[0].entry_dn

        # departmentNumber clause (user-controlled; apply safeness)
        dept_raw = (department or "").strip()
        if safeness == "no-star" and _is_bare_star(dept_raw):
            return "(blocked)", [], "input_rejected:bare_wildcard", group_dn
        if safeness == "escape-all":
            dept_val = _safe_val(dept_raw)
        else:
            dept_val = dept_raw  # vuln/off or raw/no-star after bare-star check

        # Build user filter
        clauses = ["(objectClass=inetOrgPerson)", f"(labMemberOf={_safe_val(group_dn)})"]
        if dept_val:
            clauses.append(f"(departmentNumber={dept_val})")
        user_filter = f"(&{''.join(clauses)})"

        user_base = f"ou=Departments,{BASE_DN}"
        ok2 = c.search(user_base, user_filter, SUBTREE,
                        attributes=["cn", "mail", "telephoneNumber", "uid", "labMemberOf", "departmentNumber"])
        if not ok2:
            return user_filter, [], c.result.get("description"), group_dn
        return user_filter, list(c.entries), None, group_dn
    except LDAPExceptionError as e:
        return "(error)", [], f"ldap_error:{e}", None
    except Exception as e:
        return "(error)", [], f"error:{e}", None
    finally:
        c.unbind()

# ---------------------------------------------------------------------------
# Exercise 05: Blind OR
# ---------------------------------------------------------------------------
def e05_blind_or_search(
    q: str,
    match: str = "contains",
    client_mode: Optional[str] = None,
    safeness: str = "off"
) -> Tuple[str, List, Optional[str]]:
    """
    Exercise 05: Blind Probe OR
    
    Returns: (filter_used, entries, error)
    
    Vulnerability:
    Builds an OR filter: (|(uid=<pattern>)(mail=<pattern>))
    Allows injection into 'q' to break the OR logic and infer data blindly.
    
    Safeness modes:
    - escape-all: Escapes input.
    - no-star: Blocks bare wildcards.
    - off: Vulnerable raw filter construction.
    """
    raw = (q or "").strip()
    if safeness == "no-star" and _is_bare_star(raw):
        return "(blocked)", [], "input_rejected:bare_wildcard"
    val = _safe_val(raw) if safeness == "escape-all" else raw

    m = (match or "contains").lower()
    if m not in ("contains", "starts", "ends", "exact"):
        m = "contains"

    if not val:
        # empty query still allowed; pattern = * for all styles except exact
        pattern = "*" if m != "exact" else ""
    else:
        if m == "contains":
            pattern = f"*{val}*"
        elif m == "starts":
            pattern = f"{val}*"
        elif m == "ends":
            pattern = f"*{val}"
        else:  # exact
            pattern = val

    filt = f"(|(uid={pattern})(mail={pattern}))"
    c = _conn(client_mode)
    try:
        try:
            ok = c.search(BASE_DN, filt, SUBTREE, attributes=["uid", "mail"])
        except LDAPInvalidFilterError as e:
            return filt, [], f"invalid_filter:{e}"
        except LDAPExceptionError as e:
            return filt, [], f"ldap_error:{e}"
        return filt, (list(c.entries) if ok else []), None
    except Exception as e:
        return filt, [], f"error:{e}"
    finally:
        c.unbind()
