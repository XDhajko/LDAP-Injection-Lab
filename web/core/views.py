import base64
import os

from django.core.paginator import Paginator
from django.shortcuts import render, redirect
from django.http import JsonResponse, FileResponse, Http404
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from pathlib import Path
from django.urls import reverse
from django.conf import settings
from . import ldap_client
# Remove AD-specific imports/usages (none needed now)
from ldap3 import BASE, ALL_ATTRIBUTES  # <-- existing import
from ldap3.utils.conv import escape_filter_chars  # <-- added import

BASE_FILES_DIR = Path(settings.BASE_DIR) / "project_files"

# Defaults (env overrides allowed)
CLIENT_MODES = ["openldap-legacy", "openldap"]
SAFE_LEVELS = ["off", "no-star", "escape-all"]
VERBOSITY_LEVELS = ["quiet", "verbose"]

# session defaults
CLIENT_MODE_DEFAULT = globals().get("CLIENT_MODE_DEFAULT", "openldap")
SAFENESS_DEFAULT = globals().get("SAFENESS_DEFAULT", "off")
VERBOSITY_DEFAULT = globals().get("VERBOSITY_DEFAULT", "verbose")

# ---- helpers ----
def _client_mode(request):
    return request.session.get("client_mode", CLIENT_MODE_DEFAULT)

def _safeness(request):
    return request.session.get("safeness", SAFENESS_DEFAULT)

def _verbosity(request):
    return request.session.get("verbosity", VERBOSITY_DEFAULT)

def _badge_for_client_mode(cm: str) -> str:
    return "bg-success" if cm == "openldap" else ("bg-warning" if cm == "openldap-legacy" else "bg-info")

def _badge_for_safeness(s: str) -> str:
    return {"off": "bg-danger", "no-star": "bg-warning text-dark", "escape-all": "bg-success"}.get(s, "bg-secondary")

def _badge_for_verbosity(v: str) -> str:
    return "bg-primary" if v == "verbose" else "bg-secondary"

def _base_ctx(request, extra=None, *, show_mode_difficulty=True):
    client_mode = _client_mode(request)
    safeness = _safeness(request)
    verbosity = _verbosity(request)

    ctx = {
        "client_mode": client_mode,
        "safeness": safeness,
        "verbosity": verbosity,
        "client_mode_badge": _badge_for_client_mode(client_mode),
        "safeness_badge": _badge_for_safeness(safeness),
        "verbosity_badge": _badge_for_verbosity(verbosity),
        "show_mode_difficulty": bool(show_mode_difficulty),
        "BASE_DN": ldap_client.BASE_DN,
    }
    if extra:
        ctx.update(extra)
    return ctx

# ---- settings ----
@require_http_methods(["GET"])
def settings_ui(request):
    ctx = {
        "active": None,
        "client_modes": CLIENT_MODES,
        "safe_levels": SAFE_LEVELS,
        "verbosity_levels": VERBOSITY_LEVELS,
    }
    return render(request, "settings.html", _base_ctx(request, ctx))


@require_http_methods(["POST"])
def update_settings(request):
    cm = (request.POST.get("client_mode") or CLIENT_MODE_DEFAULT).lower()
    sf = (request.POST.get("safeness") or SAFENESS_DEFAULT).lower()
    vb = (request.POST.get("verbosity") or VERBOSITY_DEFAULT).lower()

    request.session["client_mode"] = cm if cm in CLIENT_MODES else CLIENT_MODE_DEFAULT
    request.session["safeness"] = sf if sf in SAFE_LEVELS else SAFENESS_DEFAULT
    request.session["verbosity"] = vb if vb in VERBOSITY_LEVELS else VERBOSITY_DEFAULT

    return redirect(request.META.get("HTTP_REFERER") or "index")

# ---- index ----
def index(request):
    return render(request, "index.html", _base_ctx(request))

# Add near the top of views.py (after imports)
def _normalize_attr_value(v):
    """
    Convert ldap3 attribute values into JSON-serializable types:
     - bytes -> decoded string (utf-8, replace errors)
     - list/tuple -> map normalize over members
     - else -> return as-is (str/int/etc)
    """
    if isinstance(v, (bytes, bytearray)):
        try:
            return v.decode("utf-8", errors="replace")
        except Exception:
            return str(v)
    if isinstance(v, (list, tuple)):
        return [_normalize_attr_value(x) for x in v]
    # ldap3 sometimes uses special types; stringify anything else safely
    return v

# Replace helpers for serializing entries (use _verbosity for redaction)
def _entry_to_serializable(entry, hide_password_if_needed=True, verbosity="quiet"):
    d = {}
    for k, v in entry.entry_attributes_as_dict.items():
        if k == "userPassword" and verbosity != "verbose" and hide_password_if_needed:
            d[k] = ["<hidden>"]
            continue
        d[k] = _normalize_attr_value(v)
    return {"dn": entry.entry_dn, "attrs": d}

# ---------------- E01: LOGIN ----------------
@require_http_methods(["GET", "POST"])
def e01_login(request):
    client_mode = _client_mode(request)
    safeness = _safeness(request)
    verbosity = _verbosity(request)

    # pull & clear last filter so it shows after a redirect on success
    last_filter = request.session.pop("last_filter_used", None)

    # base context
    ctx = {
        "active": "e01",
        "filter_used": last_filter,
        "error": None,
        "ok": False,
        "message": None,
        # ensure DN displayed even if only user_dn stored
        "logged_in_uid": request.session.get("uid"),
        "logged_in_dn": request.session.get("dn") or request.session.get("user_dn"),
    }

    # when logged in on this page, show only the Verbosity chip in header
    show_pills = not bool(ctx["logged_in_uid"])

    if request.method == "POST":
        if request.POST.get("action") == "logout":
            for k in ("uid", "dn"):
                request.session.pop(k, None)
            return redirect("e01_login")

        uid = request.POST.get("username", "").strip()
        pwd = request.POST.get("password", "").strip()
        ok, dn, flt, err = ldap_client.e01_auth_login(uid, pwd, client_mode=client_mode, safeness=safeness)
        ctx.update({"ok": ok, "filter_used": flt, "error": err})

        if ok:
            request.session['user_dn'] = dn
            request.session['dn'] = dn  # ensure DN available for display
            request.session['department'] = _extract_department_from_dn(dn)
            # best-effort uid extraction from DN
            try:
                request.session["uid"] = next(kv.split("=")[1] for kv in dn.split(",") if kv.startswith("uid="))
            except Exception:
                request.session["uid"] = uid
            request.session["last_filter_used"] = flt
            return redirect("e01_login")
        else:
            ctx["message"] = "Authentication failed"

    # nice message when logged in
    if ctx["logged_in_uid"]:
        ctx["message"] = None  # no red banner
    return render(request, "e01_login.html", _base_ctx(request, ctx, show_mode_difficulty=show_pills))


# ---------------- E02: FILE BROWSER ----------------
# ensure FILE_ROOT is project-local by default
FILE_ROOT = Path(os.getenv("FILE_ROOT") or Path(settings.BASE_DIR) / "project_files").resolve()

# keep CATEGORY_ORDER if present, but classification is per-entry (Public/private/confidential)
CATEGORY_ORDER = ["Public", "private", "confidential"]

# departments for the dropdown (simple static list; adjust as needed)
DEPARTMENTS = ["", "Finance", "HR", "Engineering", "IT", "Sales", "Legal"]  # fallback only

def _extract_uid_from_dn(dn: str) -> str:
    # e.g. "uid=jpeterson,ou=Users,ou=Finance,ou=Departments,dc=techfusion,dc=corp"
    for part in dn.split(','):
        if part.strip().lower().startswith('uid='):
            return part.split('=', 1)[1]
    return ''

def _extract_department_from_dn(dn: str) -> str:
    # look for the first ou after Users or the ou that looks like a department
    for part in dn.split(','):
        p = part.strip()
        if p.lower().startswith('ou=') and 'users' not in p.lower() and 'departments' not in p.lower():
            return p.split('=', 1)[1]
    # fallback: try any ou that is not Users/Departments
    for part in dn.split(','):
        p = part.strip()
        if p.lower().startswith('ou='):
            val = p.split('=', 1)[1]
            if val.lower() not in ('users', 'departments', 'files'):
                return val
    return ''

def _file_department_from_path(path: str) -> str:
    # path examples: /srv/finance/quarterly_report.pdf -> Finance
    try:
        parts = Path(path).parts
        # find the component after '/srv' or first non-empty. pick the next component.
        if 'srv' in parts:
            idx = parts.index('srv')
            if idx + 1 < len(parts):
                return parts[idx + 1].title()
        # fallback to using first component
        for p in parts:
            if p and p not in ('/', '\\'):
                return p.title()
    except Exception:
        pass
    return ''


def e02_file_browser(request):
    client_mode = _client_mode(request)
    safeness = _safeness(request)
    verbosity = _verbosity(request)

    # existing session pulls
    last_filter = request.session.pop("last_filter_used", None)
    user_dn = request.session.get("user_dn") or request.session.get("dn")
    user_dept = request.session.get("department", "")

    ctx = {
        "active": "e02",
        "filter_used": last_filter,
        "error": None,
        "ok": False,
        "message": None,
        "logged_in_uid": request.session.get("uid"),
        "logged_in_dn": request.session.get("dn"),
    }

    q = (request.GET.get('q') or '').strip()

    # None => param key wasn't in the URL at all
    dept_from_query = request.GET.get('dept', None)

    # default department used by your current logic
    default_dept = (user_dept or "HR").strip() or "HR"

    #  if 'dept' is missing, redirect with it added
    if dept_from_query is None:
        params = request.GET.copy()  # keep q, page, etc.
        params['dept'] = default_dept
        return redirect(f"{request.path}?{params.urlencode()}")

    # continue with your existing fallback (handles blank value)
    dept = (dept_from_query or default_dept)

    # q from querystring drives the LDAP search
    q = request.GET.get('q', '').strip()

    # call ldap search_files which now enforces department + classification=public + optional cn filter
    try:
        flt, files, err = ldap_client.e02_search_files(q=q, client_mode=client_mode, safeness=safeness, verbosity=verbosity,
                                                   user_dn=user_dn, user_department=dept, department=dept)
    except Exception as e:
        flt, files, err = "(local_error)", [], f"error:{e}"

    # expose filter used in header (if verbosity == verbose it will be visible)
    ctx["filter_used"] = flt
    ctx["error"] = err

    # Map returned file dicts into the shape the template expects
    mapped = []
    for entry in files:
        cn = entry.get("cn") or ""
        file_path = entry.get("filePath") or ""
        classification = (entry.get("classification") or "public").lower()
        description = entry.get("description") or ""
        owner_dn = entry.get("owner") or ""
        # derive owner uid and department for display
        owner_uid = _extract_uid_from_dn(owner_dn)
        file_dept = entry.get("department") or _extract_department_from_dn(owner_dn) or _file_department_from_path(file_path) or ""
        filename = cn
        candidate_path = BASE_FILES_DIR / (file_dept.title() or "") / filename
        mapped.append({
            "cn": cn,
            "classification": classification,
            "description": description,
            "owner_uid": owner_uid,
            "file_dept": file_dept.title() if file_dept else "",
            "local_path": str(candidate_path),
            "filename": filename,
            "download_exists": candidate_path.exists(),  # new flag
            "download_rel": f"{file_dept.title()}/{filename}" if file_dept else filename,  # relative path for link
        })

    # Sort/group by classification priority (confidential first)
    priority = {"confidential": 0, "private": 1, "public": 2}
    mapped.sort(key=lambda x: (priority.get(x['classification'], 3), x['filename'].lower()))

    # Pagination
    paginator = Paginator(mapped, 10)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    # Dynamic departments from LDAP (prepend empty for '— Department —')
    try:
        dynamic_departments = [""] + ldap_client.list_departments(client_mode=client_mode)
    except Exception:
        dynamic_departments = DEPARTMENTS  # fallback if LDAP enumeration fails

    # final context via _base_ctx so header pills render correctly
    page_ctx = {
        "needs_login": False,
        "page_obj": page_obj,
        "q": q,
        # keep filter_used & error present in ctx for base.html verbose block
        "filter_used": flt,
        "error": err,
        "departments": dynamic_departments,  # changed to dynamic list
        "dept": dept,
    }
    ctx_return = render(request, "e02_file_browser.html", _base_ctx(request, page_ctx | {"active": "e02"}))
    return ctx_return

def e02_download(request):
    # download a file by path token limited to BASE_FILES_DIR subtree
    rel_path = request.GET.get('path', '')
    if not rel_path:
        raise Http404()
    requested = Path(rel_path)
    if not requested.is_absolute():
        requested = BASE_FILES_DIR / requested  # force inside project_files
    try:
        requested_absolute = requested.resolve()
    except Exception:
        requested_absolute = requested.absolute()
    base_resolved = BASE_FILES_DIR.resolve()
    if not str(requested_absolute).startswith(str(base_resolved)):
        raise Http404()
    if not requested_absolute.exists() or not requested_absolute.is_file():
        raise Http404()
    return FileResponse(open(requested_absolute, "rb"), as_attachment=True, filename=requested_absolute.name)


# ---------------- E03: DEVICES (Printers) ----------------

# Helper: map deviceType to image filename "static/img/<type>.png"
def _device_image_name(dtype: str) -> str:
    key = (dtype or "device").lower().strip()
    key = key.replace(" ", "-").replace("_", "-").replace("/", "-")
    return f"{key}.png"

def e03_devices(request):
    """Exercise 04: Device search with OR clause injection"""
    device_type = request.GET.get('device_type', 'printer')
    client_mode = _client_mode(request)
    safeness = _safeness(request)
    verbosity = _verbosity(request)
    
    # Get logged-in user from session (from E01)
    username = request.session.get('uid')
    
    # Check if authentication is needed for personal devices
    requires_auth = device_type.startswith('computer') or device_type.startswith('mobile-phone')
    
    if requires_auth and not username:
        ctx = {
            'active': 'e03',
            'error': 'Authentication required. Please complete Exercise 01 first.',
            'device_type': device_type,
            'hint': 'Use credentials: jdoe / password123',
            'devices': [],
            'filter_used': None,
        }
        return render(request, 'e03_devices.html', _base_ctx(request, ctx))
    
    # Execute LDAP search
    flt, entries, err = ldap_client.e03_search_devices(
        device_type=device_type,
        client_mode=client_mode,
        safeness=safeness,
        username=username
    )
    
    # Process results for display
    devices = []
    for entry in entries:
        attrs = entry.entry_attributes_as_dict
        dtype = _normalize_attr_value(attrs.get('deviceType', ['unknown']))[0] if attrs.get('deviceType') else 'unknown'
        device_info = {
            'dn': entry.entry_dn,
            'name': _normalize_attr_value(attrs.get('cn', ['Unknown']))[0] if attrs.get('cn') else 'Unknown',
            'type': dtype,
            'owner': _normalize_attr_value(attrs.get('owner', ['Public']))[0] if attrs.get('owner') else 'Public',
            'location': _normalize_attr_value(attrs.get('location', ['N/A']))[0] if attrs.get('location') else 'N/A',
            'ipAddress': _normalize_attr_value(attrs.get('ipAddress', ['N/A']))[0] if attrs.get('ipAddress') else 'N/A',
            'model': _normalize_attr_value(attrs.get('model', ['']))[0] if attrs.get('model') else '',
            'status': _normalize_attr_value(attrs.get('status', ['unknown']))[0] if attrs.get('status') else 'unknown',
            # new: image resolved per device type
            'image': _device_image_name(dtype),
        }
        devices.append(device_info)
    
    ctx = {
        'active': 'e03',
        'devices': devices,
        'device_type': device_type,
        'username': username,
        'filter_used': flt,
        'error': err,
    }
    
    return render(request, 'e03_devices.html', _base_ctx(request, ctx))

def e03_device_detail(request):
    client_mode = _client_mode(request)
    safeness = _safeness(request)
    verbosity = _verbosity(request)

    dn = request.GET.get("dn", "").strip()
    if not dn:
        raise Http404()

    # Enforce that the DN is under the Devices OU
    devices_root = f"ou=Devices,{ldap_client.BASE_DN}"
    if not dn.lower().endswith(devices_root.lower()):
        raise Http404()

    entry = None
    err = None
    try:
        c = ldap_client._conn(client_mode)
        try:
            ok = c.search(dn, "(objectClass=*)", BASE, attributes=[ALL_ATTRIBUTES])
            if ok and len(c.entries) > 0:
                entry = c.entries[0]
                # Verify again the returned entry is still under Devices OU
                if not entry.entry_dn.lower().endswith(devices_root.lower()):
                    entry = None
                    err = "not_in_devices_ou"
            else:
                err = c.result.get('description') or "not_found"
        finally:
            c.unbind()
    except Exception as e:
        err = str(e)
        entry = None

    if not entry:
        raise Http404()

    # attrs = {k: _normalize_attr_value(v) for k, v in entry.entry_attributes_as_dict.items()}
    # Determine image from deviceType (fallback to 'device')
    def _to_display(val):
        norm = _normalize_attr_value(val)
        if isinstance(norm, (list, tuple)):
            return ", ".join(str(x) for x in norm)
        return str(norm)

    attrs_display = {k: _to_display(v) for k, v in entry.entry_attributes_as_dict.items()}
    raw_type = entry.entry_attributes_as_dict.get('deviceType')
    dtype = _normalize_attr_value(raw_type)[0] if raw_type else 'device'
    image = _device_image_name(dtype)

    # Build a back link to the list, preserving device_type if present
    back_url = f"{reverse('e03_devices')}?device_type={(request.GET.get('device_type') or 'printer')}"

    ctx = {
        "active": "e03",
        "device_detail": {
            "dn": dn,
            "attrs": attrs_display,
            "type": dtype,
            "image": image,
        },
        "back_url": back_url,
        # Escape only for display
        "filter_used": f"(distinguishedName={escape_filter_chars(dn)})",
        "error": err,
    }
    return render(request, "e03_devices.html", _base_ctx(request, ctx))

def e03_workstations(request):
    return redirect(reverse('e03_devices'))


# ---------------- E04: BLIND SEARCHES ----------------
@require_http_methods(["GET"])
def e04_blind_and(request):
    client_mode = _client_mode(request)
    safeness = _safeness(request)
    verbosity = _verbosity(request)

    groups = ldap_client.list_groups(client_mode=client_mode)
    selected = request.GET.get("group")
    selected_dept = request.GET.get("dept")

    # Canonicalize: ensure both params exist; default dept = "" (ALL)
    if selected is None or selected_dept is None:
        params = request.GET.copy()
        if selected is None and groups:
            params["group"] = groups[0]
        if selected_dept is None:
            params["dept"] = ""  # empty means ALL
        return redirect(f"{request.path}?{params.urlencode()}")

    # Baseline: fetch all members (no department narrowing) to derive department list
    baseline_filter, baseline_entries, baseline_err, group_dn = ldap_client.e04_group_members_lab(
        selected, department=None, client_mode=client_mode, safeness=safeness
    )

    # Build department options from members' departmentNumber
    dept_values = set()
    for e in baseline_entries:
        dn_attrs = e.entry_attributes_as_dict
        val = dn_attrs.get("departmentNumber")
        if isinstance(val, (list, tuple)):
            if val:
                dept_values.add(str(val[0]))
        elif val:
            dept_values.add(str(val))
    departments = sorted(dept_values)

    # Decide which search to use based on selected_dept (empty = ALL).
    # Do NOT restrict to UI options so 'dept' remains injectable.
    if selected_dept:
        filt, entries, err, _ = ldap_client.e04_group_members_lab(
            selected, department=selected_dept, client_mode=client_mode, safeness=safeness
        )
    else:
        # Use baseline results (ALL departments)
        filt, entries, err = baseline_filter, baseline_entries, baseline_err

    members = []
    for e in entries:
        attrs = e.entry_attributes_as_dict
        def first(name):
            v = attrs.get(name)
            if isinstance(v, (list, tuple)):
                return v[0] if v else ""
            return v or ""
        members.append({
            "cn": first("cn"),
            "mail": first("mail"),
            "telephoneNumber": first("telephoneNumber"),
        })

    ctx = {
        "active": "e04",
        "groups": groups,
        "departments": departments,  # dynamic from baseline members (UI options)
        "selected_group": selected,
        "selected_dept": selected_dept,  # may be a custom (injectable) value
        "group_dn": group_dn,
        "members": members,
        "count": len(members),
        "filter_used": filt,
        "error": err,
    }
    return render(request, "e04_blind_and.html", _base_ctx(request, ctx))


@require_http_methods(["GET"])
def e05_blind_or(request):
    client_mode = _client_mode(request)
    safeness = _safeness(request)
    verbosity = _verbosity(request)
    q = request.GET.get("q", "").strip()
    match = request.GET.get("match", "contains").lower()
    if match not in ("contains", "starts", "ends", "exact"):
        match = "contains"
    page = int(request.GET.get("page", "1") or 1)
    filt, entries, search_err = ldap_client.e05_blind_or_search(q, match=match, client_mode=client_mode, safeness=safeness)
    rows = []
    for e in entries:
        attrs = e.entry_attributes_as_dict
        uid = attrs.get("uid")
        mail = attrs.get("mail")
        def first(x):
            if isinstance(x, (list, tuple)):
                return x[0] if x else ""
            return x or ""
        rows.append({"uid": first(uid), "mail": first(mail)})
    # Pagination
    per_page = 10
    total = len(rows)
    start = (page - 1) * per_page
    page_rows = rows[start:start + per_page]
    total_pages = max(1, (total + per_page - 1) // per_page)
    ctx = {
        "active": "e05",
        "q": q,
        "match": match,
        "rows": page_rows,
        "count": total,
        "page": page,
        "pages": total_pages,
        "filter_used": filt,
        "error": search_err,
    }
    return render(request, "e05_blind_or.html", _base_ctx(request, ctx))
