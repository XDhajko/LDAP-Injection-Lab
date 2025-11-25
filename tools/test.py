# Expected Vulnerabilities: 6
# 1. test_vulnerable_fstring
# 2. test_vulnerable_concat
# 3. test_vulnerable_format
# 4. test_vulnerable_percent
# 5. test_mixed_safety
# 6. test_reassignment_danger

from ldap3.utils.conv import escape_filter_chars

def test_vulnerable_fstring(user_input):
    # VULNERABLE: Raw input in f-string
    query = f"(&(uid={user_input})(objectClass=person))"
    return query

def test_safe_fstring_inline(user_input):
    # SAFE: Input escaped inline
    query = f"(&(uid={escape_filter_chars(user_input)})(objectClass=person))"
    return query

def test_safe_fstring_variable(user_input):
    # SAFE: Input escaped before use
    safe_user = escape_filter_chars(user_input)
    query = f"(&(uid={safe_user})(objectClass=person))"
    return query

def test_vulnerable_concat(user_input):
    # VULNERABLE: Raw input concatenation
    query = "(&(uid=" + user_input + ")(objectClass=person))"
    return query

def test_safe_concat(user_input):
    # SAFE: Escaped input concatenation
    safe_user = escape_filter_chars(user_input)
    query = "(&(uid=" + safe_user + ")(objectClass=person))"
    return query

def test_vulnerable_format(user_input):
    # VULNERABLE: .format() with raw input
    query = "(&(uid={})(objectClass=person))".format(user_input)
    return query

def test_safe_format(user_input):
    # SAFE: .format() with escaped input
    query = "(&(uid={})(objectClass=person))".format(escape_filter_chars(user_input))
    return query

def test_vulnerable_percent(user_input):
    # VULNERABLE: % formatting with raw input
    query = "(&(uid=%s)(objectClass=person))" % user_input
    return query

def test_safe_percent(user_input):
    # SAFE: % formatting with escaped input
    safe_user = escape_filter_chars(user_input)
    query = "(&(uid=%s)(objectClass=person))" % safe_user
    return query

def test_mixed_safety(user_input, safe_input):
    # VULNERABLE: One safe, one unsafe
    safe_val = escape_filter_chars(safe_input)
    query = f"(&(uid={user_input})(cn={safe_val}))"
    return query

def test_reassignment_danger(user_input):
    # VULNERABLE: Variable was safe, then overwritten with unsafe
    safe_val = escape_filter_chars(user_input)
    safe_val = user_input # Now unsafe
    query = f"(&(uid={safe_val}))"
    return query
