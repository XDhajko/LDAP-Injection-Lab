import argparse
import os
import sys
import ast
from typing import List, Dict, Any, Set
from collections import defaultdict

# ANSI colors for CLI output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class VariableDef:
    def __init__(self, name, lineno, code, dependencies=None, is_unsafe=False, unsafe_reason="", is_sanitized=False):
        self.name = name
        self.lineno = lineno
        self.code = code
        self.dependencies = dependencies or [] # List of variable names this depends on
        self.is_unsafe = is_unsafe # True if this specific statement constructs an unsafe string (e.g. f-string)
        self.unsafe_reason = unsafe_reason
        self.is_sanitized = is_sanitized # True if the value assigned is considered safe/sanitized

class LDAPVulnVisitor(ast.NodeVisitor):
    def __init__(self, source_lines):
        self.source_lines = source_lines
        self.issues = []
        self.function_stack = ["global"] # Stack to track nested functions
        self.safe_vars = set()
        # Map variable name -> List[VariableDef] (to handle reassignments, we just keep list)
        self.var_defs = {} 
        self.processed_sinks = set()

    @property
    def current_function(self):
        return self.function_stack[-1]

    def visit_FunctionDef(self, node):
        self.function_stack.append(node.name)
        # Reset scope-specific tracking
        old_safe_vars = self.safe_vars.copy()
        old_var_defs = self.var_defs.copy()
        self.safe_vars = set()
        self.var_defs = {}
        
        self.generic_visit(node)
        
        self.safe_vars = old_safe_vars
        self.var_defs = old_var_defs
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def _get_code(self, lineno):
        if 0 <= lineno - 1 < len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _is_sanitizer_call(self, node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                name = node.func.id.lower()
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr.lower()
            else:
                return False
            
            # Explicitly exclude 'maybe_escape' as it is conditional/ambiguous
            if "maybe" in name:
                return False
                
            return "escape" in name or "clean" in name or "safe" in name
        return False

    def _is_safe_expression(self, node):
        if self._is_sanitizer_call(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.safe_vars
        return False

    def _extract_dependencies(self, node):
        """Extract variable names used in an expression."""
        deps = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                deps.add(child.id)
        return list(deps)

    def _check_unsafe_construction(self, node):
        """Check if a node constructs a string using unsafe variables."""
        is_unsafe = False
        reason = ""
        
        if isinstance(node, ast.JoinedStr): # f-string
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    if not self._is_safe_expression(part.value):
                        is_unsafe = True
                        reason = "Unsafe F-String interpolation"
                        break
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add): # concatenation
            if self._has_unsafe_input(node):
                is_unsafe = True
                reason = "Unsafe Concatenation"
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
            # Check args
            for arg in node.args:
                if not self._is_safe_expression(arg) and not isinstance(arg, ast.Constant):
                    is_unsafe = True
                    reason = "Unsafe .format() call"
                    break
            # Check keywords
            if not is_unsafe:
                for kw in node.keywords:
                    if not self._is_safe_expression(kw.value) and not isinstance(kw.value, ast.Constant):
                        is_unsafe = True
                        reason = "Unsafe .format() call"
                        break
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod): # % formatting
             if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                 # Check right side
                 if not self._is_safe_expression(node.right) and not isinstance(node.right, ast.Constant):
                     is_unsafe = True
                     reason = "Unsafe % formatting"
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'join':
             # sep.join(iterable)
             if len(node.args) > 0:
                 if not self._is_safe_expression(node.args[0]):
                     is_unsafe = True
                     reason = "Unsafe .join()"

        return is_unsafe, reason

    def _has_unsafe_input(self, node):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._has_unsafe_input(node.left) or self._has_unsafe_input(node.right)
        if isinstance(node, ast.Constant):
            return False
        return not self._is_safe_expression(node)

    def visit_Call(self, node):
        # Handle list.append(value) to track list construction
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'append':
            if isinstance(node.func.value, ast.Name) and len(node.args) == 1:
                var_name = node.func.value.id
                val_node = node.args[0]
                
                is_unsafe, reason = self._check_unsafe_construction(val_node)
                deps = self._extract_dependencies(val_node)
                deps.append(var_name) # Depends on previous state of the list
                
                # If we append unsafe input, the list operation is tainted (not sanitized)
                is_tainted_input = self._has_unsafe_input(val_node)

                def_obj = VariableDef(
                    name=var_name,
                    lineno=node.lineno,
                    code=self._get_code(node.lineno),
                    dependencies=deps,
                    is_unsafe=is_unsafe,
                    unsafe_reason=reason or "Unsafe list append",
                    is_sanitized=not is_tainted_input
                )
                
                if var_name not in self.var_defs:
                    self.var_defs[var_name] = []
                self.var_defs[var_name].append(def_obj)

        self.generic_visit(node)

    def visit_Assign(self, node):
        # Track safe variables
        is_safe_value = self._is_sanitizer_call(node.value) or self._is_safe_expression(node.value)
        
        # Analyze if this assignment is constructing a potential filter part
        is_unsafe_construction, reason = self._check_unsafe_construction(node.value)
        deps = self._extract_dependencies(node.value)

        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                
                # Update safe vars
                if is_safe_value:
                    self.safe_vars.add(var_name)
                else:
                    self.safe_vars.discard(var_name)

                # Record definition
                def_obj = VariableDef(
                    name=var_name,
                    lineno=node.lineno,
                    code=self._get_code(node.lineno),
                    dependencies=deps,
                    is_unsafe=is_unsafe_construction,
                    unsafe_reason=reason,
                    is_sanitized=is_safe_value
                )
                
                if var_name not in self.var_defs:
                    self.var_defs[var_name] = []
                self.var_defs[var_name].append(def_obj)
                
                # Check if this assignment itself looks like a sink (final filter)
                if is_unsafe_construction and self._looks_like_filter(node.value):
                    self._report_chain(def_obj)

        self.generic_visit(node)

    def visit_AugAssign(self, node):
        # Handle += 
        if isinstance(node.target, ast.Name):
            var_name = node.target.id
            is_unsafe, reason = self._check_unsafe_construction(node.value)
            deps = self._extract_dependencies(node.value)
            # Self-dependency for +=
            deps.append(var_name) 
            
            is_tainted_input = self._has_unsafe_input(node.value)

            def_obj = VariableDef(
                name=var_name,
                lineno=node.lineno,
                code=self._get_code(node.lineno),
                dependencies=deps,
                is_unsafe=is_unsafe,
                unsafe_reason=reason or "Unsafe Augmented Assignment",
                is_sanitized=not is_tainted_input
            )
            
            if var_name not in self.var_defs:
                self.var_defs[var_name] = []
            self.var_defs[var_name].append(def_obj)

            if is_unsafe and (self._looks_like_filter(node.value) or "filter" in var_name.lower()):
                self._report_chain(def_obj)
        
        self.generic_visit(node)

    def _looks_like_filter(self, node):
        """Heuristic: does the string being constructed look like an LDAP filter?"""
        # Check constants in f-strings or concat
        if isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    if self._is_ldap_marker(part.value): return True
        elif isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Add):
                return self._check_concat_for_filter(node)
            elif isinstance(node.op, ast.Mod):
                # Check left side of % formatting
                if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                    return self._is_ldap_marker(node.left.value)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
             # Check the string being formatted
             if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
                 return self._is_ldap_marker(node.func.value.value)
        return False

    def _check_concat_for_filter(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return self._is_ldap_marker(node.value)
        if isinstance(node, ast.BinOp):
            return self._check_concat_for_filter(node.left) or self._check_concat_for_filter(node.right)
        return False

    def _is_ldap_marker(self, s):
        s = s.strip()
        return s.startswith('(') and ('=' in s or '&' in s or '|' in s or '!' in s)

    def _collect_chain(self, var_def: VariableDef, visited: Set[int]) -> List[VariableDef]:
        """Recursively collect the chain of unsafe definitions leading to this one."""
        # Avoid cycles based on line number
        if var_def.lineno in visited:
            return []
        visited.add(var_def.lineno)
        
        chain = []
        
        # Add to chain if it's an unsafe construction OR it's a variable definition that isn't safe (taint propagation)
        # This ensures we see where unsafe values come from (e.g. safe_val = ... if ... else val)
        if var_def.is_unsafe or not var_def.is_sanitized:
            chain.append(var_def)
            
        # Recurse into dependencies
        for dep_name in var_def.dependencies:
            if dep_name in self.var_defs:
                # Find the definition of this dependency that happened BEFORE current line
                # We take the most recent one before current line
                relevant_defs = [d for d in self.var_defs[dep_name] if d.lineno < var_def.lineno]
                if relevant_defs:
                    # Take the last one (most recent assignment)
                    last_def = relevant_defs[-1]
                    sub_chain = self._collect_chain(last_def, visited)
                    chain.extend(sub_chain)
        
        return chain

    def _report_chain(self, sink_def: VariableDef):
        # Unique ID for this sink to avoid duplicates
        sink_id = f"{self.current_function}:{sink_def.lineno}"
        if sink_id in self.processed_sinks:
            return
        self.processed_sinks.add(sink_id)

        chain = self._collect_chain(sink_def, set())
        # Sort by line number
        chain.sort(key=lambda x: x.lineno)
        
        # Filter out duplicates in chain
        unique_chain = []
        seen_lines = set()
        for item in chain:
            if item.lineno not in seen_lines:
                unique_chain.append(item)
                seen_lines.add(item.lineno)
        
        if unique_chain:
            self.issues.append({
                "func": self.current_function,
                "chain": unique_chain
            })

def filter_subchains(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove findings that are sub-chains of other findings.
    """
    if not findings:
        return []

    line_usage = {}
    for idx, f in enumerate(findings):
        for item in f['chain']:
            if item.lineno not in line_usage:
                line_usage[item.lineno] = []
            line_usage[item.lineno].append(idx)

    indices_to_remove = set()
    
    for idx, f in enumerate(findings):
        sink = f['chain'][-1]
        sink_line = sink.lineno
        
        if sink_line in line_usage:
            for other_idx in line_usage[sink_line]:
                if other_idx != idx:
                    other_chain = findings[other_idx]['chain']
                    if other_chain[-1].lineno != sink_line:
                        indices_to_remove.add(idx)
                        break
                    else:
                        if len(f['chain']) < len(other_chain):
                            indices_to_remove.add(idx)
                            break

    return [f for i, f in enumerate(findings) if i not in indices_to_remove]

def analyze_file(filepath: str) -> List[Dict[str, Any]]:
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
            source_lines = source.splitlines()
        
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []

        visitor = LDAPVulnVisitor(source_lines)
        visitor.visit(tree)
        
        findings = visitor.issues
        findings = filter_subchains(findings)
            
    except Exception as e:
        pass
        
    return findings

def print_fixes():
    print(f"\n{Colors.HEADER}=== General Fixes for LDAP Injection in Python ==={Colors.ENDC}")
    print(f"{Colors.OKCYAN}1. Use ldap3.utils.conv.escape_filter_chars{Colors.ENDC}")
    print("   Before inserting any user input into a filter string, pass it through this function.")
    print("   Example:")
    print("     from ldap3.utils.conv import escape_filter_chars")
    print("     safe_input = escape_filter_chars(user_input)")
    print("     query = f'(cn={safe_input})'")
    
    print(f"\n{Colors.OKCYAN}2. Use Abstraction Layers{Colors.ENDC}")
    print("   Instead of raw string concatenation, use libraries that build filters programmatically")
    print("   if available, or create a builder class that handles escaping automatically.")
    
    print(f"\n{Colors.OKCYAN}3. Strict Input Validation{Colors.ENDC}")
    print("   Validate input against a strict allowlist (e.g., alphanumeric only) before using it.")

def main():
    parser = argparse.ArgumentParser(description="LDAP Injection Code Scanner (Data Flow Analysis)")
    parser.add_argument("path", help="Path to file or directory to scan")
    parser.add_argument("-r", "--recursive", action="store_true", default=True, help="Scan directories recursively (default: True)")
    parser.add_argument("--no-recursive", action="store_false", dest="recursive", help="Do not scan recursively")
    
    args = parser.parse_args()
    target_path = args.path
    
    if not os.path.exists(target_path):
        print(f"{Colors.FAIL}Error: Path '{target_path}' does not exist.{Colors.ENDC}")
        sys.exit(1)

    files_to_scan = []
    IGNORE_DIRS = {'.venv', 'venv', 'env', '__pycache__', '.git'}

    if os.path.isfile(target_path):
        if target_path.endswith('.py'):
            files_to_scan.append(target_path)
    else:
        if args.recursive:
            for root, dirs, files in os.walk(target_path):
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
                for file in files:
                    if file.endswith(".py"):
                        files_to_scan.append(os.path.join(root, file))
        else:
            for file in os.listdir(target_path):
                if file.endswith(".py"):
                    files_to_scan.append(os.path.join(target_path, file))

    print(f"{Colors.HEADER}Starting Data Flow Scan on: {target_path}{Colors.ENDC}")
    print(f"Found {len(files_to_scan)} Python files to scan (ignoring .venv/env).\n")
    
    total_findings = 0
    files_with_issues = []
    unique_vulnerable_functions = set()
    
    for filepath in files_to_scan:
        findings = analyze_file(filepath)
        if findings:
            files_with_issues.append(filepath)
            total_findings += len(findings)
            print(f"{Colors.BOLD}File: {filepath}{Colors.ENDC}")
            print("-" * 60)
            
            # Group findings by function
            grouped_findings = defaultdict(list)
            for f in findings:
                grouped_findings[f['func']].append(f)
                unique_vulnerable_functions.add(f['func'])
            
            # Sort functions by name
            sorted_funcs = sorted(grouped_findings.keys())
            
            for func_name in sorted_funcs:
                func_findings = grouped_findings[func_name]
                
                print(f"{Colors.OKBLUE}Function: {func_name}{Colors.ENDC}")
                
                # Sort findings within function by line number
                func_findings.sort(key=lambda x: x['chain'][-1].lineno if x['chain'] else 0)
                
                for f in func_findings:
                    print(f"  {Colors.WARNING}Vulnerability Detected{Colors.ENDC}")
                    print("  Trace:")
                    for i, step in enumerate(f['chain']):
                        prefix = "    "
                        if i == len(f['chain']) - 1:
                            prefix = "  └>" # Indicate sink
                        
                        print(f"{prefix} [Line {step.lineno}] {step.code}")
                    print("")
                print("-" * 40)
            print("-" * 60 + "\n")

    print(f"{Colors.HEADER}=== Scan Summary ==={Colors.ENDC}")
    print(f"Total files scanned: {len(files_to_scan)}")
    print(f"Total vulnerabilities found: {total_findings}")
    print(f"Unique vulnerable functions: {len(unique_vulnerable_functions)}")
    
    if files_with_issues:
        print(f"\n{Colors.FAIL}Files containing potential vulnerabilities:{Colors.ENDC}")
        for f in files_with_issues:
            print(f" - {f}")
    else:
        print(f"\n{Colors.OKGREEN}No obvious LDAP injection patterns found.{Colors.ENDC}")

    print_fixes()

if __name__ == "__main__":
    main()
