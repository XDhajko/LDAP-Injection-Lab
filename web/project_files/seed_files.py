from pathlib import Path
import textwrap

BASE = Path(__file__).parent

files = {
    "Engineering": [
        # public
        ("engineering_wiki_overview.pdf", "PUBLIC", "ajohnson"),
        ("dev_tools_quickstart.pdf", "PUBLIC", "tkral"),
        # confidential
        ("architecture_roadmap_2026.pdf", "CONFIDENTIAL", "kmiller"),
        ("incident_postmortem_2025-02-14.pdf", "CONFIDENTIAL", "msvoboda"),
        ("prototype_performance_results.xlsx", "CONFIDENTIAL", "egarcia"),
        ("reliability_improvement_plan.docx", "CONFIDENTIAL", "psingh"),
        # private (home dir analogues)
        ("tkral_personal_notes.txt", "PRIVATE", "tkral"),
        ("ajohnson_personal_notes.txt", "PRIVATE", "ajohnson"),
        ("msvoboda_personal_notes.txt", "PRIVATE", "msvoboda"),
        ("psingh_personal_notes.txt", "PRIVATE", "psingh"),
        ("kmiller_personal_notes.txt", "PRIVATE", "kmiller"),
        ("kmiller_team_plans.docx", "PRIVATE", "kmiller"),
        ("kmiller_sensitive_brainstorm.md", "PRIVATE", "kmiller"),
        ("egarcia_personal_notes.txt", "PRIVATE", "egarcia"),
    ],
    "Finance": [
        ("expense_policy.pdf", "PUBLIC", "pschmidt"),
        ("travel_reimbursement_form.pdf", "PUBLIC", "eclark"),
        ("salary_review_2025.xlsx", "CONFIDENTIAL", "pschmidt"),
        ("budget_planning_2026.xlsx", "CONFIDENTIAL", "jpeterson"),
        ("tax_audit_notes_2024.docx", "CONFIDENTIAL", "mlopez"),
        ("cash_flow_sensitivity_analysis.xlsx", "CONFIDENTIAL", "skim"),
        ("jpeterson_personal_notes.txt", "PRIVATE", "jpeterson"),
        ("mlopez_personal_notes.txt", "PRIVATE", "mlopez"),
        ("dnovak_personal_notes.txt", "PRIVATE", "dnovak"),
        ("skim_personal_notes.txt", "PRIVATE", "skim"),
        ("pschmidt_personal_notes.txt", "PRIVATE", "pschmidt"),
        ("pschmidt_team_plans.docx", "PRIVATE", "pschmidt"),
        ("pschmidt_sensitive_brainstorm.md", "PRIVATE", "pschmidt"),
        ("eclark_personal_notes.txt", "PRIVATE", "eclark"),
    ],
    "HR": [
        ("employee_handbook.pdf", "PUBLIC", "anovakova"),
        ("holiday_calendar_2025.pdf", "PUBLIC", "dwilson"),
        ("performance_reviews_2025.xlsx", "CONFIDENTIAL", "rbrown"),
        ("compensation_bands_2025.xlsx", "CONFIDENTIAL", "dwilson"),
        ("recruitment_pipeline_tech_roles.xlsx", "CONFIDENTIAL", "lrossi"),
        ("anovakova_personal_notes.txt", "PRIVATE", "anovakova"),
        ("rbrown_personal_notes.txt", "PRIVATE", "rbrown"),
        ("rbrown_team_plans.docx", "PRIVATE", "rbrown"),
        ("rbrown_sensitive_brainstorm.md", "PRIVATE", "rbrown"),
        ("lrossi_personal_notes.txt", "PRIVATE", "lrossi"),
        ("mgreen_personal_notes.txt", "PRIVATE", "mgreen"),
        ("khorak_personal_notes.txt", "PRIVATE", "khorak"),
        ("dwilson_personal_notes.txt", "PRIVATE", "dwilson"),
    ],
    "IT": [
        ("vpn_setup_guide.pdf", "PUBLIC", "mnovak"),
        ("password_policy.pdf", "PUBLIC", "nhughes"),
        ("network_diagram_core.vsdx", "CONFIDENTIAL", "ipetrov"),
        ("domain_admins_credentials.kdbx", "CONFIDENTIAL", "ipetrov"),
        ("security_assessment_2025.pdf", "CONFIDENTIAL", "nhughes"),
        ("mnovak_personal_notes.txt", "PRIVATE", "mnovak"),
        ("ztaylor_personal_notes.txt", "PRIVATE", "ztaylor"),
        ("ipetrov_personal_notes.txt", "PRIVATE", "ipetrov"),
        ("ipetrov_team_plans.docx", "PRIVATE", "ipetrov"),
        ("ipetrov_sensitive_info.md", "PRIVATE", "ipetrov"),
        ("nhughes_personal_notes.txt", "PRIVATE", "nhughes"),
        ("nhughes_team_plans.docx", "PRIVATE", "nhughes"),
        ("nhughes_sensitive_brainstorm.md", "PRIVATE", "nhughes"),
        ("jblaha_personal_notes.txt", "PRIVATE", "jblaha"),
        ("oali_personal_notes.txt", "PRIVATE", "oali"),
    ],
    "Sales": [
        ("product_catalog_2025.pdf", "PUBLIC", "pnovak"),
        ("key_accounts_pipeline.xlsx", "CONFIDENTIAL", "rlee"),
        ("discount_approvals_2025.xlsx", "CONFIDENTIAL", "akowalski"),
        ("sales_forecast_2026.xlsx", "CONFIDENTIAL", "vnovak"),
        ("pnovak_personal_notes.txt", "PRIVATE", "pnovak"),
        ("lcarter_personal_notes.txt", "PRIVATE", "lcarter"),
        ("akowalski_personal_notes.txt", "PRIVATE", "akowalski"),
        ("akowalski_team_plans.docx", "PRIVATE", "akowalski"),
        ("akowalski_sensitive_brainstorm.md", "PRIVATE", "akowalski"),
        ("s_marin_personal_notes.txt", "PRIVATE", "s_marin"),
        ("rlee_personal_notes.txt", "PRIVATE", "rlee"),
        ("vnovak_personal_notes.txt", "PRIVATE", "vnovak"),
    ],
}

def content(dept, fname, classification, owner):
    return textwrap.dedent(f"""
    File: {fname}
    Department: {dept}
    Classification: {classification}
    Owner UID: {owner}

    This is placeholder demo content for LDAP injection lab.
    The real file would contain sensitive or public data according to its classification.
    """).strip() + "\n"

def main():
    for dept, entries in files.items():
        dpath = BASE / dept
        dpath.mkdir(parents=True, exist_ok=True)
        for fname, classification, owner in entries:
            fpath = dpath / fname
            # Skip if already exists to avoid overwriting manual changes
            if fpath.exists():
                continue
            # Write simple text even for non-text extensions (lab demo)
            fpath.write_text(content(dept, fname, classification, owner), encoding="utf-8")
    print("Seed files created (non-text formats contain plain text placeholders).")

if __name__ == "__main__":
    main()
