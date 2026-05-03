"""
Vulnerability and Patch Tracking System
Flask Application – Full CRUD for all 15 tables + Reports
Pavlos Giannakis – NYU Principles of Database Systems
"""

import os
import psycopg2
import psycopg2.extras
from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "vuln-tracker-dev-key")

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/vuln_tracker")


def get_conn():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn


def query(sql, params=None, fetchone=False, commit=False):
    """Helper: run a query, return results or commit."""
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        if commit:
            conn.commit()
            return cur.rowcount
        if fetchone:
            return cur.fetchone()
        return cur.fetchall()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


# ─────────────────────────────────────────────
# HOME / DASHBOARD
# ─────────────────────────────────────────────
@app.route("/")
def home():
    stats = {}
    try:
        stats["orgs"]        = query("SELECT COUNT(*) AS c FROM organizations", fetchone=True)["c"]
        stats["users"]       = query("SELECT COUNT(*) AS c FROM users", fetchone=True)["c"]
        stats["assets"]      = query("SELECT COUNT(*) AS c FROM assets", fetchone=True)["c"]
        stats["asset_groups"]= query("SELECT COUNT(*) AS c FROM asset_groups", fetchone=True)["c"]
        stats["software"]    = query("SELECT COUNT(*) AS c FROM software_products", fetchone=True)["c"]
        stats["vulns"]       = query("SELECT COUNT(*) AS c FROM vulnerabilities", fetchone=True)["c"]
        stats["findings"]    = query("SELECT COUNT(*) AS c FROM scan_findings WHERE status='Open'", fetchone=True)["c"]
        stats["actions"]     = query("SELECT COUNT(*) AS c FROM patch_actions", fetchone=True)["c"]
        stats["critical_findings"] = query(
            """SELECT COUNT(*) AS c FROM scan_findings sf
               JOIN software_vulnerabilities sv ON sf.sw_vuln_id_fk = sv.sw_vuln_id
               JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
               WHERE sf.status = 'Open' AND v.severity = 'Critical'""", fetchone=True)["c"]
        stats["exploitable"] = query(
            """SELECT COUNT(*) AS c FROM scan_findings sf
               JOIN software_vulnerabilities sv ON sf.sw_vuln_id_fk = sv.sw_vuln_id
               JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
               WHERE sf.status = 'Open' AND v.exploit_available = TRUE""", fetchone=True)["c"]
        stats["sla_breached"] = query(
            """SELECT COUNT(*) AS c FROM scan_findings
               WHERE status NOT IN ('Remediated','False Positive')
               AND sla_due_date < CURRENT_DATE""", fetchone=True)["c"]
        stats["scan_sources"] = query("SELECT COUNT(*) AS c FROM scan_sources", fetchone=True)["c"]
    except Exception:
        stats = {}
    return render_template("home.html", stats=stats)


# ─────────────────────────────────────────────
# GENERIC CRUD HELPERS
# ─────────────────────────────────────────────

TABLE_CONFIG = {
    # ── TABLE 1 ──────────────────────────────────────────────────────
    "organizations": {
        "label": "Organizations",
        "pk": "org_id",
        "columns": ["org_id", "org_name", "industry", "hq_country", "employee_count",
                    "revenue_tier", "regulatory_scope", "security_contact", "created_at"],
        "editable": ["org_name", "industry", "hq_country", "employee_count",
                     "revenue_tier", "regulatory_scope", "security_contact"],
        "display": ["ID", "Name", "Industry", "Country", "Employees",
                    "Revenue Tier", "Regulatory Scope", "Security Contact", "Created"],
        "order": "org_id",
        "field_options": {
            "revenue_tier": ["SMB", "Mid-Market", "Enterprise", "Fortune500"],
        },
    },

    # ── TABLE 2 ──────────────────────────────────────────────────────
    "users": {
        "label": "Users",
        "pk": "user_id",
        "columns": ["user_id", "org_id_fk", "username", "full_name", "email",
                    "department", "job_title", "role", "mfa_enabled", "is_active", "created_at"],
        "editable": ["org_id_fk", "username", "full_name", "email",
                     "department", "job_title", "role", "mfa_enabled", "is_active"],
        "display": ["ID", "Org", "Username", "Full Name", "Email",
                    "Department", "Job Title", "Role", "MFA", "Active", "Created"],
        "order": "user_id",
        "fk_lookups": {
            "org_id_fk": ("organizations", "org_id", "org_name"),
        },
        "field_options": {
            "role": ["admin", "security_engineer", "analyst", "patch_manager", "auditor", "viewer"],
        },
    },

    # ── TABLE 3 ──────────────────────────────────────────────────────
    "asset_groups": {
        "label": "Asset Groups",
        "pk": "group_id",
        "columns": ["group_id", "org_id_fk", "group_name", "group_type", "description",
                    "owner_id_fk", "created_at"],
        "editable": ["org_id_fk", "group_name", "group_type", "description", "owner_id_fk"],
        "display": ["ID", "Org", "Group Name", "Type", "Description", "Owner", "Created"],
        "order": "group_id",
        "fk_lookups": {
            "org_id_fk": ("organizations", "org_id", "org_name"),
            "owner_id_fk": ("users", "user_id", "full_name"),
        },
        "field_options": {
            "group_type": ["Network Zone", "Business Unit", "Compliance Scope",
                           "Criticality Tier", "Geographic"],
        },
    },

    # ── TABLE 4 ──────────────────────────────────────────────────────
    "assets": {
        "label": "Assets",
        "pk": "asset_id",
        "columns": ["asset_id", "org_id_fk", "owner_id_fk", "hostname", "fqdn",
                    "ip_address", "asset_type", "operating_system", "os_version",
                    "criticality", "environment", "network_zone", "is_active", "created_at"],
        "editable": ["org_id_fk", "owner_id_fk", "hostname", "fqdn",
                     "ip_address", "asset_type", "operating_system", "os_version",
                     "criticality", "environment", "network_zone", "is_active"],
        "display": ["ID", "Org", "Owner", "Hostname", "FQDN", "IP Address",
                    "Type", "OS", "OS Version", "Criticality", "Environment",
                    "Network Zone", "Active", "Created"],
        "order": "asset_id",
        "fk_lookups": {
            "org_id_fk": ("organizations", "org_id", "org_name"),
            "owner_id_fk": ("users", "user_id", "full_name"),
        },
        "field_options": {
            "environment": ["Production", "Staging", "Development", "Corporate", "Lab", "DMZ"],
        },
    },

    # ── TABLE 5 ──────────────────────────────────────────────────────
    "asset_group_memberships": {
        "label": "Asset Group Memberships",
        "pk": "membership_id",
        "columns": ["membership_id", "asset_id_fk", "group_id_fk", "added_at", "added_by_fk"],
        "editable": ["asset_id_fk", "group_id_fk", "added_by_fk"],
        "display": ["ID", "Asset", "Group", "Added At", "Added By"],
        "order": "membership_id",
        "fk_lookups": {
            "asset_id_fk": ("assets", "asset_id", "hostname"),
            "group_id_fk": ("asset_groups", "group_id", "group_name"),
            "added_by_fk": ("users", "user_id", "full_name"),
        },
    },

    # ── TABLE 6 ──────────────────────────────────────────────────────
    "scan_sources": {
        "label": "Scan Sources",
        "pk": "source_id",
        "columns": ["source_id", "org_id_fk", "source_name", "source_type", "vendor",
                    "product_version", "scan_frequency", "last_scan_at", "is_active"],
        "editable": ["org_id_fk", "source_name", "source_type", "vendor",
                     "product_version", "scan_frequency", "is_active"],
        "display": ["ID", "Org", "Source Name", "Type", "Vendor",
                    "Version", "Frequency", "Last Scan", "Active"],
        "order": "source_id",
        "fk_lookups": {
            "org_id_fk": ("organizations", "org_id", "org_name"),
        },
        "field_options": {
            "source_type": ["Vulnerability Scanner", "EDR", "SAST", "DAST",
                            "Manual", "Threat Intelligence", "Cloud Security"],
        },
    },

    # ── TABLE 7 ──────────────────────────────────────────────────────
    "software_products": {
        "label": "Software Products",
        "pk": "software_id",
        "columns": ["software_id", "product_name", "vendor", "version", "product_type",
                    "package_manager", "cpe_uri", "end_of_life_date", "is_supported", "license_type"],
        "editable": ["product_name", "vendor", "version", "product_type",
                     "package_manager", "cpe_uri", "end_of_life_date", "is_supported", "license_type"],
        "display": ["ID", "Product", "Vendor", "Version", "Type",
                    "Pkg Manager", "CPE URI", "EOL Date", "Supported", "License"],
        "order": "software_id",
        "field_options": {
            "product_type": ["Operating System", "Application", "Library", "Middleware",
                             "Database", "Network Device", "Container Runtime", "Cloud Service"],
        },
    },

    # ── TABLE 8 ──────────────────────────────────────────────────────
    "asset_software_installs": {
        "label": "Software Installs",
        "pk": "install_id",
        "columns": ["install_id", "asset_id_fk", "software_id_fk", "install_path",
                    "install_date", "detected_by", "is_authorized"],
        "editable": ["asset_id_fk", "software_id_fk", "install_path",
                     "install_date", "detected_by", "is_authorized"],
        "display": ["ID", "Asset", "Software", "Install Path",
                    "Install Date", "Detected By", "Authorized"],
        "order": "install_id",
        "fk_lookups": {
            "asset_id_fk": ("assets", "asset_id", "hostname"),
            "software_id_fk": ("software_products", "software_id", "product_name"),
        },
        "field_options": {
            "detected_by": ["scan", "agent", "manual", "SIEM"],
        },
    },

    # ── TABLE 9 ──────────────────────────────────────────────────────
    "vulnerabilities": {
        "label": "Vulnerabilities",
        "pk": "vuln_id",
        "columns": ["vuln_id", "cve_id", "cwe_id", "title", "severity", "cvss_score",
                    "epss_score", "attack_vector", "exploit_available", "patch_available",
                    "published_date", "description"],
        "editable": ["cve_id", "cwe_id", "title", "severity", "cvss_score",
                     "epss_score", "attack_vector", "exploit_available", "patch_available",
                     "published_date", "description"],
        "display": ["ID", "CVE", "CWE", "Title", "Severity", "CVSS",
                    "EPSS", "Attack Vector", "Exploit", "Patch Available",
                    "Published", "Description"],
        "order": "vuln_id",
        "field_options": {
            "severity": ["Critical", "High", "Medium", "Low", "Info"],
            "attack_vector": ["Network", "Adjacent", "Local", "Physical"],
        },
    },

    # ── TABLE 10 ──────────────────────────────────────────────────────
    "software_vulnerabilities": {
        "label": "Software Vulnerabilities",
        "pk": "sw_vuln_id",
        "columns": ["sw_vuln_id", "software_id_fk", "vuln_id_fk",
                    "affected_version_range", "fix_version", "patch_url"],
        "editable": ["software_id_fk", "vuln_id_fk",
                     "affected_version_range", "fix_version", "patch_url"],
        "display": ["ID", "Software", "Vulnerability", "Affected Versions", "Fix Version", "Patch URL"],
        "order": "sw_vuln_id",
        "fk_lookups": {
            "software_id_fk": ("software_products", "software_id", "product_name"),
            "vuln_id_fk": ("vulnerabilities", "vuln_id", "cve_id"),
        },
    },

    # ── TABLE 11 ──────────────────────────────────────────────────────
    "remediation_sla_policies": {
        "label": "SLA Policies",
        "pk": "policy_id",
        "columns": ["policy_id", "org_id_fk", "policy_name", "severity",
                    "max_days_to_remediate", "escalation_days",
                    "applies_to_env", "is_active", "effective_date", "created_by_fk"],
        "editable": ["org_id_fk", "policy_name", "severity",
                     "max_days_to_remediate", "escalation_days",
                     "applies_to_env", "is_active", "effective_date", "created_by_fk"],
        "display": ["ID", "Org", "Policy Name", "Severity",
                    "Max Days", "Escalation Days",
                    "Applies To Env", "Active", "Effective Date", "Created By"],
        "order": "policy_id",
        "fk_lookups": {
            "org_id_fk": ("organizations", "org_id", "org_name"),
            "created_by_fk": ("users", "user_id", "full_name"),
        },
        "field_options": {
            "severity": ["Critical", "High", "Medium", "Low", "Info"],
            "applies_to_env": ["Production", "Staging", "Development", "Corporate", "Lab", "DMZ"],
        },
    },

    # ── TABLE 12 ──────────────────────────────────────────────────────
    "scan_findings": {
        "label": "Scan Findings",
        "pk": "finding_id",
        "columns": ["finding_id", "asset_id_fk", "sw_vuln_id_fk", "scan_source_id_fk",
                    "status", "risk_score", "sla_due_date",
                    "discovered_at", "last_seen_at", "notes"],
        "editable": ["asset_id_fk", "sw_vuln_id_fk", "scan_source_id_fk",
                     "status", "notes"],
        "display": ["ID", "Asset", "SW Vuln", "Scan Source",
                    "Status", "Risk Score", "SLA Due",
                    "Discovered", "Last Seen", "Notes"],
        "order": "finding_id",
        "fk_lookups": {
            "asset_id_fk": ("assets", "asset_id", "hostname"),
            "sw_vuln_id_fk": {
                "sql": """
                    SELECT sv.sw_vuln_id,
                           sp.product_name || ' — ' || v.cve_id AS label
                    FROM software_vulnerabilities sv
                    JOIN software_products sp ON sv.software_id_fk = sp.software_id
                    JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
                    ORDER BY sv.sw_vuln_id
                """,
                "id_col": "sw_vuln_id",
                "label_col": "label",
            },
            "scan_source_id_fk": ("scan_sources", "source_id", "source_name"),
        },
        "field_options": {
            "status": ["Open", "In Progress", "Remediated", "Accepted Risk",
                       "False Positive", "Pending Retest"],
        },
    },

    # ── TABLE 13 ──────────────────────────────────────────────────────
    "patch_actions": {
        "label": "Patch Actions",
        "pk": "action_id",
        "columns": ["action_id", "finding_id_fk", "assigned_to_fk", "assigned_by_fk",
                    "action_type", "status", "priority", "due_date",
                    "change_ticket_id", "resolution_notes", "created_at"],
        "editable": ["finding_id_fk", "assigned_to_fk", "assigned_by_fk",
                     "action_type", "status", "priority", "due_date",
                     "change_ticket_id", "resolution_notes"],
        "display": ["ID", "Finding", "Assigned To", "Assigned By",
                    "Type", "Status", "Priority", "Due Date",
                    "Ticket", "Resolution Notes", "Created"],
        "order": "action_id",
        "fk_lookups": {
            "finding_id_fk": ("scan_findings", "finding_id", "finding_id"),
            "assigned_to_fk": ("users", "user_id", "full_name"),
            "assigned_by_fk": ("users", "user_id", "full_name"),
        },
        "field_options": {
            "action_type": ["Patch", "Configuration Change", "Workaround",
                            "Accept Risk", "Compensating Control", "Mitigate", "Remove Software"],
            "status": ["Pending", "In Progress", "Awaiting Approval",
                       "Completed", "Failed", "Cancelled", "Rolled Back"],
            "priority": ["Critical", "High", "Medium", "Low"],
        },
    },

    # ── TABLE 14 ──────────────────────────────────────────────────────
    "patch_status_history": {
        "label": "Patch Status History",
        "pk": "history_id",
        "columns": ["history_id", "action_id_fk", "old_status", "new_status",
                    "changed_by_fk", "changed_at", "change_reason", "automated"],
        "editable": ["action_id_fk", "old_status", "new_status",
                     "changed_by_fk", "change_reason", "automated"],
        "display": ["ID", "Action", "Old Status", "New Status",
                    "Changed By", "Changed At", "Reason", "Automated"],
        "order": "history_id DESC",
        "fk_lookups": {
            "action_id_fk": ("patch_actions", "action_id", "action_id"),
            "changed_by_fk": ("users", "user_id", "full_name"),
        },
    },

    # ── TABLE 15 ──────────────────────────────────────────────────────
    "risk_score_snapshots": {
        "label": "Risk Score Snapshots",
        "pk": "snapshot_id",
        "columns": ["snapshot_id", "asset_id_fk", "snapshot_date", "composite_score",
                    "open_findings_count", "critical_count", "high_count",
                    "medium_count", "low_count", "exploit_active_count", "sla_breached_count"],
        "editable": ["asset_id_fk", "snapshot_date", "composite_score",
                     "open_findings_count", "critical_count", "high_count",
                     "medium_count", "low_count", "exploit_active_count", "sla_breached_count"],
        "display": ["ID", "Asset", "Date", "Composite Score",
                    "Open Findings", "Critical", "High",
                    "Medium", "Low", "Exploitable", "SLA Breached"],
        "order": "snapshot_date DESC, asset_id_fk",
        "fk_lookups": {
            "asset_id_fk": ("assets", "asset_id", "hostname"),
        },
    },
}

TABLES_NAV = [
    ("organizations",           "Organizations"),
    ("users",                   "Users"),
    ("asset_groups",            "Asset Groups"),
    ("assets",                  "Assets"),
    ("asset_group_memberships", "Group Memberships"),
    ("scan_sources",            "Scan Sources"),
    ("software_products",       "Software Products"),
    ("asset_software_installs", "Software Installs"),
    ("vulnerabilities",         "Vulnerabilities"),
    ("software_vulnerabilities","Software Vulns"),
    ("remediation_sla_policies","SLA Policies"),
    ("scan_findings",           "Scan Findings"),
    ("patch_actions",           "Patch Actions"),
    ("patch_status_history",    "Status History"),
    ("risk_score_snapshots",    "Risk Snapshots"),
]


# Inject tables_nav into every template automatically so the sidebar
# always renders all 15 table links — no need to remember to pass it
# in each render_template call.
@app.context_processor
def inject_nav():
    return {"tables_nav": TABLES_NAV}


def get_fk_options(table_name):
    """Load FK dropdown options for a table's foreign key columns.

    Supports two lookup forms:
      - 3-tuple (ref_table, ref_pk, ref_display) — simple lookup
      - dict {"sql": "...", "id_col": "...", "label_col": "..."} — custom JOIN query
    """
    cfg = TABLE_CONFIG[table_name]
    fk_opts = {}
    lookups = cfg.get("fk_lookups", {})
    for fk_col, spec in lookups.items():
        if isinstance(spec, tuple):
            ref_table, ref_pk, ref_display = spec
            rows = query(f"SELECT {ref_pk}, {ref_display} FROM {ref_table} ORDER BY {ref_pk}")
            fk_opts[fk_col] = [(r[ref_pk], r[ref_display]) for r in rows]
        elif isinstance(spec, dict):
            rows = query(spec["sql"])
            fk_opts[fk_col] = [(r[spec["id_col"]], r[spec["label_col"]]) for r in rows]
    return fk_opts


# ─── LIST (SELECT) ───
@app.route("/table/<table_name>")
def table_list(table_name):
    if table_name not in TABLE_CONFIG:
        flash("Unknown table.", "error")
        return redirect(url_for("home"))
    cfg = TABLE_CONFIG[table_name]
    cols = ", ".join(cfg["columns"])
    rows = query(f"SELECT {cols} FROM {table_name} ORDER BY {cfg['order']}")
    return render_template("table_list.html",
                           table_name=table_name,
                           cfg=cfg,
                           rows=rows,
                           tables_nav=TABLES_NAV)


# ─── CREATE (INSERT) ───
@app.route("/table/<table_name>/create", methods=["GET", "POST"])
def table_create(table_name):
    if table_name not in TABLE_CONFIG:
        flash("Unknown table.", "error")
        return redirect(url_for("home"))
    cfg = TABLE_CONFIG[table_name]
    fk_opts = get_fk_options(table_name)

    if request.method == "POST":
        fields = cfg["editable"]
        values = []
        for f in fields:
            val = request.form.get(f, "").strip()
            values.append(val if val != "" else None)
        placeholders = ", ".join(["%s"] * len(fields))
        col_names = ", ".join(fields)
        try:
            query(f"INSERT INTO {table_name} ({col_names}) VALUES ({placeholders})",
                  params=tuple(values), commit=True)
            flash(f"Record created in {cfg['label']}.", "success")
            return redirect(url_for("table_list", table_name=table_name))
        except Exception as e:
            flash(f"Error: {e}", "error")

    return render_template("table_form.html",
                           table_name=table_name,
                           cfg=cfg,
                           mode="Create",
                           record=None,
                           fk_opts=fk_opts,
                           tables_nav=TABLES_NAV)


# ─── EDIT (UPDATE) ───
@app.route("/table/<table_name>/edit/<int:pk_val>", methods=["GET", "POST"])
def table_edit(table_name, pk_val):
    if table_name not in TABLE_CONFIG:
        flash("Unknown table.", "error")
        return redirect(url_for("home"))
    cfg = TABLE_CONFIG[table_name]
    fk_opts = get_fk_options(table_name)
    pk = cfg["pk"]

    record = query(f"SELECT * FROM {table_name} WHERE {pk} = %s", (pk_val,), fetchone=True)
    if not record:
        flash("Record not found.", "error")
        return redirect(url_for("table_list", table_name=table_name))

    if request.method == "POST":
        fields = cfg["editable"]
        set_clause = ", ".join([f"{f} = %s" for f in fields])
        values = []
        for f in fields:
            val = request.form.get(f, "").strip()
            values.append(val if val != "" else None)
        values.append(pk_val)
        try:
            query(f"UPDATE {table_name} SET {set_clause} WHERE {pk} = %s",
                  params=tuple(values), commit=True)
            flash(f"Record updated in {cfg['label']}.", "success")
            return redirect(url_for("table_list", table_name=table_name))
        except Exception as e:
            flash(f"Error: {e}", "error")

    return render_template("table_form.html",
                           table_name=table_name,
                           cfg=cfg,
                           mode="Edit",
                           record=record,
                           fk_opts=fk_opts,
                           tables_nav=TABLES_NAV)


# ─── DELETE ───
@app.route("/table/<table_name>/delete/<int:pk_val>", methods=["POST"])
def table_delete(table_name, pk_val):
    if table_name not in TABLE_CONFIG:
        flash("Unknown table.", "error")
        return redirect(url_for("home"))
    cfg = TABLE_CONFIG[table_name]
    pk = cfg["pk"]
    try:
        query(f"DELETE FROM {table_name} WHERE {pk} = %s", (pk_val,), commit=True)
        flash(f"Record deleted from {cfg['label']}.", "success")
    except Exception as e:
        flash(f"Error deleting: {e}", "error")
    return redirect(url_for("table_list", table_name=table_name))


# ─────────────────────────────────────────────
# REPORTS
# ─────────────────────────────────────────────
@app.route("/reports")
def reports_index():
    return render_template("reports_index.html", tables_nav=TABLES_NAV)


@app.route("/reports/findings-by-severity")
def report_findings_severity():
    rows = query("""
        SELECT v.severity,
               COUNT(*) AS cnt,
               ROUND(AVG(v.cvss_score), 2) AS avg_cvss,
               ROUND(AVG(v.epss_score)::NUMERIC, 4) AS avg_epss,
               SUM(CASE WHEN v.exploit_available THEN 1 ELSE 0 END) AS with_exploit
        FROM scan_findings sf
        JOIN software_vulnerabilities sv ON sf.sw_vuln_id_fk = sv.sw_vuln_id
        JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
        WHERE sf.status NOT IN ('Remediated', 'False Positive')
        GROUP BY v.severity
        ORDER BY CASE v.severity
            WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
            WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END
    """)
    return render_template("report.html",
                           title="Active Findings by Severity",
                           description="Active (non-remediated) scan findings grouped by vulnerability severity, with average CVSS/EPSS scores and exploit availability counts.",
                           headers=["Severity", "Count", "Avg CVSS", "Avg EPSS", "With Exploit"],
                           rows=[(r["severity"], r["cnt"], r["avg_cvss"], r["avg_epss"], r["with_exploit"]) for r in rows],
                           tables_nav=TABLES_NAV)


@app.route("/reports/patch-status-summary")
def report_patch_status():
    rows = query("""
        SELECT pa.status,
               pa.priority,
               COUNT(*) AS cnt,
               COUNT(CASE WHEN pa.due_date < CURRENT_DATE AND pa.status NOT IN ('Completed','Cancelled') THEN 1 END) AS overdue
        FROM patch_actions pa
        GROUP BY pa.status, pa.priority
        ORDER BY CASE pa.priority WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END,
                 pa.status
    """)
    return render_template("report.html",
                           title="Patch Actions by Status and Priority",
                           description="Breakdown of patch actions across all statuses and priority levels, with overdue action count.",
                           headers=["Status", "Priority", "Count", "Overdue"],
                           rows=[(r["status"], r["priority"], r["cnt"], r["overdue"]) for r in rows],
                           tables_nav=TABLES_NAV)


@app.route("/reports/top-exposed-assets")
def report_top_assets():
    rows = query("""
        SELECT a.hostname,
               a.ip_address::TEXT AS ip,
               a.environment,
               a.criticality,
               o.org_name,
               COUNT(sf.finding_id) AS open_findings,
               ROUND(MAX(sf.risk_score), 2) AS max_risk_score,
               SUM(CASE WHEN v.exploit_available THEN 1 ELSE 0 END) AS exploitable_vulns,
               SUM(CASE WHEN sf.sla_due_date < CURRENT_DATE THEN 1 ELSE 0 END) AS sla_breaches
        FROM assets a
        JOIN organizations o ON a.org_id_fk = o.org_id
        JOIN scan_findings sf ON a.asset_id = sf.asset_id_fk
        JOIN software_vulnerabilities sv ON sf.sw_vuln_id_fk = sv.sw_vuln_id
        JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
        WHERE sf.status NOT IN ('Remediated', 'False Positive')
        GROUP BY a.asset_id, a.hostname, a.ip_address, a.environment, a.criticality, o.org_name
        ORDER BY open_findings DESC, max_risk_score DESC
        LIMIT 10
    """)
    return render_template("report.html",
                           title="Top 10 Highest-Exposure Assets",
                           description="Assets ranked by open finding count, with max risk score, exploitable vulnerability count, and SLA breach count.",
                           headers=["Hostname", "IP", "Env", "Criticality", "Org",
                                    "Open Findings", "Max Risk Score", "Exploitable", "SLA Breaches"],
                           rows=[(r["hostname"], r["ip"], r["environment"], r["criticality"],
                                  r["org_name"], r["open_findings"], r["max_risk_score"],
                                  r["exploitable_vulns"], r["sla_breaches"]) for r in rows],
                           tables_nav=TABLES_NAV)


@app.route("/reports/compliance-by-org")
def report_compliance_org():
    rows = query("""
        SELECT o.org_name,
               o.industry,
               o.regulatory_scope,
               COUNT(DISTINCT a.asset_id) AS asset_count,
               COUNT(pa.action_id) AS total_actions,
               COUNT(CASE WHEN pa.status = 'Completed' THEN 1 END) AS completed,
               CASE WHEN COUNT(pa.action_id) > 0
                    THEN ROUND(COUNT(CASE WHEN pa.status = 'Completed' THEN 1 END)::NUMERIC
                               / COUNT(pa.action_id) * 100, 1)
                    ELSE 100.0 END AS compliance_pct,
               COUNT(CASE WHEN sf.sla_due_date < CURRENT_DATE
                          AND sf.status NOT IN ('Remediated','False Positive') THEN 1 END) AS sla_breaches
        FROM organizations o
        LEFT JOIN assets a ON o.org_id = a.org_id_fk
        LEFT JOIN scan_findings sf ON a.asset_id = sf.asset_id_fk
        LEFT JOIN patch_actions pa ON sf.finding_id = pa.finding_id_fk
        GROUP BY o.org_id, o.org_name, o.industry, o.regulatory_scope
        ORDER BY compliance_pct ASC
    """)
    return render_template("report.html",
                           title="Patch Compliance Rate by Organization",
                           description="Per-organization compliance: total assets, patch actions completed vs. total, compliance percentage, and SLA breach count.",
                           headers=["Organization", "Industry", "Regulatory Scope", "Assets",
                                    "Total Actions", "Completed", "Compliance %", "SLA Breaches"],
                           rows=[(r["org_name"], r["industry"], r["regulatory_scope"],
                                  r["asset_count"], r["total_actions"], r["completed"],
                                  r["compliance_pct"], r["sla_breaches"]) for r in rows],
                           tables_nav=TABLES_NAV)


@app.route("/reports/most-affected-software")
def report_most_affected_sw():
    rows = query("""
        SELECT sp.product_name,
               sp.vendor,
               sp.version,
               sp.product_type,
               sp.cpe_uri,
               COUNT(DISTINCT sv.vuln_id_fk) AS vuln_count,
               COUNT(DISTINCT sf.finding_id) AS finding_count,
               ROUND(MAX(v.cvss_score), 1) AS max_cvss,
               ROUND(MAX(v.epss_score)::NUMERIC, 4) AS max_epss,
               SUM(CASE WHEN v.exploit_available THEN 1 ELSE 0 END) AS exploitable_count
        FROM software_products sp
        JOIN software_vulnerabilities sv ON sp.software_id = sv.software_id_fk
        JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
        LEFT JOIN scan_findings sf ON sv.sw_vuln_id = sf.sw_vuln_id_fk
        GROUP BY sp.software_id, sp.product_name, sp.vendor, sp.version, sp.product_type, sp.cpe_uri
        ORDER BY vuln_count DESC, max_cvss DESC
    """)
    return render_template("report.html",
                           title="Most Vulnerable Software Products",
                           description="Software products ranked by known vulnerability count, with max CVSS/EPSS scores and exploitable vulnerability counts.",
                           headers=["Product", "Vendor", "Version", "Type", "CPE URI",
                                    "Known Vulns", "Active Findings", "Max CVSS", "Max EPSS", "Exploitable"],
                           rows=[(r["product_name"], r["vendor"], r["version"], r["product_type"],
                                  r["cpe_uri"], r["vuln_count"], r["finding_count"],
                                  r["max_cvss"], r["max_epss"], r["exploitable_count"]) for r in rows],
                           tables_nav=TABLES_NAV)


@app.route("/reports/exploit-risk-dashboard")
def report_exploit_risk():
    """Uses vw_exploit_risk_dashboard view."""
    rows = query("""
        SELECT * FROM vw_exploit_risk_dashboard
        ORDER BY epss_score DESC, cvss_score DESC
        LIMIT 20
    """)
    if not rows:
        headers = ["No data"]
        data = []
    else:
        headers = list(rows[0].keys())
        data = [tuple(r[h] for h in headers) for r in rows]
    return render_template("report.html",
                           title="Exploit Risk Dashboard (Top 20)",
                           description="View: vw_exploit_risk_dashboard — shows only active findings (excluding Remediated, Accepted Risk, and False Positive) that are Critical or High severity, or have a known public exploit. Sorted by exploit probability.",
                           headers=headers,
                           rows=data,
                           tables_nav=TABLES_NAV)


@app.route("/reports/org-risk-posture")
def report_org_risk():
    """Uses vw_organization_risk_posture view."""
    rows = query("SELECT * FROM vw_organization_risk_posture ORDER BY aggregate_risk_score DESC")
    if not rows:
        headers = ["No data"]
        data = []
    else:
        headers = list(rows[0].keys())
        data = [tuple(r[h] for h in headers) for r in rows]
    return render_template("report.html",
                           title="Organization Risk Posture",
                           description="View: vw_organization_risk_posture — aggregated risk scores, SLA breach counts, and compliance rates per organization.",
                           headers=headers,
                           rows=data,
                           tables_nav=TABLES_NAV)


@app.route("/reports/sla-breach-analysis")
def report_sla_breach():
    rows = query("""
        SELECT o.org_name,
               v.severity,
               COUNT(*) AS breach_count,
               ROUND(AVG(CURRENT_DATE - sf.sla_due_date), 1) AS avg_days_overdue,
               MAX(CURRENT_DATE - sf.sla_due_date) AS max_days_overdue,
               ROUND(AVG(sf.risk_score), 2) AS avg_risk_score
        FROM scan_findings sf
        JOIN assets a ON sf.asset_id_fk = a.asset_id
        JOIN organizations o ON a.org_id_fk = o.org_id
        JOIN software_vulnerabilities sv ON sf.sw_vuln_id_fk = sv.sw_vuln_id
        JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
        WHERE sf.sla_due_date < CURRENT_DATE
          AND sf.status NOT IN ('Remediated','False Positive')
        GROUP BY o.org_name, v.severity
        ORDER BY CASE v.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END,
                 breach_count DESC
    """)
    return render_template("report.html",
                           title="SLA Breach Analysis",
                           description="Findings that have exceeded their SLA deadline, grouped by organization and severity. Shows average and maximum days overdue.",
                           headers=["Organization", "Severity", "Breach Count",
                                    "Avg Days Overdue", "Max Days Overdue", "Avg Risk Score"],
                           rows=[(r["org_name"], r["severity"], r["breach_count"],
                                  r["avg_days_overdue"], r["max_days_overdue"],
                                  r["avg_risk_score"]) for r in rows],
                           tables_nav=TABLES_NAV)


# ─────────────────────────────────────────────
# SQL OBJECTS INFO PAGE
# ─────────────────────────────────────────────
@app.route("/sql-objects")
def sql_objects():
    return render_template("sql_objects.html", tables_nav=TABLES_NAV)


# ─────────────────────────────────────────────
# DISCUSSION PAGES
# ─────────────────────────────────────────────
@app.route("/discussion")
def discussion():
    return render_template("discussion.html", tables_nav=TABLES_NAV)


# ─────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
