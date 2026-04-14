"""
Vulnerability and Patch Tracking System
Flask Application – Full CRUD for all 10 tables + Reports
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
        stats["orgs"] = query("SELECT COUNT(*) AS c FROM organizations", fetchone=True)["c"]
        stats["users"] = query("SELECT COUNT(*) AS c FROM users", fetchone=True)["c"]
        stats["assets"] = query("SELECT COUNT(*) AS c FROM assets", fetchone=True)["c"]
        stats["software"] = query("SELECT COUNT(*) AS c FROM software_products", fetchone=True)["c"]
        stats["vulns"] = query("SELECT COUNT(*) AS c FROM vulnerabilities", fetchone=True)["c"]
        stats["findings"] = query("SELECT COUNT(*) AS c FROM scan_findings WHERE status='Open'", fetchone=True)["c"]
        stats["actions"] = query("SELECT COUNT(*) AS c FROM patch_actions", fetchone=True)["c"]
    except Exception:
        stats = {}
    return render_template("home.html", stats=stats)


# ─────────────────────────────────────────────
# GENERIC CRUD HELPERS
# ─────────────────────────────────────────────

TABLE_CONFIG = {
    "organizations": {
        "label": "Organizations",
        "pk": "org_id",
        "columns": ["org_id", "org_name", "industry", "created_at"],
        "editable": ["org_name", "industry"],
        "display": ["ID", "Name", "Industry", "Created"],
        "order": "org_id",
    },
    "users": {
        "label": "Users",
        "pk": "user_id",
        "columns": ["user_id", "org_id_fk", "username", "full_name", "email", "role", "created_at"],
        "editable": ["org_id_fk", "username", "full_name", "email", "role"],
        "display": ["ID", "Org ID", "Username", "Full Name", "Email", "Role", "Created"],
        "order": "user_id",
        "fk_lookups": {
            "org_id_fk": ("organizations", "org_id", "org_name"),
        },
        "field_options": {
            "role": ["admin", "analyst", "engineer", "viewer"],
        },
    },
    "assets": {
        "label": "Assets",
        "pk": "asset_id",
        "columns": ["asset_id", "org_id_fk", "hostname", "asset_type", "operating_system", "criticality", "environment", "created_at"],
        "editable": ["org_id_fk", "hostname", "asset_type", "operating_system", "criticality", "environment"],
        "display": ["ID", "Org ID", "Hostname", "Type", "OS", "Criticality", "Environment", "Created"],
        "order": "asset_id",
        "fk_lookups": {
            "org_id_fk": ("organizations", "org_id", "org_name"),
        },
        "field_options": {
            "environment": ["Production", "Staging", "Development", "Corporate", "Lab"],
        },
    },
    "software_products": {
        "label": "Software Products",
        "pk": "software_id",
        "columns": ["software_id", "product_name", "vendor", "version"],
        "editable": ["product_name", "vendor", "version"],
        "display": ["ID", "Product", "Vendor", "Version"],
        "order": "software_id",
    },
    "asset_software_installs": {
        "label": "Software Installs",
        "pk": "install_id",
        "columns": ["install_id", "asset_id_fk", "software_id_fk", "install_date"],
        "editable": ["asset_id_fk", "software_id_fk", "install_date"],
        "display": ["ID", "Asset ID", "Software ID", "Install Date"],
        "order": "install_id",
        "fk_lookups": {
            "asset_id_fk": ("assets", "asset_id", "hostname"),
            "software_id_fk": ("software_products", "software_id", "product_name"),
        },
    },
    "vulnerabilities": {
        "label": "Vulnerabilities",
        "pk": "vuln_id",
        "columns": ["vuln_id", "cve_id", "title", "severity", "cvss_score", "published_date", "description"],
        "editable": ["cve_id", "title", "severity", "cvss_score", "published_date", "description"],
        "display": ["ID", "CVE", "Title", "Severity", "CVSS", "Published", "Description"],
        "order": "vuln_id",
        "field_options": {
            "severity": ["Critical", "High", "Medium", "Low", "Info"],
        },
    },
    "software_vulnerabilities": {
        "label": "Software Vulnerabilities",
        "pk": "sw_vuln_id",
        "columns": ["sw_vuln_id", "software_id_fk", "vuln_id_fk"],
        "editable": ["software_id_fk", "vuln_id_fk"],
        "display": ["ID", "Software ID", "Vulnerability ID"],
        "order": "sw_vuln_id",
        "fk_lookups": {
            "software_id_fk": ("software_products", "software_id", "product_name"),
            "vuln_id_fk": ("vulnerabilities", "vuln_id", "title"),
        },
    },
    "scan_findings": {
        "label": "Scan Findings",
        "pk": "finding_id",
        "columns": ["finding_id", "asset_id_fk", "sw_vuln_id_fk", "status", "discovered_at", "notes"],
        "editable": ["asset_id_fk", "sw_vuln_id_fk", "status", "notes"],
        "display": ["ID", "Asset ID", "SW Vuln ID", "Status", "Discovered", "Notes"],
        "order": "finding_id",
        "fk_lookups": {
            "asset_id_fk": ("assets", "asset_id", "hostname"),
            "sw_vuln_id_fk": ("software_vulnerabilities", "sw_vuln_id", "sw_vuln_id"),
        },
        "field_options": {
            "status": ["Open", "In Progress", "Remediated", "Accepted Risk", "False Positive"],
        },
    },
    "patch_actions": {
        "label": "Patch Actions",
        "pk": "action_id",
        "columns": ["action_id", "finding_id_fk", "assigned_to_fk", "action_type", "status", "due_date", "completed_at", "created_at"],
        "editable": ["finding_id_fk", "assigned_to_fk", "action_type", "status", "due_date", "completed_at"],
        "display": ["ID", "Finding ID", "Assigned To", "Type", "Status", "Due Date", "Completed", "Created"],
        "order": "action_id",
        "fk_lookups": {
            "finding_id_fk": ("scan_findings", "finding_id", "finding_id"),
            "assigned_to_fk": ("users", "user_id", "full_name"),
        },
        "field_options": {
            "action_type": ["Patch", "Workaround", "Accept Risk", "Mitigate"],
            "status": ["Pending", "In Progress", "Completed", "Failed", "Cancelled"],
        },
    },
    "patch_status_history": {
        "label": "Patch Status History",
        "pk": "history_id",
        "columns": ["history_id", "action_id_fk", "old_status", "new_status", "changed_by_fk", "changed_at", "note"],
        "editable": ["action_id_fk", "old_status", "new_status", "changed_by_fk", "note"],
        "display": ["ID", "Action ID", "Old Status", "New Status", "Changed By", "Changed At", "Note"],
        "order": "history_id DESC",
        "fk_lookups": {
            "action_id_fk": ("patch_actions", "action_id", "action_id"),
            "changed_by_fk": ("users", "user_id", "full_name"),
        },
    },
}

TABLES_NAV = [
    ("organizations", "Organizations"),
    ("users", "Users"),
    ("assets", "Assets"),
    ("software_products", "Software Products"),
    ("asset_software_installs", "Software Installs"),
    ("vulnerabilities", "Vulnerabilities"),
    ("software_vulnerabilities", "Software Vulns"),
    ("scan_findings", "Scan Findings"),
    ("patch_actions", "Patch Actions"),
    ("patch_status_history", "Status History"),
]


def get_fk_options(table_name):
    """Load FK dropdown options for a table's foreign key columns."""
    cfg = TABLE_CONFIG[table_name]
    fk_opts = {}
    lookups = cfg.get("fk_lookups", {})
    for fk_col, (ref_table, ref_pk, ref_display) in lookups.items():
        rows = query(f"SELECT {ref_pk}, {ref_display} FROM {ref_table} ORDER BY {ref_pk}")
        fk_opts[fk_col] = [(r[ref_pk], r[ref_display]) for r in rows]
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
        SELECT v.severity, COUNT(*) AS cnt
        FROM scan_findings sf
        JOIN software_vulnerabilities sv ON sf.sw_vuln_id_fk = sv.sw_vuln_id
        JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
        WHERE sf.status = 'Open'
        GROUP BY v.severity
        ORDER BY CASE v.severity
            WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
            WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END
    """)
    return render_template("report.html",
                           title="Open Findings by Severity",
                           headers=["Severity", "Count"],
                           rows=[(r["severity"], r["cnt"]) for r in rows],
                           tables_nav=TABLES_NAV)


@app.route("/reports/patch-status-summary")
def report_patch_status():
    rows = query("""
        SELECT status, COUNT(*) AS cnt
        FROM patch_actions
        GROUP BY status
        ORDER BY COUNT(*) DESC
    """)
    return render_template("report.html",
                           title="Patch Actions by Status",
                           headers=["Status", "Count"],
                           rows=[(r["status"], r["cnt"]) for r in rows],
                           tables_nav=TABLES_NAV)


@app.route("/reports/top-exposed-assets")
def report_top_assets():
    rows = query("""
        SELECT a.hostname, a.environment, a.criticality,
               COUNT(sf.finding_id) AS open_findings
        FROM assets a
        JOIN scan_findings sf ON a.asset_id = sf.asset_id_fk AND sf.status = 'Open'
        GROUP BY a.asset_id, a.hostname, a.environment, a.criticality
        ORDER BY open_findings DESC, a.criticality DESC
        LIMIT 10
    """)
    return render_template("report.html",
                           title="Top Exposed Assets (Open Findings)",
                           headers=["Hostname", "Environment", "Criticality", "Open Findings"],
                           rows=[(r["hostname"], r["environment"], r["criticality"], r["open_findings"]) for r in rows],
                           tables_nav=TABLES_NAV)


@app.route("/reports/compliance-by-org")
def report_compliance_org():
    rows = query("""
        SELECT o.org_name,
               COUNT(pa.action_id) AS total_actions,
               COUNT(CASE WHEN pa.status = 'Completed' THEN 1 END) AS completed,
               CASE WHEN COUNT(pa.action_id) > 0
                    THEN ROUND(COUNT(CASE WHEN pa.status = 'Completed' THEN 1 END)::NUMERIC
                               / COUNT(pa.action_id) * 100, 1)
                    ELSE 100.0 END AS compliance_pct
        FROM organizations o
        LEFT JOIN assets a ON o.org_id = a.org_id_fk
        LEFT JOIN scan_findings sf ON a.asset_id = sf.asset_id_fk
        LEFT JOIN patch_actions pa ON sf.finding_id = pa.finding_id_fk
        GROUP BY o.org_id, o.org_name
        ORDER BY compliance_pct ASC
    """)
    return render_template("report.html",
                           title="Patch Compliance Rate by Organization",
                           headers=["Organization", "Total Actions", "Completed", "Compliance %"],
                           rows=[(r["org_name"], r["total_actions"], r["completed"], r["compliance_pct"]) for r in rows],
                           tables_nav=TABLES_NAV)


@app.route("/reports/most-affected-software")
def report_most_affected_sw():
    rows = query("""
        SELECT sp.product_name, sp.vendor, sp.version,
               COUNT(DISTINCT sv.vuln_id_fk) AS vuln_count,
               COUNT(DISTINCT sf.finding_id) AS finding_count
        FROM software_products sp
        JOIN software_vulnerabilities sv ON sp.software_id = sv.software_id_fk
        LEFT JOIN scan_findings sf ON sv.sw_vuln_id = sf.sw_vuln_id_fk
        GROUP BY sp.software_id, sp.product_name, sp.vendor, sp.version
        ORDER BY vuln_count DESC, finding_count DESC
    """)
    return render_template("report.html",
                           title="Most Affected Software Products",
                           headers=["Product", "Vendor", "Version", "Known Vulns", "Findings"],
                           rows=[(r["product_name"], r["vendor"], r["version"], r["vuln_count"], r["finding_count"]) for r in rows],
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
