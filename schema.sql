-- ============================================================
-- Vulnerability and Patch Tracking System
-- PostgreSQL DDL Schema
-- Pavlos Giannakis – NYU Principles of Database Systems
-- ============================================================

-- 1. organizations
CREATE TABLE organizations (
    org_id        SERIAL PRIMARY KEY,
    org_name      VARCHAR(200) NOT NULL UNIQUE,
    industry      VARCHAR(100),
    created_at    TIMESTAMP NOT NULL DEFAULT NOW()
);

-- 2. users
CREATE TABLE users (
    user_id       SERIAL PRIMARY KEY,
    org_id_fk     INTEGER NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    username      VARCHAR(100) NOT NULL UNIQUE,
    full_name     VARCHAR(200) NOT NULL,
    email         VARCHAR(200) NOT NULL,
    role          VARCHAR(50) NOT NULL DEFAULT 'analyst'
                  CHECK (role IN ('admin','analyst','engineer','viewer')),
    created_at    TIMESTAMP NOT NULL DEFAULT NOW()
);

-- 3. assets
CREATE TABLE assets (
    asset_id         SERIAL PRIMARY KEY,
    org_id_fk        INTEGER NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    hostname         VARCHAR(200) NOT NULL UNIQUE,
    asset_type       VARCHAR(100) NOT NULL,
    operating_system VARCHAR(150) NOT NULL,
    criticality      INTEGER NOT NULL CHECK (criticality BETWEEN 1 AND 5),
    environment      VARCHAR(50) NOT NULL
                     CHECK (environment IN ('Production','Staging','Development','Corporate','Lab')),
    created_at       TIMESTAMP NOT NULL DEFAULT NOW()
);

-- 4. software_products
CREATE TABLE software_products (
    software_id   SERIAL PRIMARY KEY,
    product_name  VARCHAR(200) NOT NULL,
    vendor        VARCHAR(200) NOT NULL,
    version       VARCHAR(50),
    UNIQUE (product_name, vendor, version)
);

-- 5. asset_software_installs (junction: assets <-> software_products)
CREATE TABLE asset_software_installs (
    install_id    SERIAL PRIMARY KEY,
    asset_id_fk   INTEGER NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    software_id_fk INTEGER NOT NULL REFERENCES software_products(software_id) ON DELETE CASCADE,
    install_date  DATE NOT NULL DEFAULT CURRENT_DATE,
    UNIQUE (asset_id_fk, software_id_fk)
);

-- 6. vulnerabilities
CREATE TABLE vulnerabilities (
    vuln_id       SERIAL PRIMARY KEY,
    cve_id        VARCHAR(30) UNIQUE,
    title         VARCHAR(300) NOT NULL,
    severity      VARCHAR(20) NOT NULL
                  CHECK (severity IN ('Critical','High','Medium','Low','Info')),
    cvss_score    NUMERIC(3,1) CHECK (cvss_score BETWEEN 0.0 AND 10.0),
    published_date DATE,
    description   TEXT
);

-- 7. software_vulnerabilities (junction: software_products <-> vulnerabilities)
CREATE TABLE software_vulnerabilities (
    sw_vuln_id    SERIAL PRIMARY KEY,
    software_id_fk INTEGER NOT NULL REFERENCES software_products(software_id) ON DELETE CASCADE,
    vuln_id_fk    INTEGER NOT NULL REFERENCES vulnerabilities(vuln_id) ON DELETE CASCADE,
    UNIQUE (software_id_fk, vuln_id_fk)
);

-- 8. scan_findings
CREATE TABLE scan_findings (
    finding_id    SERIAL PRIMARY KEY,
    asset_id_fk   INTEGER NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    sw_vuln_id_fk INTEGER NOT NULL REFERENCES software_vulnerabilities(sw_vuln_id) ON DELETE CASCADE,
    status        VARCHAR(30) NOT NULL DEFAULT 'Open'
                  CHECK (status IN ('Open','In Progress','Remediated','Accepted Risk','False Positive')),
    discovered_at TIMESTAMP NOT NULL DEFAULT NOW(),
    notes         TEXT
);

-- 9. patch_actions
CREATE TABLE patch_actions (
    action_id     SERIAL PRIMARY KEY,
    finding_id_fk INTEGER NOT NULL REFERENCES scan_findings(finding_id) ON DELETE CASCADE,
    assigned_to_fk INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    action_type   VARCHAR(50) NOT NULL DEFAULT 'Patch'
                  CHECK (action_type IN ('Patch','Workaround','Accept Risk','Mitigate')),
    status        VARCHAR(30) NOT NULL DEFAULT 'Pending'
                  CHECK (status IN ('Pending','In Progress','Completed','Failed','Cancelled')),
    due_date      DATE,
    completed_at  TIMESTAMP,
    created_at    TIMESTAMP NOT NULL DEFAULT NOW()
);

-- 10. patch_status_history
CREATE TABLE patch_status_history (
    history_id    SERIAL PRIMARY KEY,
    action_id_fk  INTEGER NOT NULL REFERENCES patch_actions(action_id) ON DELETE CASCADE,
    old_status    VARCHAR(30),
    new_status    VARCHAR(30) NOT NULL,
    changed_by_fk INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    changed_at    TIMESTAMP NOT NULL DEFAULT NOW(),
    note          TEXT
);


-- ============================================================
-- VIEWS
-- ============================================================

-- View 1: Asset Exposure Summary
-- Shows each asset with count of open findings by severity
CREATE OR REPLACE VIEW vw_asset_exposure_summary AS
SELECT
    a.asset_id,
    a.hostname,
    a.asset_type,
    a.environment,
    a.criticality,
    o.org_name,
    COUNT(sf.finding_id) AS total_open_findings,
    COUNT(CASE WHEN v.severity = 'Critical' THEN 1 END) AS critical_count,
    COUNT(CASE WHEN v.severity = 'High' THEN 1 END) AS high_count,
    COUNT(CASE WHEN v.severity = 'Medium' THEN 1 END) AS medium_count,
    COUNT(CASE WHEN v.severity = 'Low' THEN 1 END) AS low_count
FROM assets a
JOIN organizations o ON a.org_id_fk = o.org_id
LEFT JOIN scan_findings sf ON a.asset_id = sf.asset_id_fk AND sf.status = 'Open'
LEFT JOIN software_vulnerabilities sv ON sf.sw_vuln_id_fk = sv.sw_vuln_id
LEFT JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
GROUP BY a.asset_id, a.hostname, a.asset_type, a.environment, a.criticality, o.org_name;

-- View 2: Patch Compliance Status
-- Shows each patch action with full context (asset, vulnerability, assignee)
CREATE OR REPLACE VIEW vw_patch_compliance_status AS
SELECT
    pa.action_id,
    a.hostname,
    v.cve_id,
    v.title AS vuln_title,
    v.severity,
    pa.action_type,
    pa.status AS action_status,
    pa.due_date,
    pa.completed_at,
    u.full_name AS assigned_to,
    sf.status AS finding_status,
    CASE
        WHEN pa.status = 'Completed' THEN 'Compliant'
        WHEN pa.due_date < CURRENT_DATE AND pa.status NOT IN ('Completed','Cancelled') THEN 'Overdue'
        ELSE 'In Progress'
    END AS compliance_state
FROM patch_actions pa
JOIN scan_findings sf ON pa.finding_id_fk = sf.finding_id
JOIN software_vulnerabilities sv ON sf.sw_vuln_id_fk = sv.sw_vuln_id
JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
JOIN assets a ON sf.asset_id_fk = a.asset_id
LEFT JOIN users u ON pa.assigned_to_fk = u.user_id;


-- ============================================================
-- FUNCTIONS
-- ============================================================

-- Function 1: Calculate risk score for an asset
-- Weights: Critical=10, High=6, Medium=3, Low=1, multiplied by asset criticality
CREATE OR REPLACE FUNCTION fn_asset_risk_score(p_asset_id INTEGER)
RETURNS NUMERIC AS $$
DECLARE
    risk NUMERIC := 0;
    asset_crit INTEGER;
BEGIN
    SELECT criticality INTO asset_crit FROM assets WHERE asset_id = p_asset_id;
    IF asset_crit IS NULL THEN RETURN 0; END IF;

    SELECT COALESCE(SUM(
        CASE v.severity
            WHEN 'Critical' THEN 10
            WHEN 'High' THEN 6
            WHEN 'Medium' THEN 3
            WHEN 'Low' THEN 1
            ELSE 0
        END
    ), 0) INTO risk
    FROM scan_findings sf
    JOIN software_vulnerabilities sv ON sf.sw_vuln_id_fk = sv.sw_vuln_id
    JOIN vulnerabilities v ON sv.vuln_id_fk = v.vuln_id
    WHERE sf.asset_id_fk = p_asset_id AND sf.status = 'Open';

    RETURN risk * asset_crit;
END;
$$ LANGUAGE plpgsql;

-- Function 2: Patch compliance rate for an organization (returns percentage)
CREATE OR REPLACE FUNCTION fn_patch_compliance_rate(p_org_id INTEGER)
RETURNS NUMERIC AS $$
DECLARE
    total_actions INTEGER;
    completed_actions INTEGER;
BEGIN
    SELECT COUNT(*), COUNT(CASE WHEN pa.status = 'Completed' THEN 1 END)
    INTO total_actions, completed_actions
    FROM patch_actions pa
    JOIN scan_findings sf ON pa.finding_id_fk = sf.finding_id
    JOIN assets a ON sf.asset_id_fk = a.asset_id
    WHERE a.org_id_fk = p_org_id;

    IF total_actions = 0 THEN RETURN 100.0; END IF;
    RETURN ROUND((completed_actions::NUMERIC / total_actions) * 100, 1);
END;
$$ LANGUAGE plpgsql;


-- ============================================================
-- STORED PROCEDURES
-- ============================================================

-- Procedure 1: Record a scan finding
-- Checks for duplicate (same asset + sw_vuln combo still open), prevents double-entry
CREATE OR REPLACE PROCEDURE sp_record_scan_finding(
    p_asset_id INTEGER,
    p_sw_vuln_id INTEGER,
    p_notes TEXT DEFAULT NULL
)
LANGUAGE plpgsql AS $$
DECLARE
    existing INTEGER;
BEGIN
    SELECT finding_id INTO existing
    FROM scan_findings
    WHERE asset_id_fk = p_asset_id
      AND sw_vuln_id_fk = p_sw_vuln_id
      AND status = 'Open'
    LIMIT 1;

    IF existing IS NOT NULL THEN
        RAISE NOTICE 'Finding already exists (finding_id=%). Skipping.', existing;
        RETURN;
    END IF;

    INSERT INTO scan_findings (asset_id_fk, sw_vuln_id_fk, status, notes)
    VALUES (p_asset_id, p_sw_vuln_id, 'Open', p_notes);
END;
$$;

-- Procedure 2: Initiate a patch action with initial status history
-- Creates the patch_action and inserts the first history row in one transaction
CREATE OR REPLACE PROCEDURE sp_initiate_patch_action(
    p_finding_id INTEGER,
    p_assigned_to INTEGER,
    p_action_type VARCHAR(50) DEFAULT 'Patch',
    p_due_date DATE DEFAULT NULL
)
LANGUAGE plpgsql AS $$
DECLARE
    new_action_id INTEGER;
BEGIN
    INSERT INTO patch_actions (finding_id_fk, assigned_to_fk, action_type, status, due_date)
    VALUES (p_finding_id, p_assigned_to, p_action_type, 'Pending', p_due_date)
    RETURNING action_id INTO new_action_id;

    INSERT INTO patch_status_history (action_id_fk, old_status, new_status, changed_by_fk, note)
    VALUES (new_action_id, NULL, 'Pending', p_assigned_to, 'Patch action initiated');

    -- Update the finding status to In Progress
    UPDATE scan_findings SET status = 'In Progress'
    WHERE finding_id = p_finding_id AND status = 'Open';
END;
$$;


-- ============================================================
-- TRIGGERS
-- ============================================================

-- Trigger 1: Auto-insert into patch_status_history when patch_actions.status changes
CREATE OR REPLACE FUNCTION trg_fn_patch_status_audit()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status IS DISTINCT FROM NEW.status THEN
        INSERT INTO patch_status_history (action_id_fk, old_status, new_status, changed_by_fk, note)
        VALUES (NEW.action_id, OLD.status, NEW.status, NEW.assigned_to_fk, 'Status changed via update');
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_patch_status_audit
AFTER UPDATE ON patch_actions
FOR EACH ROW
EXECUTE FUNCTION trg_fn_patch_status_audit();

-- Trigger 2: Auto-set discovered_at timestamp on scan_findings insert
CREATE OR REPLACE FUNCTION trg_fn_set_finding_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.discovered_at IS NULL THEN
        NEW.discovered_at := NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_set_finding_timestamp
BEFORE INSERT ON scan_findings
FOR EACH ROW
EXECUTE FUNCTION trg_fn_set_finding_timestamp();


-- ============================================================
-- SEED DATA
-- ============================================================

-- Organizations
INSERT INTO organizations (org_name, industry) VALUES
('Acme Corp', 'Technology'),
('SecureBank Inc', 'Financial Services'),
('HealthFirst LLC', 'Healthcare');

-- Users
INSERT INTO users (org_id_fk, username, full_name, email, role) VALUES
(1, 'jdoe', 'John Doe', 'jdoe@acme.com', 'admin'),
(1, 'asmith', 'Alice Smith', 'asmith@acme.com', 'engineer'),
(2, 'bwilson', 'Bob Wilson', 'bwilson@securebank.com', 'analyst'),
(3, 'cjones', 'Carol Jones', 'cjones@healthfirst.com', 'engineer');

-- Assets
INSERT INTO assets (org_id_fk, hostname, asset_type, operating_system, criticality, environment) VALUES
(1, 'web-prod-01', 'Web Server', 'Ubuntu 22.04', 5, 'Production'),
(1, 'db-prod-01', 'Database Server', 'Ubuntu 20.04', 5, 'Production'),
(1, 'dev-vm-03', 'Virtual Machine', 'Ubuntu 22.04', 2, 'Development'),
(2, 'core-banking-01', 'Application Server', 'RHEL 9', 5, 'Production'),
(2, 'atm-gw-01', 'Gateway', 'Windows Server 2022', 4, 'Production'),
(3, 'ehr-app-01', 'Application Server', 'Windows Server 2022', 5, 'Production'),
(3, 'laptop-nurse-12', 'Laptop', 'Windows 11', 3, 'Corporate');

-- Software Products
INSERT INTO software_products (product_name, vendor, version) VALUES
('Apache HTTP Server', 'Apache Foundation', '2.4.54'),
('OpenSSL', 'OpenSSL Project', '1.1.1'),
('PostgreSQL', 'PostgreSQL Global', '14.5'),
('Microsoft SQL Server', 'Microsoft', '2019'),
('Nginx', 'F5 Networks', '1.22.0'),
('Log4j', 'Apache Foundation', '2.14.1');

-- Asset-Software Installs
INSERT INTO asset_software_installs (asset_id_fk, software_id_fk, install_date) VALUES
(1, 1, '2024-06-15'), -- web-prod-01 has Apache
(1, 2, '2024-06-15'), -- web-prod-01 has OpenSSL
(2, 3, '2024-07-01'), -- db-prod-01 has PostgreSQL
(2, 2, '2024-07-01'), -- db-prod-01 has OpenSSL
(3, 5, '2025-01-10'), -- dev-vm-03 has Nginx
(4, 4, '2024-03-20'), -- core-banking-01 has MSSQL
(4, 6, '2024-03-20'), -- core-banking-01 has Log4j
(5, 2, '2024-05-10'), -- atm-gw-01 has OpenSSL
(6, 4, '2024-08-01'), -- ehr-app-01 has MSSQL
(7, 2, '2025-02-01'); -- laptop-nurse-12 has OpenSSL

-- Vulnerabilities
INSERT INTO vulnerabilities (cve_id, title, severity, cvss_score, published_date, description) VALUES
('CVE-2021-44228', 'Log4Shell Remote Code Execution', 'Critical', 10.0, '2021-12-10', 'Remote code execution in Apache Log4j 2.x via JNDI lookup.'),
('CVE-2022-0778', 'OpenSSL Infinite Loop DoS', 'High', 7.5, '2022-03-15', 'Denial of service via crafted certificate in OpenSSL.'),
('CVE-2023-44487', 'HTTP/2 Rapid Reset Attack', 'High', 7.5, '2023-10-10', 'DDoS amplification via HTTP/2 rapid reset.'),
('CVE-2024-21626', 'Container Escape via runc', 'High', 8.6, '2024-01-31', 'Container escape vulnerability in runc.'),
('CVE-2023-31047', 'Apache Path Traversal', 'Medium', 5.3, '2023-06-01', 'Path traversal in Apache HTTP Server mod_rewrite.'),
('CVE-2022-24735', 'PostgreSQL Privilege Escalation', 'Medium', 6.5, '2022-04-27', 'Privilege escalation via crafted SQL in PostgreSQL.');

-- Software-Vulnerability mappings
INSERT INTO software_vulnerabilities (software_id_fk, vuln_id_fk) VALUES
(6, 1), -- Log4j -> Log4Shell
(2, 2), -- OpenSSL -> Infinite Loop
(1, 3), -- Apache -> HTTP/2 Rapid Reset
(1, 5), -- Apache -> Path Traversal
(3, 6), -- PostgreSQL -> Privilege Escalation
(5, 3); -- Nginx -> HTTP/2 Rapid Reset

-- Scan Findings
INSERT INTO scan_findings (asset_id_fk, sw_vuln_id_fk, status, discovered_at, notes) VALUES
(4, 1, 'Open', '2025-11-15 10:30:00', 'Log4Shell detected on core banking server'),
(1, 2, 'Open', '2025-11-20 09:00:00', 'OpenSSL DoS vulnerability on web server'),
(2, 2, 'Remediated', '2025-11-20 09:15:00', 'OpenSSL patched on db server'),
(1, 3, 'Open', '2025-12-01 14:00:00', 'HTTP/2 rapid reset on Apache'),
(1, 4, 'In Progress', '2025-12-01 14:00:00', 'Apache path traversal being patched'),
(2, 5, 'Open', '2026-01-05 11:00:00', 'PostgreSQL privilege escalation found'),
(5, 2, 'Accepted Risk', '2025-12-10 16:00:00', 'OpenSSL on ATM gateway - accepted risk due to network isolation'),
(3, 6, 'Open', '2026-02-01 08:00:00', 'HTTP/2 on dev Nginx');

-- Patch Actions
INSERT INTO patch_actions (finding_id_fk, assigned_to_fk, action_type, status, due_date, completed_at) VALUES
(1, 2, 'Patch', 'In Progress', '2026-01-15', NULL),
(2, 2, 'Patch', 'Pending', '2026-01-20', NULL),
(3, 2, 'Patch', 'Completed', '2025-12-15', '2025-12-14 17:30:00'),
(4, 2, 'Workaround', 'Pending', '2026-02-01', NULL),
(5, 2, 'Patch', 'In Progress', '2026-01-25', NULL),
(6, 3, 'Patch', 'Pending', '2026-02-10', NULL),
(7, NULL, 'Accept Risk', 'Completed', NULL, '2025-12-10 16:30:00');

-- Patch Status History
INSERT INTO patch_status_history (action_id_fk, old_status, new_status, changed_by_fk, changed_at, note) VALUES
(1, NULL, 'Pending', 2, '2025-11-16 09:00:00', 'Action created'),
(1, 'Pending', 'In Progress', 2, '2025-12-01 10:00:00', 'Engineer started work on Log4j patch'),
(3, NULL, 'Pending', 2, '2025-11-21 08:00:00', 'Action created for db-prod-01 OpenSSL'),
(3, 'Pending', 'In Progress', 2, '2025-12-10 09:00:00', 'Applying patch'),
(3, 'In Progress', 'Completed', 2, '2025-12-14 17:30:00', 'Patch verified and deployed'),
(5, NULL, 'Pending', 2, '2025-12-02 08:00:00', 'Action created'),
(5, 'Pending', 'In Progress', 2, '2026-01-10 09:00:00', 'Work started on path traversal fix'),
(7, NULL, 'Pending', NULL, '2025-12-10 16:00:00', 'Risk acceptance documented'),
(7, 'Pending', 'Completed', NULL, '2025-12-10 16:30:00', 'Approved by security team');
