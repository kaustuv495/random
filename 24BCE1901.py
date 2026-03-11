import ipaddress
import random
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple
import mysql.connector
import pandas as pd
import streamlit as st
# ---------------------------------------------------------------------------
# Configuration and RBAC
# ---------------------------------------------------------------------------
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "Xyz@1234",
    "database": "AegisDefense",
    "port": 3306,
}
ROLE_SUPER_ADMIN = "super_admin"
ROLE_SECURITY_ANALYST = "security_analyst"
ROLE_NETWORK_SENSOR = "network_sensor"
DEMO_USERS = {
    "superadmin": {"password": "SuperAdmin!123", "role": ROLE_SUPER_ADMIN},
    "analyst": {"password": "Analyst!123", "role": ROLE_SECURITY_ANALYST},
    "sensor": {"password": "Sensor!123", "role": ROLE_NETWORK_SENSOR},
}
# ---------------------------------------------------------------------------
# Database connection management
# ---------------------------------------------------------------------------
@dataclass
class MySQLConnectionManager:
    """
    Singleton-style manager for MySQL connections.
    The instance is created and cached via Streamlit's ``st.cache_resource``
    decorator to avoid repeatedly opening new connections on every rerun.
    """
    host: str
    user: str
    password: str
    database: str
    port: int = 3306
    def __post_init__(self) -> None:
        """Initialize the underlying MySQL connection."""
        self._conn = mysql.connector.connect(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.database,
            port=self.port,
            autocommit=False,
        )
    @property
    def connection(self) -> mysql.connector.connection.MySQLConnection:
        """
        Return an active MySQL connection, reconnecting if necessary.
        """
        if not self._conn.is_connected():
            self._conn.reconnect(attempts=3, delay=2)
        return self._conn
    def cursor(
        self,
        dictionary: bool = False,
    ) -> mysql.connector.cursor.MySQLCursor:
        """
        Create a new cursor object from the underlying connection.
        Parameters
        ----------
        dictionary:
            Whether to return rows as dictionaries instead of tuples.
        Returns
        -------
        mysql.connector.cursor.MySQLCursor
            Configured cursor instance.
        """
        return self.connection.cursor(dictionary=dictionary)
@st.cache_resource(show_spinner=False)
def get_connection_manager() -> MySQLConnectionManager:
    try:
        # Try connecting to your real local DB
        return MySQLConnectionManager(**DB_CONFIG)
    except Exception:
        # If it fails (like on the Cloud), return a 'Mock' object so the app doesn't crash
        class MockManager:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def execute_query(self, query, params=None): return []
        return MockManager()

def execute_query(
    manager: MySQLConnectionManager,
    query: str,
    params: Optional[Iterable[Any]] = None,
    fetch: bool = False,
    dictionary: bool = False,
) -> Optional[List[Dict[str, Any]]]:
    """
    Execute a parameterized SQL query safely.
    Parameters
    ----------
    manager:
        Connection manager instance.
    query:
        SQL statement with ``%s`` placeholders.
    params:
        Iterable of parameters for the SQL statement.
    fetch:
        Whether to fetch and return results.
    dictionary:
        Whether to return rows as dictionaries instead of tuples.
    Returns
    -------
    Optional[List[Dict[str, Any]]]
        List of rows when ``fetch`` is True and ``dictionary`` is True;
        otherwise returns None.
    """
    conn = manager.connection
    cur = conn.cursor(dictionary=dictionary)
    try:
        cur.execute(query, params or ())
        if fetch:
            rows = cur.fetchall()
        else:
            rows = None
        conn.commit()
        return rows
    except Exception as exc:  # pragma: no cover - defensive
        conn.rollback()
        st.error(f"Database error: {exc}")
        return None
    finally:
        cur.close()
# ---------------------------------------------------------------------------
# Schema initialization
# ---------------------------------------------------------------------------
def initialize_schema(manager: MySQLConnectionManager) -> None:
    """
    Create the AegisDefense schema if it does not already exist.
    Tables
    ------
    - Resources
    - Signatures
    - Logs
    - Policies
    - Incidents
    - Audit
    All foreign keys are defined with ``ON DELETE CASCADE`` to preserve
    referential integrity and enable clean cascading deletions.
    """
    ddl_statements = [
        """
        CREATE TABLE IF NOT EXISTS Resources (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            ip_address VARCHAR(45) NOT NULL,
            resource_type VARCHAR(100) NOT NULL,
            status VARCHAR(50) NOT NULL DEFAULT 'Active',
            created_at TIMESTAMP NOT NULL
                DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB;
        """,
        """
        CREATE TABLE IF NOT EXISTS Signatures (
            id INT AUTO_INCREMENT PRIMARY KEY,
            signature_name VARCHAR(255) NOT NULL,
            pattern_text VARCHAR(255) NOT NULL,
            severity VARCHAR(50) NOT NULL,
            category VARCHAR(100) NOT NULL,
            created_at TIMESTAMP NOT NULL
                DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB;
        """,
        """
        CREATE TABLE IF NOT EXISTS Logs (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            resource_id INT NOT NULL,
            signature_id INT,
            log_time TIMESTAMP NOT NULL
                DEFAULT CURRENT_TIMESTAMP,
            status ENUM('Success', 'Failed') NOT NULL,
            message TEXT,
            INDEX idx_logs_resource_id (resource_id),
            INDEX idx_logs_signature_id (signature_id),
            CONSTRAINT fk_logs_resource
                FOREIGN KEY (resource_id)
                REFERENCES Resources(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_logs_signature
                FOREIGN KEY (signature_id)
                REFERENCES Signatures(id)
                ON DELETE CASCADE
        ) ENGINE=InnoDB;
        """,
        """
        CREATE TABLE IF NOT EXISTS Policies (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL
                DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NULL
        ) ENGINE=InnoDB;
        """,
        """
        CREATE TABLE IF NOT EXISTS Incidents (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            log_id BIGINT NOT NULL,
            resource_id INT NOT NULL,
            severity VARCHAR(50) NOT NULL,
            status VARCHAR(50) NOT NULL DEFAULT 'Open',
            description TEXT,
            opened_at TIMESTAMP NOT NULL
                DEFAULT CURRENT_TIMESTAMP,
            closed_at TIMESTAMP NULL,
            CONSTRAINT fk_incidents_log
                FOREIGN KEY (log_id)
                REFERENCES Logs(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_incidents_resource
                FOREIGN KEY (resource_id)
                REFERENCES Resources(id)
                ON DELETE CASCADE
        ) ENGINE=InnoDB;
        """,
        """
        CREATE TABLE IF NOT EXISTS Audit (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(150) NOT NULL,
            action VARCHAR(255) NOT NULL,
            details TEXT,
            created_at TIMESTAMP NOT NULL
                DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB;
        """,
    ]
    conn = manager.connection
    cur = conn.cursor()
    try:
        for ddl in ddl_statements:
            cur.execute(ddl)
        conn.commit()
    except Exception as exc:  # pragma: no cover - defensive
        conn.rollback()
        st.error(f"Schema initialization failed: {exc}")
    finally:
        cur.close()
def write_audit_event(
    manager: MySQLConnectionManager,
    username: str,
    action: str,
    details: str = "",
) -> None:
    """
    Persist an entry to the ``Audit`` table.
    Parameters
    ----------
    manager:
        Connection manager instance.
    username:
        Username that performed the action.
    action:
        Short description of the action.
    details:
        Longer free-text details for forensic context.
    """
    query = """
        INSERT INTO Audit (username, action, details)
        VALUES (%s, %s, %s)
    """
    execute_query(manager, query, (username, action, details), fetch=False)
# ---------------------------------------------------------------------------
# Authentication and session management
# ---------------------------------------------------------------------------
def authenticate_user(username: str, password: str) -> Optional[Dict[str, str]]:
    """
    Validate submitted credentials against the in-memory user store.
    In a production deployment, this function should be replaced with
    a lookup against a hardened identity provider or IAM system.
    """
    user = DEMO_USERS.get(username)
    if user and user["password"] == password:
        return {"username": username, "role": user["role"]}
    return None
def ensure_session_keys() -> None:
    """
    Ensure that required Streamlit session state keys exist.
    """
    defaults = {
        "authenticated": False,
        "username": None,
        "role": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value
def render_login() -> None:
    """
    Render the login form and update session state upon success.
    """
    st.title("Aegis Defense Console")
    st.subheader("Secure Login")
    with st.form("login_form", clear_on_submit=False):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
    if submitted:
        auth_result = authenticate_user(username, password)
        if auth_result:
            st.session_state["authenticated"] = True
            st.session_state["username"] = auth_result["username"]
            st.session_state["role"] = auth_result["role"]
            st.success("Authentication successful.")
            st.experimental_rerun()
        else:
            st.error("Invalid credentials.")
def logout() -> None:
    """
    Clear authentication-related keys from session state.
    """
    for key in ("authenticated", "username", "role"):
        if key in st.session_state:
            del st.session_state[key]
    st.experimental_rerun()
# ---------------------------------------------------------------------------
# Data access helpers and advanced SQL logic
# ---------------------------------------------------------------------------
def get_master_incident_table(
    manager: MySQLConnectionManager,
) -> pd.DataFrame:
    """
    Return a combined incident view joining Incidents, Logs, and Resources.
    The result provides a single master table suitable for triage and
    reporting within the SOC dashboard.
    """
    query = """
        SELECT
            i.id AS incident_id,
            i.severity AS incident_severity,
            i.status AS incident_status,
            i.opened_at,
            i.closed_at,
            i.description AS incident_description,
            l.id AS log_id,
            l.log_time,
            l.status AS log_status,
            l.message AS log_message,
            r.id AS resource_id,
            r.name AS resource_name,
            r.ip_address,
            r.resource_type,
            r.status AS resource_status
        FROM Incidents i
        INNER JOIN Logs l
            ON i.log_id = l.id
        INNER JOIN Resources r
            ON i.resource_id = r.id
        ORDER BY i.opened_at DESC
    """
    rows = execute_query(manager, query, fetch=True, dictionary=True) or []
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)
def get_system_health_percentages(
    manager: MySQLConnectionManager,
) -> Tuple[float, float]:
    """
    Compute the percentage of ``Failed`` vs ``Success`` log entries.
    Returns
    -------
    Tuple[float, float]
        A tuple of (failed_percentage, success_percentage).
    """
    query = """
        SELECT status, COUNT(*) AS count
        FROM Logs
        GROUP BY status
    """
    rows = execute_query(manager, query, fetch=True, dictionary=True) or []
    total = sum(row["count"] for row in rows)
    if total == 0:
        return 0.0, 0.0
    failed_count = next(
        (row["count"] for row in rows if row["status"] == "Failed"),
        0,
    )
    success_count = next(
        (row["count"] for row in rows if row["status"] == "Success"),
        0,
    )
    failed_pct = round((failed_count / total) * 100, 2)
    success_pct = round((success_count / total) * 100, 2)
    return failed_pct, success_pct
def get_active_threat_count(manager: MySQLConnectionManager) -> int:
    """
    Return the count of active incidents (non-closed).
    """
    query = """
        SELECT COUNT(*) AS cnt
        FROM Incidents
        WHERE status NOT IN ('Closed', 'Resolved')
    """
    rows = execute_query(manager, query, fetch=True, dictionary=True) or []
    return int(rows[0]["cnt"]) if rows else 0
def get_total_resources(manager: MySQLConnectionManager) -> int:
    """
    Return the total number of resources registered.
    """
    query = "SELECT COUNT(*) AS cnt FROM Resources"
    rows = execute_query(manager, query, fetch=True, dictionary=True) or []
    return int(rows[0]["cnt"]) if rows else 0
def get_uptime_percentage(manager: MySQLConnectionManager) -> float:
    """
    Derive an uptime-style KPI from log success ratios.
    """
    failed_pct, success_pct = get_system_health_percentages(manager)
    if failed_pct + success_pct == 0:
        return 0.0
    return success_pct
def get_threats_by_category(manager: MySQLConnectionManager) -> pd.DataFrame:
    """
    Return a breakdown of incidents by signature category.
    """
    query = """
        SELECT
            s.category AS category,
            COUNT(i.id) AS incident_count
        FROM Incidents i
        INNER JOIN Logs l ON i.log_id = l.id
        INNER JOIN Signatures s ON l.signature_id = s.id
        GROUP BY s.category
        ORDER BY incident_count DESC
    """
    rows = execute_query(manager, query, fetch=True, dictionary=True) or []
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)
def get_attack_frequency_over_time(
    manager: MySQLConnectionManager,
) -> pd.DataFrame:
    """
    Return a time series of failed log counts per day.
    """
    query = """
        SELECT
            DATE(log_time) AS log_date,
            COUNT(*) AS failed_count
        FROM Logs
        WHERE status = 'Failed'
        GROUP BY DATE(log_time)
        ORDER BY log_date ASC
    """
    rows = execute_query(manager, query, fetch=True, dictionary=True) or []
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    df.set_index("log_date", inplace=True)
    return df
# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------
def inject_midnight_security_theme() -> None:
   st.markdown("""
    <style>
        /* 1. Force a Deep Space Radial Background */
        .stApp {
            background: radial-gradient(circle at center, #0a0f1e 0%, #010409 100%) !important;
            color: #00ffc3 !important;
        }

        /* 2. Glassmorphism for the Sidebar */
        section[data-testid="stSidebar"] {
            background-color: rgba(15, 23, 42, 0.9) !important;
            backdrop-filter: blur(12px) !important;
            border-right: 1px solid rgba(0, 255, 195, 0.3) !important;
        }

        /* 3. Styled Dashboard Cards with Neon Glow */
        .metric-card {
            background: rgba(30, 41, 59, 0.6) !important;
            border: 2px solid #00ffc3 !important;
            border-radius: 15px !important;
            box-shadow: 0 0 20px rgba(0, 255, 195, 0.3) !important;
            padding: 20px !important;
            margin-bottom: 10px !important;
        }

        /* 4. Make Headers and Labels Pop */
        h1, h2, h3, .metric-label {
            color: #ffffff !important;
            text-shadow: 0 0 10px rgba(0, 255, 195, 0.7) !important;
        }
    </style>
    """, unsafe_allow_html=True)

def render_soc_dashboard(manager: MySQLConnectionManager) -> None:
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f'<div class="metric-card"><div>Threats</div><div class="metric-value">{get_active_threat_count(manager)}</div></div>', unsafe_allow_html=True);
    with col2:
        st.markdown(f'<div class="metric-card"><div>Resources</div><div class="metric-value">{get_total_resources(manager)}</div></div>', unsafe_allow_html=True);
    with col3:
        st.markdown(f'<div class="metric-card"><div>Uptime</div><div class="metric-value">{get_uptime_percentage(manager):.1f}%</div></div>', unsafe_allow_html=True);
    
def render_resource_registry(
    manager: MySQLConnectionManager,
    username: str,
) -> None:
    """
    Render a form to register new resources with input validation.
    """;
    st.header("Resource Registry")
    with st.form("resource_form"):
        name = st.text_input("Server Name", max_chars=255)
        ip = st.text_input("IP Address (IPv4 or IPv6)", max_chars=45)
        resource_type = st.selectbox(
            "Resource Type",
            ["Server", "Database", "Firewall", "Endpoint", "Application"],
        )
        status = st.selectbox("Status", ["Active", "Maintenance", "Retired"])
        submitted = st.form_submit_button("Register Resource")
    if submitted:
        if not name.strip():
            st.error("Server name is required.")
            return
        try:
            ipaddress.ip_address(ip.strip())
        except ValueError:
            st.error("Invalid IP address format.")
            return
        query = """
            INSERT INTO Resources (name, ip_address, resource_type, status)
            VALUES (%s, %s, %s, %s)
        """
        params = (name.strip(), ip.strip(), resource_type, status)
        execute_query(manager, query, params, fetch=False)
        write_audit_event(
            manager,
            username,
            "RESOURCE_REGISTERED",
            f"Registered resource '{name}' with IP {ip}.",
        )
        st.success("Resource registered successfully.")
    st.subheader("Registered Resources")
    rows = execute_query(
        manager,
        """
        SELECT id, name, ip_address, resource_type, status, created_at
        FROM Resources
        ORDER BY created_at DESC
        """,
        fetch=True,
        dictionary=True,
    ) or []
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
    else:
        st.info("No resources registered yet.")
def render_incident_management(
    manager: MySQLConnectionManager,
    username: str,
) -> None:
    """
    Render the incident management interface for analysts.
    """
    st.header("Incident Management")
    df_master = get_master_incident_table(manager)
    if df_master.empty:
        st.info("There are no incidents to manage yet.")
        return
    st.dataframe(df_master, use_container_width=True)
    st.subheader("Update Incident Status")
    incident_ids = df_master["incident_id"].tolist()
    selected_id = st.selectbox("Incident ID", incident_ids)
    new_status = st.selectbox(
        "New Status",
        ["Open", "Investigating", "Contained", "Eradicated", "Closed", "Resolved"],
    )
    if st.button("Update Incident"):
        query = """
            UPDATE Incidents
            SET status = %s,
                closed_at = CASE
                    WHEN %s IN ('Closed', 'Resolved')
                    THEN NOW()
                    ELSE closed_at
                END
            WHERE id = %s
        """
        params = (new_status, new_status, selected_id)
        execute_query(manager, query, params, fetch=False)
        write_audit_event(
            manager,
            username,
            "INCIDENT_STATUS_UPDATED",
            f"Incident {selected_id} set to {new_status}.",
        )
        st.success("Incident status updated.")
def render_policies(
    manager: MySQLConnectionManager,
    username: str,
) -> None:
    """
    Render the security governance / policy management interface.
    """
    st.header("Security Governance - Policies")
    with st.form("policy_form"):
        name = st.text_input("Policy Name", max_chars=255)
        description = st.text_area("Policy Description")
        is_active = st.checkbox("Active", value=True)
        submitted = st.form_submit_button("Create Policy")
    if submitted:
        if not name.strip() or not description.strip():
            st.error("Both name and description are required.")
        else:
            query = """
                INSERT INTO Policies (name, description, is_active)
                VALUES (%s, %s, %s)
            """
            params = (name.strip(), description.strip(), int(is_active))
            execute_query(manager, query, params, fetch=False)
            write_audit_event(
                manager,
                username,
                "POLICY_CREATED",
                f"Policy '{name}' created.",
            )
            st.success("Policy created.")
    st.subheader("Existing Policies")
    rows = execute_query(
        manager,
        """
        SELECT id, name, description, is_active, created_at, updated_at
        FROM Policies
        ORDER BY created_at DESC
        """,
        fetch=True,
        dictionary=True,
    ) or []
    if not rows:
        st.info("No policies defined yet.")
        return
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True)
    st.subheader("Toggle Policy State")
    policy_ids = df["id"].tolist()
    selected = st.selectbox("Policy ID", policy_ids)
    new_state = st.selectbox("Set Active State", [True, False])
    if st.button("Update Policy"):
        query = """
            UPDATE Policies
            SET is_active = %s,
                updated_at = NOW()
            WHERE id = %s
        """
        params = (int(new_state), selected)
        execute_query(manager, query, params, fetch=False)
        write_audit_event(
            manager,
            username,
            "POLICY_UPDATED",
            f"Policy {selected} active={new_state}.",
        )
        st.success("Policy updated.")
def render_audit_view(manager: MySQLConnectionManager) -> None:
    """
    Render a forensic audit trail view for super admins.
    """
    st.header("Forensic Audit")
    rows = execute_query(
        manager,
        """
        SELECT id, username, action, details, created_at
        FROM Audit
        ORDER BY created_at DESC
        LIMIT 500
        """,
        fetch=True,
        dictionary=True,
    ) or []
    if not rows:
        st.info("No audit records found.")
        return
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True)
def render_threat_simulator(
    manager: MySQLConnectionManager,
    username: str,
) -> None:
    """
    Render a threat simulator that generates a failed log and incident.
    """
    st.header("Threat Simulator")
    st.write(
        "Use this simulator to generate a synthetic failed log and incident "
        "for testing the automation pipeline.",
    )
    if st.button("Simulate Failed Threat Event"):
        resources = execute_query(
            manager,
            "SELECT id FROM Resources ORDER BY RAND() LIMIT 1",
            fetch=True,
            dictionary=True,
        ) or []
        if not resources:
            st.error("At least one resource is required to simulate a threat.")
            return
        resource_id = resources[0]["id"]
        # Ensure at least one signature exists
        signatures = execute_query(
            manager,
            "SELECT id FROM Signatures ORDER BY RAND() LIMIT 1",
            fetch=True,
            dictionary=True,
        ) or []
        if signatures:
            signature_id = signatures[0]["id"]
        else:
            sig_query = """
                INSERT INTO Signatures
                    (signature_name, pattern_text, severity, category)
                VALUES (%s, %s, %s, %s)
            """
            sig_params = (
                "Demo Brute Force",
                "AUTH_FAIL_*",
                "High",
                "Authentication",
            )
            execute_query(manager, sig_query, sig_params, fetch=False)
            signature_id = (
                execute_query(
                    manager,
                    "SELECT LAST_INSERT_ID() AS id",
                    fetch=True,
                    dictionary=True,
                )
                or [{"id": None}]
            )[0]["id"]
        # Insert failed log
        log_query = """
            INSERT INTO Logs (resource_id, signature_id, status, message)
            VALUES (%s, %s, %s, %s)
        """
        message = "Automated threat simulation - failed authentication burst."
        log_params = (resource_id, signature_id, "Failed", message)
        execute_query(manager, log_query, log_params, fetch=False)
        log_id = (
            execute_query(
                manager,
                "SELECT LAST_INSERT_ID() AS id",
                fetch=True,
                dictionary=True,
            )
            or [{"id": None}]
        )[0]["id"]
        # Create incident tied to the log
        severity = random.choice(["High", "Critical"])
        incident_query = """
            INSERT INTO Incidents
                (log_id, resource_id, severity, status, description)
            VALUES (%s, %s, %s, %s, %s)
        """
        incident_params = (
            log_id,
            resource_id,
            severity,
            "Open",
            "Automated incident from threat simulator.",
        )
        execute_query(manager, incident_query, incident_params, fetch=False)
        write_audit_event(
            manager,
            username,
            "THREAT_SIMULATED",
            f"Resource {resource_id}, log {log_id}, severity={severity}.",
        )
        st.success("Threat simulation executed. New log and incident created.")
def render_sensor_view(manager: MySQLConnectionManager, username: str) -> None:
    """
    Render the restricted network sensor view.
    This view intentionally exposes no analytical UI; instead it provides
    a minimal confirmation that the sensor identity is recognized and a
    controlled mechanism to inject test logs.
    """
    st.header("Network Sensor Endpoint")
    st.write(
        "This account is restricted for automated sensor ingestion only. "
        "Use programmatic calls or scheduled jobs to push telemetry into "
        "the ``Logs`` table via this identity.",
    )
    with st.expander("Manual Sensor Injection (for testing only)"):
        resource_id = st.number_input(
            "Resource ID",
            min_value=1,
            step=1,
            value=1,
        )
        message = st.text_input(
            "Raw Log Message",
            value="Sensor heartbeat - simulated event.",
        )
        status = st.selectbox("Status", ["Success", "Failed"])
        if st.button("Insert Log Event"):
            query = """
                INSERT INTO Logs (resource_id, status, message)
                VALUES (%s, %s, %s)
            """
            params = (int(resource_id), status, message)
            execute_query(manager, query, params, fetch=False)
            write_audit_event(
                manager,
                username,
                "SENSOR_LOG_INSERTED",
                f"Resource {resource_id}, status={status}.",
            )
            st.success("Log event inserted via sensor account.")
# ---------------------------------------------------------------------------
# Main application orchestration
# ---------------------------------------------------------------------------
def render_sidebar(role: str, username: str) -> str:
    """
    Render the sidebar navigation and return the selected view.
    """
    st.sidebar.title("Aegis Navigation")
    st.sidebar.write(f"Signed in as **{username}**")
    st.sidebar.write(f"Role: `{role}`")
    if st.sidebar.button("Logout"):
        logout()
    if role == ROLE_SUPER_ADMIN:
        options = [
            "SOC Dashboard",
            "Incident Management",
            "Resource Registry",
            "Security Governance",
            "Forensic Audit",
            "Threat Simulator",
        ]
    elif role == ROLE_SECURITY_ANALYST:
        options = [
            "SOC Dashboard",
            "Incident Management",
            "Resource Registry",
            "Threat Simulator",
        ]
    else:  # ROLE_NETWORK_SENSOR
        options = ["Sensor Ingestion"]
    return st.sidebar.radio("Module", options)
def run_app() -> None:
    inject_midnight_security_theme();
    """
    Main entry point to run the Streamlit application.
    """
    inject_midnight_security_theme()
    ensure_session_keys()
    manager = get_connection_manager()
    initialize_schema(manager)
    if not st.session_state["authenticated"]:
        render_login()
        return
    username = st.session_state["username"]
    role = st.session_state["role"]
    selected_view = render_sidebar(role, username)
    if role == ROLE_NETWORK_SENSOR:
        render_sensor_view(manager, username)
        return
    if selected_view == "SOC Dashboard":
        render_soc_dashboard(manager)
    elif selected_view == "Incident Management":
        render_incident_management(manager, username)
    elif selected_view == "Resource Registry":
        render_resource_registry(manager, username)
    elif selected_view == "Security Governance":
        render_policies(manager, username)
    elif selected_view == "Forensic Audit":
        render_audit_view(manager)
    elif selected_view == "Threat Simulator":
        render_threat_simulator(manager, username)
if __name__ == "__main__":
    run_app();
    

