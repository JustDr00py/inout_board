import streamlit as st
import pandas as pd
from datetime import datetime
import json
import sqlite3
import os
import hashlib
import secrets

# Configure the page
st.set_page_config(
    page_title="Employee In/Out Board",
    page_icon="👥",
    layout="wide"
)

# Authentication database setup
AUTH_DB_PATH = "auth.db"
BOARDS_DIR = "boards"

def init_auth_database():
    """Initialize the authentication database"""
    conn = sqlite3.connect(AUTH_DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            organization TEXT,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def hash_password(password, salt=None):
    """Hash a password with salt"""
    if salt is None:
        salt = secrets.token_hex(32)
    
    password_hash = hashlib.pbkdf2_hmac('sha256', 
                                        password.encode('utf-8'), 
                                        salt.encode('utf-8'), 
                                        100000)
    return password_hash.hex(), salt

def verify_password(password, stored_hash, salt):
    """Verify a password against stored hash"""
    password_hash, _ = hash_password(password, salt)
    return password_hash == stored_hash

def register_user(username, password, organization=""):
    """Register a new user"""
    conn = sqlite3.connect(AUTH_DB_PATH)
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        conn.close()
        return False, "Username already exists"
    
    # Hash password and create user
    password_hash, salt = hash_password(password)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute('''
        INSERT INTO users (username, password_hash, salt, organization, created_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (username, password_hash, salt, organization, created_at))
    
    conn.commit()
    conn.close()
    
    # Create user's board directory
    user_board_dir = os.path.join(BOARDS_DIR, username)
    os.makedirs(user_board_dir, exist_ok=True)
    
    return True, "User registered successfully"

def authenticate_user(username, password):
    """Authenticate a user"""
    conn = sqlite3.connect(AUTH_DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT password_hash, salt FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    
    if result and verify_password(password, result[0], result[1]):
        # Update last login
        last_login = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('UPDATE users SET last_login = ? WHERE username = ?', (last_login, username))
        conn.commit()
        conn.close()
        return True
    
    conn.close()
    return False

def get_user_info(username):
    """Get user information"""
    conn = sqlite3.connect(AUTH_DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT organization, created_at, last_login FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {
            'organization': result[0] or 'No organization',
            'created_at': result[1],
            'last_login': result[2] or 'Never'
        }
    return None

# Board database functions (user-specific)
def get_user_db_path(username):
    """Get the database path for a specific user"""
    user_board_dir = os.path.join(BOARDS_DIR, username)
    os.makedirs(user_board_dir, exist_ok=True)
    return os.path.join(user_board_dir, "employee_board.db")

def init_user_database(username):
    """Initialize the user's employee database"""
    db_path = get_user_db_path(username)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS employees (
            name TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            note TEXT,
            department TEXT,
            last_updated TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()

def load_employees_from_db(username):
    """Load all employees from user's database"""
    db_path = get_user_db_path(username)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM employees')
    rows = cursor.fetchall()
    
    employees = {}
    for row in rows:
        name, status, note, department, last_updated = row
        employees[name] = {
            'status': status,
            'note': note or '',
            'department': department or '',
            'last_updated': last_updated
        }
    
    conn.close()
    return employees

def save_employee_to_db(username, name, status, note="", department=""):
    """Save or update an employee in the user's database"""
    db_path = get_user_db_path(username)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    last_updated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute('''
        INSERT OR REPLACE INTO employees (name, status, note, department, last_updated)
        VALUES (?, ?, ?, ?, ?)
    ''', (name, status, note, department, last_updated))
    
    conn.commit()
    conn.close()
    return last_updated

def remove_employee_from_db(username, name):
    """Remove an employee from the user's database"""
    db_path = get_user_db_path(username)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM employees WHERE name = ?', (name,))
    
    conn.commit()
    conn.close()

def clear_all_employees_db(username):
    """Clear all employees from the user's database"""
    db_path = get_user_db_path(username)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM employees')
    
    conn.commit()
    conn.close()

# Initialize authentication system
init_auth_database()
os.makedirs(BOARDS_DIR, exist_ok=True)

# Authentication UI
def show_login_page():
    """Show login/registration page"""
    st.title("🏢 Employee In/Out Board")
    st.markdown("*Multi-tenant employee tracking system*")
    
    tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])
    
    with tab1:
        st.header("Login to Your Board")
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            login_submit = st.form_submit_button("Login", type="primary")
            
            if login_submit:
                if username and password:
                    if authenticate_user(username, password):
                        st.session_state.authenticated = True
                        st.session_state.username = username
                        st.success(f"Welcome back, {username}!")
                        st.rerun()
                    else:
                        st.error("Invalid username or password")
                else:
                    st.error("Please enter both username and password")
    
    with tab2:
        st.header("Create New Account")
        with st.form("register_form"):
            new_username = st.text_input("Choose Username")
            new_password = st.text_input("Choose Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            organization = st.text_input("Organization/Company (optional)")
            register_submit = st.form_submit_button("Register", type="primary")
            
            if register_submit:
                if new_username and new_password and confirm_password:
                    if new_password != confirm_password:
                        st.error("Passwords do not match")
                    elif len(new_password) < 6:
                        st.error("Password must be at least 6 characters long")
                    else:
                        success, message = register_user(new_username, new_password, organization)
                        if success:
                            st.success(message)
                            st.info("You can now login with your new account!")
                        else:
                            st.error(message)
                else:
                    st.error("Please fill in all required fields")
    
    # Demo info
    st.markdown("---")
    st.info("""
    🎯 **About this app:**
    - Each user gets their own private employee board
    - Data is securely stored and isolated per user
    - Perfect for small businesses, teams, or departments
    - Track employee status: In, Out, Lunch, Meeting, WFH
    """)

def show_main_app():
    """Show the main application for authenticated users"""
    username = st.session_state.username
    user_info = get_user_info(username)
    
    # Initialize user's database
    init_user_database(username)
    
    # Initialize session state and load from user's database
    if 'employees' not in st.session_state or st.session_state.get('current_user') != username:
        st.session_state.employees = load_employees_from_db(username)
        st.session_state.current_user = username
    
    # Helper functions for current user
    def add_employee(name, status="In", note="", department=""):
        """Add a new employee to the board"""
        if name and name not in st.session_state.employees:
            last_updated = save_employee_to_db(username, name, status, note, department)
            st.session_state.employees[name] = {
                'status': status,
                'note': note,
                'department': department,
                'last_updated': last_updated
            }
            return True
        return False

    def update_employee_status(name, status, note=""):
        """Update an employee's status"""
        if name in st.session_state.employees:
            department = st.session_state.employees[name].get('department', '')
            last_updated = save_employee_to_db(username, name, status, note, department)
            
            st.session_state.employees[name]['status'] = status
            st.session_state.employees[name]['note'] = note
            st.session_state.employees[name]['last_updated'] = last_updated

    def remove_employee(name):
        """Remove an employee from the board"""
        if name in st.session_state.employees:
            remove_employee_from_db(username, name)
            del st.session_state.employees[name]

    def export_data():
        """Export current data as JSON"""
        return json.dumps(st.session_state.employees, indent=2)

    def import_data(json_str):
        """Import data from JSON string"""
        try:
            data = json.loads(json_str)
            clear_all_employees_db(username)
            st.session_state.employees = {}
            
            for name, info in data.items():
                add_employee(
                    name, 
                    info.get('status', 'In'),
                    info.get('note', ''),
                    info.get('department', '')
                )
            
            st.session_state.employees = load_employees_from_db(username)
            return True
        except Exception as e:
            st.error(f"Import error: {str(e)}")
            return False

    def refresh_from_database():
        """Refresh employee data from database"""
        st.session_state.employees = load_employees_from_db(username)

    # Header with user info and logout
    col1, col2, col3 = st.columns([3, 2, 1])
    
    with col1:
        st.title(f"🏢 {user_info['organization']} - Employee Board")
        st.caption(f"Welcome, {username}")
    
    with col2:
        st.caption(f"Last login: {user_info['last_login']}")
        st.caption(f"Member since: {user_info['created_at'][:10]}")
    
    with col3:
        if st.button("🚪 Logout", type="secondary"):
            # Clear session state
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

    st.markdown("---")

    # Sidebar for adding new employees
    with st.sidebar:
        st.header("➕ Add New Employee")
        
        with st.form("add_employee_form"):
            new_name = st.text_input("Employee Name")
            new_department = st.text_input("Department (optional)")
            new_status = st.selectbox("Initial Status", ["In", "Out", "Lunch", "Meeting", "WFH"])
            new_note = st.text_input("Note (optional)")
            
            submitted = st.form_submit_button("Add Employee")
            
            if submitted:
                if add_employee(new_name, new_status, new_note, new_department):
                    st.success(f"Added {new_name} to the board!")
                    st.rerun()
                else:
                    st.error("Employee name is required and must be unique!")
        
        st.markdown("---")
        
        # Database management
        st.header("💾 Database Management")
        
        if st.button("🔄 Refresh from Database"):
            refresh_from_database()
            st.success("Data refreshed from database!")
            st.rerun()
        
        db_path = get_user_db_path(username)
        db_size = os.path.getsize(db_path) if os.path.exists(db_path) else 0
        st.caption(f"Your database: {os.path.basename(db_path)}")
        st.caption(f"Size: {db_size} bytes")
        
        st.markdown("---")
        
        # Data management
        st.header("📊 Data Management")
        
        # Clear all data with confirmation
        if st.button("Clear All Data", type="secondary"):
            st.session_state.show_clear_confirmation = True
        
        if st.session_state.get('show_clear_confirmation', False):
            st.warning("⚠️ Are you sure you want to clear all employee data? This cannot be undone!")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Yes, Clear All", type="primary"):
                    clear_all_employees_db(username)
                    st.session_state.employees = {}
                    st.session_state.show_clear_confirmation = False
                    st.success("All data cleared!")
                    st.rerun()
            with col2:
                if st.button("Cancel"):
                    st.session_state.show_clear_confirmation = False
                    st.rerun()
        
        # Export data
        if st.session_state.employees:
            st.download_button(
                label="📤 Export Data (JSON)",
                data=export_data(),
                file_name=f"{username}_employee_board_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
        
        # Import data
        uploaded_file = st.file_uploader("📥 Import Data (JSON)", type=['json'])
        if uploaded_file:
            try:
                json_str = uploaded_file.read().decode('utf-8')
                if import_data(json_str):
                    st.success("Data imported successfully!")
                    st.rerun()
                else:
                    st.error("Invalid JSON file!")
            except Exception as e:
                st.error(f"Error reading file: {str(e)}")

    # Main content area
    if not st.session_state.employees:
        st.info("No employees added yet. Use the sidebar to add your first employee!")
        st.info("💡 All data is automatically saved to your private database and will persist between sessions.")
    else:
        # Summary stats
        col1, col2, col3, col4 = st.columns(4)
        
        total_employees = len(st.session_state.employees)
        in_count = sum(1 for emp in st.session_state.employees.values() if emp['status'] == 'In')
        out_count = sum(1 for emp in st.session_state.employees.values() if emp['status'] == 'Out')
        other_count = total_employees - in_count - out_count
        
        col1.metric("Total Employees", total_employees)
        col2.metric("In Office", in_count)
        col3.metric("Out of Office", out_count)
        col4.metric("Other Status", other_count)
        
        st.markdown("---")
        
        # Filter and search options
        st.subheader("🔍 Search & Filter Options")
        
        # Search bar
        search_col1, search_col2 = st.columns([3, 1])
        with search_col1:
            search_term = st.text_input(
                "🔎 Search employees by name",
                placeholder="Type employee name...",
                help="Search is case-insensitive and matches partial names"
            )
        with search_col2:
            if st.button("Clear Search"):
                st.rerun()
        
        filter_col1, filter_col2 = st.columns(2)
        
        with filter_col1:
            status_filter = st.multiselect(
                "Filter by Status",
                options=["In", "Out", "Lunch", "Meeting", "WFH"],
                default=["In", "Out", "Lunch", "Meeting", "WFH"]
            )
        
        with filter_col2:
            departments = list(set([emp.get('department', '') for emp in st.session_state.employees.values() if emp.get('department')]))
            if departments:
                dept_filter = st.multiselect(
                    "Filter by Department",
                    options=departments,
                    default=departments
                )
            else:
                dept_filter = []
        
        st.markdown("---")
        
        # Employee cards
        st.subheader("👥 Employee Status")
        
        # Filter and search employees
        filtered_employees = {}
        for name, info in st.session_state.employees.items():
            # Apply status filter
            if info['status'] not in status_filter:
                continue
                
            # Apply department filter
            if departments and dept_filter and info.get('department', '') not in dept_filter:
                continue
                
            # Apply search filter (case-insensitive partial match)
            if search_term and search_term.lower() not in name.lower():
                continue
                
            filtered_employees[name] = info
        
        # Show search results info
        if search_term:
            if filtered_employees:
                st.info(f"🔍 Found {len(filtered_employees)} employee(s) matching '{search_term}'")
            else:
                st.warning(f"🔍 No employees found matching '{search_term}'")
        
        if not filtered_employees:
            if search_term:
                st.info("Try adjusting your search term or filters.")
            else:
                st.info("No employees match the current filters.")
        else:
            # Create employee cards
            for i, (name, info) in enumerate(filtered_employees.items()):
                with st.container():
                    col1, col2, col3, col4, col5 = st.columns([2, 1, 2, 2, 1])
                    
                    with col1:
                        st.write(f"**{name}**")
                        if info.get('department'):
                            st.caption(f"Dept: {info['department']}")
                    
                    with col2:
                        # Status with color coding
                        status_colors = {
                            'In': '🟢',
                            'Out': '🔴',
                            'Lunch': '🟡',
                            'Meeting': '🔵',
                            'WFH': '🟣'
                        }
                        st.write(f"{status_colors.get(info['status'], '⚪')} {info['status']}")
                    
                    with col3:
                        if info.get('note'):
                            st.write(f"*{info['note']}*")
                        else:
                            st.write("*No note*")
                    
                    with col4:
                        st.caption(f"Updated: {info['last_updated']}")
                    
                    with col5:
                        # Quick status update
                        key_prefix = f"status_update_{i}_{name}"
                        
                        new_status = st.selectbox(
                            "Status",
                            ["In", "Out", "Lunch", "Meeting", "WFH"],
                            index=["In", "Out", "Lunch", "Meeting", "WFH"].index(info['status']),
                            key=f"{key_prefix}_status",
                            label_visibility="collapsed"
                        )
                        
                        if new_status != info['status']:
                            update_employee_status(name, new_status, info.get('note', ''))
                            st.rerun()
                    
                    # Expandable section for detailed updates and removal
                    with st.expander(f"Edit {name}", expanded=False):
                        edit_col1, edit_col2 = st.columns(2)
                        
                        with edit_col1:
                            new_note = st.text_input(
                                "Update Note",
                                value=info.get('note', ''),
                                key=f"{key_prefix}_note"
                            )
                            
                            if st.button(f"Update Note", key=f"{key_prefix}_update_note"):
                                update_employee_status(name, info['status'], new_note)
                                st.success(f"Updated note for {name}")
                                st.rerun()
                        
                        with edit_col2:
                            st.write("⚠️ Danger Zone")
                            if st.button(f"Remove {name}", key=f"{key_prefix}_remove", type="secondary"):
                                remove_employee(name)
                                st.success(f"Removed {name} from board")
                                st.rerun()
                    
                    st.markdown("---")

    # Footer
    st.markdown("---")
    st.markdown(f"*Employee In/Out Board - {username}'s Dashboard | Built with Streamlit*")

# Main application logic
def main():
    # Initialize session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    
    # Show appropriate page based on authentication status
    if st.session_state.authenticated:
        show_main_app()
    else:
        show_login_page()

if __name__ == "__main__":
    main()
