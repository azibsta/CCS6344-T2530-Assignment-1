from flask import Flask, render_template, request, redirect, session, url_for, flash
import pyodbc
import hashlib
import os
import re
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'secure_assignment_key_final'

# --- DATABASE CONNECTION & RLS ---
def get_db():
    # -------------------------------------------------------------------------
    # IMPORTANT: Change 'SERVER=localhost' to your actual server name if needed
    # Example: 'SERVER=DESKTOP-ABC1234\SQLEXPRESS;'
    # -------------------------------------------------------------------------
    conn = pyodbc.connect(
        'DRIVER={ODBC Driver 18 for SQL Server};'
        'SERVER=localhost;'  
        'DATABASE=StudentProjectDB;'
        'Trusted_Connection=yes;'
        'TrustServerCertificate=yes;'
    )
    
    # --- ROW-LEVEL SECURITY (RLS) INJECTION ---
    if 'user_id' in session and 'role' in session:
        cursor = conn.cursor()
        cursor.execute("EXEC sp_set_session_context @key=N'UserID', @value=?", (session['user_id'],))
        cursor.execute("EXEC sp_set_session_context @key=N'RoleID', @value=?", (session['role'],))
        cursor.close()
        
    return conn

# --- SECURITY UTILITIES ---
def hash_password(password, salt=None):
    if not salt:
        salt = os.urandom(16).hex()
    pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return pwd_hash, salt

def is_password_complex(password):
    if len(password) < 8: return False
    if not re.search(r"[A-Z]", password): return False # At least 1 Uppercase
    if not re.search(r"[0-9]", password): return False # At least 1 Number
    if not re.search(r"[!@#$%^&*]", password): return False # At least 1 Symbol
    return True

def is_login_allowed():
    current_hour = datetime.now().hour
    if 3 <= current_hour < 5:
        return False
    return True

# --- CONTEXT PROCESSOR ---
@app.context_processor
def inject_globals():
    if 'user_id' not in session: return {}
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM App.Notifications WHERE UserID = ? AND IsRead = 0", (session['user_id'],))
        count = cursor.fetchone()[0]
        conn.close()
        return {'notif_count': count, 'role': session.get('role'), 'username': session.get('username')}
    except:
        return {}

# --- ROUTES ---

@app.route('/')
def home():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not is_login_allowed():
            flash("Maintenance Mode: Logins disabled (3AM-5AM).")
            return render_template('login.html')

        username = request.form['username']
        password = request.form['password']
        
        print(f"DEBUG: Attempting login for: {username}") 

        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute("{CALL Sec.sp_GetDecryptedUser (?)}", (username,))
            user = cursor.fetchone()
        except Exception as e:
            print(f"DEBUG: Database Error: {e}") 
            flash("Database Error: Check Server Connection in app.py")
            return render_template('login.html')
        
        if user:
            print(f"DEBUG: User found in DB. ID={user[0]}, Role={user[3]}")
            
            stored_hash = user[1]
            stored_salt = user[2]
            
            calculated_hash = hash_password(password, stored_salt)[0]
            
            if calculated_hash == stored_hash:
                print("DEBUG: Password Verified! Logging in...")
                session['user_id'] = user[0]
                session['role'] = user[3]
                session['username'] = username 
                
                cursor.execute("INSERT INTO Sec.AuditLog (ActionType, UserIP, Details) VALUES (?, ?, ?)", 
                               ('LOGIN_SUCCESS', request.remote_addr, f"User {username} logged in"))
                conn.commit()
                conn.close()
                return redirect(url_for('dashboard'))
            else:
                print("DEBUG: Password Mismatch.")
        else:
            print("DEBUG: User not found in database.")

        flash("Invalid Credentials.")
        conn.close()
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not request.form.get('consent'):
            flash("You must agree to PDPA processing.")
            return render_template('register.html')
        
        if not is_password_complex(request.form['password']):
            flash("Password too weak! (Min 8 chars, Uppercase, Number, Symbol)")
            return render_template('register.html')

        uname = request.form['username']
        pword = request.form['password']
        email = request.form['email']
        phone = request.form['phone']
        role = request.form['role']

        pwd_hash, salt = hash_password(pword)
        
        try:
            conn = get_db()
            conn.cursor().execute("{CALL Sec.sp_RegisterUser (?, ?, ?, ?, ?, ?)}", 
                                  (uname, pwd_hash, salt, email, phone, role))
            conn.commit()
            conn.close()
            flash("Registration Successful! Please Login.")
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Register Error: {e}")
            flash("Error: Username likely already exists.")
            
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('home'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT ConfigValue FROM Sec.SystemConfig WHERE ConfigKey = 'AllowUploads'")
    uploads_allowed = cursor.fetchone()[0]
    
    projects = []
    audit_logs = []
    milestones = {}

    if session['role'] == 3: 
        cursor.execute("SELECT * FROM App.Assignments WHERE SubmittedBy = ?", (session['user_id'],))
    else: 
        cursor.execute("SELECT A.*, U.Username FROM App.Assignments A JOIN App.Users U ON A.SubmittedBy = U.UserID")
    
    projects = cursor.fetchall()

    if session['role'] == 1:
        cursor.execute("SELECT TOP 15 * FROM Sec.AuditLog ORDER BY Timestamp DESC")
        audit_logs = cursor.fetchall()

    for p in projects:
        pid = p[0]
        cursor.execute("SELECT MilestoneID, TaskName, IsCompleted FROM App.Milestones WHERE AssignmentID = ?", (pid,))
        milestones[pid] = cursor.fetchall()

    conn.close()
    return render_template('dashboard.html', projects=projects, audit_logs=audit_logs, 
                           milestones=milestones, uploads_allowed=uploads_allowed)

@app.route('/submit', methods=['POST'])
def submit():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT ConfigValue FROM Sec.SystemConfig WHERE ConfigKey = 'AllowUploads'")
    if cursor.fetchone()[0] == 'FALSE':
        flash("Submissions currently disabled by Admin.")
    else:
        cursor.execute("INSERT INTO App.Assignments (ProjectTitle, Description, GitHubLink, SubmittedBy) VALUES (?, ?, ?, ?)", 
                       (request.form['title'], request.form['desc'], request.form['link'], session['user_id']))
        conn.commit()
        flash("Project Submitted.")
        
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:id>')
def delete_project(id):
    if session.get('role') in [1, 2]: 
        conn = get_db()
        conn.cursor().execute("DELETE FROM App.Assignments WHERE AssignmentID = ?", (id,))
        conn.commit()
        conn.close()
        flash("Project Deleted (Logged in Audit Trail).")
    return redirect(url_for('dashboard'))

@app.route('/toggle_security')
def toggle_security():
    if session.get('role') == 1: 
        conn = get_db()
        conn.cursor().execute("UPDATE Sec.SystemConfig SET ConfigValue = CASE WHEN ConfigValue = 'TRUE' THEN 'FALSE' ELSE 'TRUE' END WHERE ConfigKey = 'AllowUploads'")
        conn.commit()
        conn.close()
    return redirect(url_for('dashboard'))

# --- EXTRA FEATURES: Milestones, Notifications, Feedback ---

@app.route('/add_milestone', methods=['POST'])
def add_milestone():
    conn = get_db()
    conn.cursor().execute("INSERT INTO App.Milestones (AssignmentID, TaskName) VALUES (?, ?)", 
                          (request.form['assign_id'], request.form['task']))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/toggle_milestone/<int:mid>')
def toggle_milestone(mid):
    conn = get_db()
    conn.cursor().execute("UPDATE App.Milestones SET IsCompleted = 1 - IsCompleted WHERE MilestoneID = ?", (mid,))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/notifications')
def notifications():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT Message, DateCreated FROM App.Notifications WHERE UserID = ? ORDER BY DateCreated DESC", (session['user_id'],))
    data = cursor.fetchall()
    cursor.execute("UPDATE App.Notifications SET IsRead = 1 WHERE UserID = ?", (session['user_id'],))
    conn.commit()
    conn.close()
    return render_template('notifications.html', notifications=data)

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        conn = get_db()
        conn.cursor().execute("INSERT INTO App.Feedback (SubmittedBy, IssueType, Message) VALUES (?, ?, ?)", 
                              (session['user_id'], request.form['type'], request.form['msg']))
        conn.commit()
        conn.close()
        flash("Feedback Sent.")
        return redirect(url_for('dashboard'))
    return render_template('feedback.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)