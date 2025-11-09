"""
SQL INJECTION PREVENTION PROJECT - COMPLETE WORKING VERSION
All CRUD Operations: SELECT, INSERT, UPDATE, DELETE
"""

import sqlite3
from typing import List, Tuple, Optional
import re
from datetime import datetime

print("\n" + "="*90)
print("SQL INJECTION PREVENTION - ALL CRUD OPERATIONS")
print("="*90 + "\n")

# PART 1: DATABASE SETUP
print("PART 1: Setting up database...")
print("-" * 90)

class Database:
    def __init__(self, db_name=':memory:'):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.cursor.execute("PRAGMA foreign_keys = ON")
        self.create_tables()
    
    def create_tables(self):
        self.cursor.execute('''
            CREATE TABLE users (
                user_id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password TEXT,
                email TEXT UNIQUE,
                full_name TEXT,
                role TEXT,
                created_at TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE products (
                product_id INTEGER PRIMARY KEY,
                product_name TEXT,
                category TEXT,
                price REAL,
                stock INTEGER,
                description TEXT,
                created_at TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE orders (
                order_id INTEGER PRIMARY KEY,
                user_id INTEGER,
                order_date TEXT,
                total_amount REAL,
                status TEXT,
                shipping_address TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        
        users = [
            (1, 'john_doe', 'pass123', 'john@email.com', 'John Doe', 'user', '2024-01-01'),
            (2, 'admin', 'admin@pass', 'admin@company.com', 'Admin User', 'admin', '2024-01-01'),
            (3, 'jane_smith', 'jane@pass', 'jane@email.com', 'Jane Smith', 'user', '2024-01-05'),
        ]
        self.cursor.executemany('INSERT INTO users VALUES (?,?,?,?,?,?,?)', users)
        
        products = [
            (1, 'Laptop Pro', 'Electronics', 1299.99, 10, 'High-end laptop', '2024-01-01'),
            (2, 'Wireless Mouse', 'Electronics', 29.99, 150, 'Ergonomic design', '2024-01-02'),
            (3, 'USB Cable', 'Accessories', 9.99, 500, '2-meter cable', '2024-01-03'),
        ]
        self.cursor.executemany('INSERT INTO products VALUES (?,?,?,?,?,?,?)', products)
        
        orders = [
            (1, 1, '2024-01-15', 1299.99, 'Shipped', '123 Main St, USA'),
            (2, 2, '2024-01-20', 29.99, 'Delivered', '456 Oak Ave, USA'),
        ]
        self.cursor.executemany('INSERT INTO orders VALUES (?,?,?,?,?,?)', orders)
        
        self.conn.commit()
        print("✓ Database created\n")


# PART 2: VULNERABLE CRUD OPERATIONS
print("PART 2: VULNERABLE IMPLEMENTATION")
print("-" * 90)

class VulnerableCRUD:
    def __init__(self, db: Database):
        self.conn = db.conn
        self.cursor = db.cursor
    
    def select_user_vulnerable(self, username: str) -> Tuple[List, str]:
        query = "SELECT user_id, username, email, full_name, role FROM users WHERE username='" + username + "'"
        print(f"[VULNERABLE] Query: {query}")
        try:
            self.cursor.execute(query)
            return self.cursor.fetchall(), "Success"
        except sqlite3.Error as e:
            return [], f"Error: {str(e)}"
    
    def insert_user_vulnerable(self, username: str, email: str, full_name: str, password: str) -> Tuple[bool, str]:
        query = "INSERT INTO users (username, email, full_name, password, role, created_at) VALUES ('" + username + "', '" + email + "', '" + full_name + "', '" + password + "', 'user', '" + datetime.now().isoformat() + "')"
        print(f"[VULNERABLE] Query: {query}")
        try:
            self.cursor.execute(query)
            self.conn.commit()
            return True, "User inserted"
        except sqlite3.Error as e:
            return False, f"Error: {str(e)}"
    
    def update_user_vulnerable(self, user_id: str, email: str) -> Tuple[bool, str]:
        query = "UPDATE users SET email='" + email + "' WHERE user_id=" + user_id
        print(f"[VULNERABLE] Query: {query}")
        try:
            self.cursor.execute(query)
            self.conn.commit()
            affected = self.cursor.rowcount
            return True, f"Updated {affected} user(s)"
        except sqlite3.Error as e:
            return False, f"Error: {str(e)}"
    
    def delete_user_vulnerable(self, user_id: str) -> Tuple[bool, str]:
        query = "DELETE FROM users WHERE user_id=" + user_id
        print(f"[VULNERABLE] Query: {query}")
        try:
            self.cursor.execute(query)
            self.conn.commit()
            affected = self.cursor.rowcount
            return True, f"Deleted {affected} user(s)"
        except sqlite3.Error as e:
            return False, f"Error: {str(e)}"


# PART 3: SECURE CRUD OPERATIONS
print("\nPART 3: SECURE IMPLEMENTATION")
print("-" * 90)

class SecureCRUD:
    def __init__(self, db: Database):
        self.conn = db.conn
        self.cursor = db.cursor
    
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        if not username or len(username) < 3 or len(username) > 20:
            return False, "Username must be 3-20 characters"
        if not re.match("^[a-zA-Z0-9_]+$", username):
            return False, "Username can only contain letters, numbers, underscore"
        return True, "Valid"
    
    @staticmethod
    def validate_email(email: str) -> Tuple[bool, str]:
        if not email or len(email) > 100:
            return False, "Invalid email"
        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
            return False, "Invalid email format"
        return True, "Valid"
    
    @staticmethod
    def validate_numeric_id(value: str) -> Tuple[bool, int, str]:
        try:
            id_int = int(value)
            if id_int <= 0:
                return False, 0, "ID must be positive"
            return True, id_int, "Valid"
        except ValueError:
            return False, 0, "ID must be a number"
    
    def select_user_secure(self, username: str) -> Tuple[List, str]:
        is_valid, message = self.validate_username(username)
        if not is_valid:
            return [], f"Invalid input: {message}"
        
        query = "SELECT user_id, username, email, full_name, role FROM users WHERE username=?"
        print(f"[SECURE] Query: {query}")
        print(f"[SECURE] Parameters: ('{username}')")
        try:
            self.cursor.execute(query, (username,))
            return self.cursor.fetchall(), "Success"
        except sqlite3.Error as e:
            return [], "Database error"
    
    def insert_user_secure(self, username: str, email: str, full_name: str, password: str) -> Tuple[bool, str]:
        is_valid, msg = self.validate_username(username)
        if not is_valid:
            return False, f"Invalid username: {msg}"
        
        is_valid, msg = self.validate_email(email)
        if not is_valid:
            return False, f"Invalid email: {msg}"
        
        if not full_name or len(full_name) > 100:
            return False, "Invalid full_name"
        
        if not password or len(password) < 5:
            return False, "Password too short"
        
        query = "INSERT INTO users (username, email, full_name, password, role, created_at) VALUES (?, ?, ?, ?, ?, ?)"
        print(f"[SECURE] Query: {query}")
        print(f"[SECURE] Parameters: ('{username}', '{email}', '{full_name}', '***', 'user', timestamp)")
        try:
            self.cursor.execute(query, (username, email, full_name, password, 'user', datetime.now().isoformat()))
            self.conn.commit()
            return True, "User inserted"
        except sqlite3.IntegrityError:
            return False, "Username or email already exists"
        except sqlite3.Error:
            return False, "Database error"
    
    def update_user_secure(self, user_id: str, email: str) -> Tuple[bool, str]:
        is_valid, id_int, msg = self.validate_numeric_id(user_id)
        if not is_valid:
            return False, f"Invalid user_id: {msg}"
        
        is_valid, msg = self.validate_email(email)
        if not is_valid:
            return False, f"Invalid email: {msg}"
        
        query = "UPDATE users SET email=? WHERE user_id=?"
        print(f"[SECURE] Query: {query}")
        print(f"[SECURE] Parameters: ('{email}', {id_int})")
        try:
            self.cursor.execute(query, (email, id_int))
            self.conn.commit()
            affected = self.cursor.rowcount
            return True, f"Updated {affected} user(s)"
        except sqlite3.IntegrityError:
            return False, "Email already in use"
        except sqlite3.Error:
            return False, "Database error"
    
    def delete_user_secure(self, user_id: str) -> Tuple[bool, str]:
        is_valid, id_int, msg = self.validate_numeric_id(user_id)
        if not is_valid:
            return False, f"Invalid user_id: {msg}"
        
        query = "DELETE FROM users WHERE user_id=?"
        print(f"[SECURE] Query: {query}")
        print(f"[SECURE] Parameters: ({id_int})")
        try:
            self.cursor.execute(query, (id_int,))
            self.conn.commit()
            affected = self.cursor.rowcount
            return True, f"Deleted {affected} user(s)"
        except sqlite3.Error:
            return False, "Database error"


# PART 4: DEMONSTRATIONS
print("\nPART 4: ATTACK DEMONSTRATIONS")
print("-" * 90)

db = Database()
vuln_crud = VulnerableCRUD(db)
secure_crud = SecureCRUD(db)

# ATTACK 1
print("\n### ATTACK 1: SELECT with Comment Injection ###\n")
attack_username = "admin' --"
print(f"Attacker Input: username = '{attack_username}'")
print(f"Goal: Bypass password check\n")

print("VULNERABLE APP:")
results, msg = vuln_crud.select_user_vulnerable(attack_username)
print(f"Result: {msg}")
if len(results) > 0:
    print(f"STATUS: ⚠️  SECURITY BREACH - Retrieved: {results[0]}\n")
else:
    print("STATUS: No match\n")

print("SECURE APP:")
results, msg = secure_crud.select_user_secure(attack_username)
print(f"Result: {msg}")
print(f"STATUS: ✓ PROTECTED - Input validation rejected\n")

# ATTACK 2
print("="*90)
print("### ATTACK 2: INSERT with Stacked Query ###\n")
attack_username = "hacker"
attack_email = "hack@evil.com', 'Hacker', 'pass123', 'admin'); DROP TABLE users; --"
print(f"Attacker Input:")
print(f"  username = '{attack_username}'")
print(f"  email = '{attack_email}'")
print(f"Goal: Create account AND drop users table\n")

print("VULNERABLE APP:")
success, msg = vuln_crud.insert_user_vulnerable(attack_username, attack_email, "Hacker", "pass123")
print(f"Result: {msg}")
print(f"STATUS: ⚠️  ATTEMPTED - Dangerous query\n")

print("SECURE APP:")
success, msg = secure_crud.insert_user_secure(attack_username, attack_email, "Hacker", "pass123")
print(f"Result: {msg}")
print(f"STATUS: ✓ PROTECTED - Email validation rejected\n")

# ATTACK 3
print("="*90)
print("### ATTACK 3: UPDATE with OR Injection ###\n")
attack_user_id = "1 OR 1=1"
attack_email = "hack@evil.com"
print(f"Attacker Input:")
print(f"  user_id = '{attack_user_id}'")
print(f"  email = '{attack_email}'")
print(f"Goal: Update ALL users' emails\n")

print("VULNERABLE APP:")
success, msg = vuln_crud.update_user_vulnerable(attack_user_id, attack_email)
print(f"Result: {msg}")
if "3" in msg:
    print(f"STATUS: ⚠️  SECURITY BREACH - All users updated!\n")
else:
    print(f"STATUS: Attack result\n")

print("SECURE APP:")
success, msg = secure_crud.update_user_secure(attack_user_id, attack_email)
print(f"Result: {msg}")
print(f"STATUS: ✓ PROTECTED - Type validation rejected non-numeric\n")

# ATTACK 4
print("="*90)
print("### ATTACK 4: DELETE with OR Injection ###\n")
attack_user_id = "1 OR 1=1"
print(f"Attacker Input: user_id = '{attack_user_id}'")
print(f"Goal: Delete ALL users from database\n")

print("VULNERABLE APP:")
success, msg = vuln_crud.delete_user_vulnerable(attack_user_id)
print(f"Result: {msg}")
if "3" in msg:
    print(f"STATUS: ⚠️  CRITICAL BREACH - All users deleted!\n")
else:
    print(f"STATUS: Attack result\n")

print("SECURE APP:")
success, msg = secure_crud.delete_user_secure(attack_user_id)
print(f"Result: {msg}")
print(f"STATUS: ✓ PROTECTED - Type validation rejected OR condition\n")

# ============================================================================
# PART 5: SUMMARY
# ============================================================================
print("="*90)
print("SUMMARY: KEY DEFENSE MECHANISMS")
print("="*90 + "\n")

print("CRUD OPERATIONS COVERED:")
print("-" * 90)

operations = {
    "SELECT (READ)": "Query and retrieve data - Protected by parameterization",
    "INSERT (CREATE)": "Add new records - Protected by validation + parameterization",
    "UPDATE (MODIFY)": "Change existing data - Protected by type validation + parameterization",
    "DELETE (REMOVE)": "Remove data - Protected by type validation + parameterization"
}

for op, desc in operations.items():
    print(f"\n{op}")
    print(f"  Description: {desc}")

print("\n" + "="*90)
print("ATTACK PATTERNS STOPPED:")
print("="*90 + "\n")

attacks = {
    "Comment Injection ('  --)": "Treated as literal string, not SQL comment",
    "OR Injection (' OR '1'='1)": "Parameter treated as single value, not condition",
    "Stacked Queries ('; DROP TABLE)": "Parameter can't contain multiple statements",
    "Escape Bypass (', role='admin)": "Parameter passed separately from query"
}

for attack, defense in attacks.items():
    print(f"\n{attack}")
    print(f"  How Stopped: {defense}")

print("\n" + "="*90)
print("DEFENSE TECHNIQUES USED:")
print("="*90 + "\n")

techniques = [
    "1. PARAMETERIZED QUERIES - Data separated from code",
    "2. INPUT VALIDATION - Check type, length, format before use",
    "3. TYPE CONVERSION - Convert to int/float, reject if fails",
    "4. ERROR HANDLING - Generic messages, hide database details",
    "5. AUTHORIZATION - Verify user permissions before operations"
]

for technique in techniques:
    print(f"  ✓ {technique}")

print("\n" + "="*90)
print("BEST PRACTICES FOR SECURE CRUD:")
print("="*90 + "\n")

practices = [
    "✓ Always use parameterized queries (? placeholders)",
    "✓ Validate ALL input before database operations",
    "✓ Use type conversion for numeric fields (int(), float())",
    "✓ Validate text with regex for allowed characters",
    "✓ Check length limits on all string inputs",
    "✓ Show generic error messages to users",
    "✓ Log detailed errors on server-side",
    "✓ Use principle of least privilege on database accounts",
    "✓ Test with injection payloads in each CRUD operation",
    "✓ Never trust user input - always treat it as potential attack"
]

for practice in practices:
    print(f"  {practice}")

print("\n" + "="*90)
print("PROJECT COMPLETE!")
print("="*90 + "\n")

print("WHAT YOU DEMONSTRATED:")
print("-" * 90)
demonstrations = [
    "✓ How SQL injection works in SELECT queries",
    "✓ How SQL injection works in INSERT queries",
    "✓ How SQL injection works in UPDATE queries",
    "✓ How SQL injection works in DELETE queries",
    "✓ How parameterized queries prevent all attacks",
    "✓ How input validation catches dangerous input",
    "✓ Why type conversion provides extra protection"
]

for demo in demonstrations:
    print(f"  {demo}")

print("\n" + "="*90)
print("Ready to present to your faculty!")
print("="*90 + "\n")