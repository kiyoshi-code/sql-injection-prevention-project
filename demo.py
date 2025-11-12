"""
SQL INJECTION PREVENTION - EDUCATIONAL DEMONSTRATION
Complete demonstration of vulnerable vs secure code with all CRUD operations
Run this file to see side-by-side comparison in terminal
NOW USING BCRYPT FOR PASSWORD HASHING
"""

import sqlite3
from typing import List, Tuple
import re
from datetime import datetime
import bcrypt

print("\n" + "="*100)
print("SQL INJECTION PREVENTION - COMPLETE DEMONSTRATION")
print("Using bcrypt for Password Hashing + Parameterized Queries for SQL Injection Prevention")
print("="*100 + "\n")

# ============================================================================
# PART 1: DATABASE SETUP
# ============================================================================
print("PART 1: Setting up database...")
print("-" * 100)

class Database:
    def __init__(self, db_name=':memory:'):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.cursor.execute("PRAGMA foreign_keys = ON")
        self.create_tables()
    
    def create_tables(self):
        # Users table
        self.cursor.execute('''
            CREATE TABLE users (
                user_id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password_hash TEXT,
                email TEXT UNIQUE,
                full_name TEXT,
                role TEXT,
                created_at TEXT
            )
        ''')
        
        # Products table
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
        
        # Orders table
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
        
        # Insert sample data with bcrypt hashed passwords
        users = [
            (1, 'john_doe', bcrypt.hashpw('pass123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), 'john@email.com', 'John Doe', 'user', '2024-01-01'),
            (2, 'admin', bcrypt.hashpw('admin@pass'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), 'admin@company.com', 'Admin User', 'admin', '2024-01-01'),
            (3, 'jane_smith', bcrypt.hashpw('jane@pass'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), 'jane@email.com', 'Jane Smith', 'user', '2024-01-05'),
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
        print("✓ Database created with sample data")
        print("✓ Passwords hashed using bcrypt with automatic salt generation\n")

# ============================================================================
# PART 2: PASSWORD SECURITY & VALIDATION FUNCTIONS
# ============================================================================
print("\nPART 2: PASSWORD HASHING & VALIDATION")
print("-" * 100)

class PasswordSecurity:
    """
    bcrypt Password Hashing - Industry Standard
    
    Why bcrypt is better than SHA256:
    1. Built-in salt (random data added to password before hashing)
    2. Slow by design (makes brute-force attacks impractical)
    3. Adjustable work factor (can increase difficulty over time)
    4. Same password produces different hash each time (due to random salt)
    """
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt with automatic salt generation"""
        salt = bcrypt.gensalt(rounds=12)  # 12 rounds = 2^12 iterations
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify password against bcrypt hash"""
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

print("✓ Using bcrypt for password hashing (12 rounds)")
print("✓ Automatic salt generation for each password")
print("✓ Same password = different hash each time\n")

class Validation:
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
            return False, 0, f"ID must be a number (you entered: {value})"

# ============================================================================
# PART 3: VULNERABLE CODE (What NOT to do)
# ============================================================================
print("\nPART 3: VULNERABLE CODE IMPLEMENTATION")
print("-" * 100)

class VulnerableCRUD:
    """
    ⚠️ VULNERABLE CODE - Uses String Concatenation
    This is what you should NEVER do in production!
    """
    
    def __init__(self, db: Database):
        self.conn = db.conn
        self.cursor = db.cursor
    
    def select_user_vulnerable(self, username: str) -> Tuple[List, str]:
        """VULNERABLE: String concatenation allows comment injection"""
        # THE PROBLEM: User input directly concatenated into SQL
        query = f"SELECT user_id, username, email, role FROM users WHERE username='{username}'"
        
        print(f"[VULNERABLE] Query: {query}")
        try:
            self.cursor.execute(query)
            results = self.cursor.fetchall()
            return results, "Success"
        except sqlite3.Error as e:
            return [], f"Error: {str(e)}"
    
    def insert_user_vulnerable(self, username: str, email: str, password: str) -> Tuple[bool, str]:
        """VULNERABLE: Allows stacked queries and DROP TABLE attacks"""
        # Even though we hash the password with bcrypt, the query is still vulnerable
        password_hash = PasswordSecurity.hash_password(password)
        query = f"INSERT INTO users (username, email, full_name, password_hash, role, created_at) VALUES ('{username}', '{email}', 'User', '{password_hash}', 'user', '{datetime.now().isoformat()}')"
        
        print(f"[VULNERABLE] Query: {query[:100]}...")
        try:
            self.cursor.execute(query)
            self.conn.commit()
            return True, "User inserted"
        except sqlite3.Error as e:
            return False, f"Error: {str(e)}"
    
    def update_email_vulnerable(self, user_id: str, new_email: str) -> Tuple[bool, str]:
        """VULNERABLE: Allows privilege escalation and OR injection"""
        query = f"UPDATE users SET email='{new_email}' WHERE user_id={user_id}"
        
        print(f"[VULNERABLE] Query: {query}")
        try:
            self.cursor.execute(query)
            self.conn.commit()
            return True, f"Updated {self.cursor.rowcount} user(s)"
        except sqlite3.Error as e:
            return False, f"Error: {str(e)}"
    
    def delete_user_vulnerable(self, user_id: str) -> Tuple[bool, str]:
        """VULNERABLE: OR injection can delete all records"""
        query = f"DELETE FROM users WHERE user_id={user_id}"
        
        print(f"[VULNERABLE] Query: {query}")
        try:
            self.cursor.execute(query)
            self.conn.commit()
            return True, f"Deleted {self.cursor.rowcount} user(s)"
        except sqlite3.Error as e:
            return False, f"Error: {str(e)}"

# ============================================================================
# PART 4: SECURE CODE (Best Practices)
# ============================================================================
print("\nPART 4: SECURE CODE IMPLEMENTATION")
print("-" * 100)

class SecureCRUD:
    """
    ✅ SECURE CODE - Uses Parameterized Queries + Validation + bcrypt
    This is the correct way to write database code!
    """
    
    def __init__(self, db: Database):
        self.conn = db.conn
        self.cursor = db.cursor
    
    def select_user_secure(self, username: str, password: str = None) -> Tuple[List, str]:
        """SECURE: Parameterized query + validation + bcrypt password verification"""
        # Step 1: Validate input
        is_valid, msg = Validation.validate_username(username)
        if not is_valid:
            return [], f"Invalid input: {msg}"
        
        # Step 2: Use parameterized query (? placeholder)
        query = "SELECT user_id, username, email, role, password_hash FROM users WHERE username=?"
        
        print(f"[SECURE] Query: {query}")
        print(f"[SECURE] Parameters: ('{username}')")
        try:
            self.cursor.execute(query, (username,))  # Data passed separately!
            results = self.cursor.fetchall()
            
            # Step 3: Verify password using bcrypt if provided
            if password and results:
                user_data = results[0]
                password_hash = user_data[4]
                if PasswordSecurity.verify_password(password, password_hash):
                    return [user_data[:4]], "Login successful - password verified with bcrypt"
                else:
                    return [], "Invalid credentials - bcrypt verification failed"
            
            return [r[:4] for r in results], "Success"
        except sqlite3.Error:
            return [], "Database error"
    
    def insert_user_secure(self, username: str, email: str, password: str) -> Tuple[bool, str]:
        """SECURE: Validation + parameterized query + bcrypt hashing"""
        # Validate all inputs
        is_valid, msg = Validation.validate_username(username)
        if not is_valid:
            return False, f"Invalid username: {msg}"
        
        is_valid, msg = Validation.validate_email(email)
        if not is_valid:
            return False, f"Invalid email: {msg}"
        
        if not password or len(password) < 5:
            return False, "Password must be at least 5 characters"
        
        # Hash password using bcrypt
        password_hash = PasswordSecurity.hash_password(password)
        
        # Parameterized INSERT
        query = "INSERT INTO users (username, email, full_name, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)"
        
        print(f"[SECURE] Query: {query}")
        print(f"[SECURE] Parameters: ('{username}', '{email}', 'User', '***bcrypt_hash***', 'user', timestamp)")
        try:
            self.cursor.execute(query, (username, email, 'User', password_hash, 'user', datetime.now().isoformat()))
            self.conn.commit()
            return True, "User inserted with bcrypt hashed password"
        except sqlite3.IntegrityError:
            return False, "Username or email already exists"
        except sqlite3.Error:
            return False, "Database error"
    
    def update_email_secure(self, user_id: str, new_email: str) -> Tuple[bool, str]:
        """SECURE: Type validation + parameterized query"""
        # Validate ID as numeric
        is_valid, id_int, msg = Validation.validate_numeric_id(user_id)
        if not is_valid:
            return False, f"Invalid user_id: {msg}"
        
        # Validate email
        is_valid, msg = Validation.validate_email(new_email)
        if not is_valid:
            return False, f"Invalid email: {msg}"
        
        # Parameterized UPDATE
        query = "UPDATE users SET email=? WHERE user_id=?"
        
        print(f"[SECURE] Query: {query}")
        print(f"[SECURE] Parameters: ('{new_email}', {id_int})")
        try:
            self.cursor.execute(query, (new_email, id_int))
            self.conn.commit()
            return True, f"Updated {self.cursor.rowcount} user(s)"
        except sqlite3.IntegrityError:
            return False, "Email already in use"
        except sqlite3.Error:
            return False, "Database error"
    
    def delete_user_secure(self, user_id: str) -> Tuple[bool, str]:
        """SECURE: Type validation prevents OR injection"""
        # Validate ID
        is_valid, id_int, msg = Validation.validate_numeric_id(user_id)
        if not is_valid:
            return False, f"Invalid user_id: {msg}"
        
        # Parameterized DELETE
        query = "DELETE FROM users WHERE user_id=?"
        
        print(f"[SECURE] Query: {query}")
        print(f"[SECURE] Parameters: ({id_int})")
        try:
            self.cursor.execute(query, (id_int,))
            self.conn.commit()
            return True, f"Deleted {self.cursor.rowcount} user(s)"
        except sqlite3.Error:
            return False, "Database error"

# ============================================================================
# PART 5: ATTACK DEMONSTRATIONS
# ============================================================================
print("\n" + "="*100)
print("PART 5: ATTACK DEMONSTRATIONS")
print("="*100)

db = Database()
vuln = VulnerableCRUD(db)
secure = SecureCRUD(db)

# ATTACK 1: Comment Injection (Bypass Authentication)
print("\n" + "─"*100)
print("ATTACK 1: Comment Injection - Bypass Password Check")
print("─"*100)

attack_input = "admin' --"
print(f"\n🔴 Attacker Input: username = \"{attack_input}\"")
print(f"🎯 Goal: Login without knowing password\n")

print("VULNERABLE CODE:")
results, msg = vuln.select_user_vulnerable(attack_input)
if results:
    print(f"⚠️  SECURITY BREACH! Retrieved: {results[0]}")
    print(f"    The '--' commented out the password check!")
    print(f"    Note: Even though passwords are stored with bcrypt,")
    print(f"    the SQL injection bypassed authentication entirely!\n")
else:
    print(f"Result: {msg}\n")

print("SECURE CODE:")
results, msg = secure.select_user_secure(attack_input, "any_password")
print(f"✅ PROTECTED: {msg}")
print(f"    Input validation rejected the single quote")
print(f"    Even if it passed, bcrypt would verify the password\n")

# ATTACK 2: OR Injection (Data Extraction)
print("─"*100)
print("ATTACK 2: OR Injection - Unauthorized Data Access")
print("─"*100)

attack_input = "1 OR 1=1"
print(f"\n🔴 Attacker Input: user_id = \"{attack_input}\"")
print(f"🎯 Goal: Update ALL users instead of one\n")

print("VULNERABLE CODE:")
success, msg = vuln.update_email_vulnerable(attack_input, "hacked@evil.com")
if "3" in msg:
    print(f"⚠️  SECURITY BREACH! {msg}")
    print(f"    All users' emails were changed!\n")
else:
    print(f"Result: {msg}\n")

print("SECURE CODE:")
success, msg = secure.update_email_secure(attack_input, "hacked@evil.com")
print(f"✅ PROTECTED: {msg}")
print(f"    Type validation rejected non-numeric input\n")

# ATTACK 3: Stacked Query (Data Destruction)
print("─"*100)
print("ATTACK 3: Stacked Query - DROP TABLE Attack")
print("─"*100)

attack_email = "hack@evil.com'); DROP TABLE users; --"
print(f"\n🔴 Attacker Input:")
print(f"    username = \"hacker\"")
print(f"    email = \"{attack_email}\"")
print(f"🎯 Goal: Create account AND destroy users table\n")

print("VULNERABLE CODE:")
success, msg = vuln.insert_user_vulnerable("hacker", attack_email, "pass123")
if not success:
    print(f"⚠️  DANGEROUS! Query attempted: {msg}")
    print(f"    Could have destroyed the database!")
    print(f"    Note: bcrypt hashing doesn't prevent SQL injection!\n")
else:
    print(f"Result: {msg}\n")

print("SECURE CODE:")
success, msg = secure.insert_user_secure("hacker", attack_email, "pass123")
print(f"✅ PROTECTED: {msg}")
print(f"    Email validation rejected special characters")
print(f"    Password would be hashed with bcrypt before storage\n")

# ATTACK 4: Bulk Delete (Data Destruction)
print("─"*100)
print("ATTACK 4: Bulk Delete - Delete All Records")
print("─"*100)

attack_input = "1 OR 1=1"
print(f"\n🔴 Attacker Input: user_id = \"{attack_input}\"")
print(f"🎯 Goal: Delete ALL users from database\n")

print("VULNERABLE CODE:")
success, msg = vuln.delete_user_vulnerable(attack_input)
if "3" in msg:
    print(f"⚠️  CRITICAL BREACH! {msg}")
    print(f"    Entire users table was wiped out!")
    print(f"    All bcrypt hashed passwords are gone!\n")
else:
    print(f"Result: {msg}\n")

print("SECURE CODE:")
success, msg = secure.delete_user_secure(attack_input)
print(f"✅ PROTECTED: {msg}")
print(f"    Type validation prevented OR condition\n")

# ============================================================================
# PART 6: bcrypt DEMONSTRATION
# ============================================================================
print("="*100)
print("BONUS: bcrypt PASSWORD HASHING DEMONSTRATION")
print("="*100 + "\n")

print("Why bcrypt is better than SHA256 for passwords:")
print("-" * 100)

test_password = "MySecretPassword123"
print(f"\nOriginal Password: {test_password}")

# Hash the same password twice
hash1 = PasswordSecurity.hash_password(test_password)
hash2 = PasswordSecurity.hash_password(test_password)

print(f"\nHash 1: {hash1}")
print(f"Hash 2: {hash2}")
print("\n✓ Notice: Same password = DIFFERENT hashes (due to random salt)")
print("✓ This prevents rainbow table attacks")

# Verify passwords
print(f"\nVerify 'MySecretPassword123' against Hash 1: {PasswordSecurity.verify_password(test_password, hash1)}")
print(f"Verify 'WrongPassword' against Hash 1: {PasswordSecurity.verify_password('WrongPassword', hash1)}")

print("\n" + "="*100)
print("SUMMARY: TWO-LAYER SECURITY APPROACH")
print("="*100 + "\n")

print("LAYER 1: PREVENT SQL INJECTION")
print("-" * 100)
print("✅ Parameterized Queries (? placeholders)")
print("   • SQL code and data are separated")
print("   • User input is never interpreted as SQL code")
print("   • Stops: Comment injection, OR injection, UNION, stacked queries\n")

print("✅ Input Validation")
print("   • Type checking: int() rejects non-numeric input")
print("   • Format checking: regex validates allowed characters")
print("   • Length checking: prevents buffer overflow\n")

print("LAYER 2: PROTECT PASSWORDS (IF DATABASE IS BREACHED)")
print("-" * 100)
print("✅ bcrypt Password Hashing")
print("   • Built-in salt (random data added to each password)")
print("   • Slow by design (2^12 iterations = 4096 hashing rounds)")
print("   • Same password = different hash each time")
print("   • Protects against: Rainbow tables, brute force, dictionary attacks\n")

print("="*100)
print("KEY TAKEAWAY")
print("="*100 + "\n")
print("🔐 bcrypt does NOT prevent SQL injection")
print("🔐 Parameterized queries prevent SQL injection")
print("🔐 bcrypt protects passwords IF an attacker breaches your database")
print("🔐 Use BOTH for defense-in-depth security\n")

print("="*100)
print("PROJECT COMPLETE - Ready for Faculty Presentation!")
print("="*100 + "\n")