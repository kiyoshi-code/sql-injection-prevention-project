#shows attacks
"""
SQL INJECTION PREVENTION PROJECT - PART 4: SECURE CRUD OPERATIONS
Shows proper parameterized queries with comprehensive input validation
PRODUCTION-READY PATTERNS
"""

import sqlite3
from typing import List, Tuple
from datetime import datetime
from validation import Validation, PasswordSecurity

class SecureCRUD:
    """
    SECURE CODE - Parameterized queries for all operations
    
    WHY THIS IS SECURE:
    - ? placeholders separate SQL code from user data
    - Input validation catches attacks before database execution
    - Type conversion rejects non-numeric input in numeric fields
    - Password hashing protects user credentials
    - Database treats all parameters as pure data, never code
    """
    
    def __init__(self, db):
        """Initialize with database connection"""
        self.conn = db.get_connection()
        self.cursor = db.get_cursor()
    
    # ===== SELECT (Read) Operations - SECURE =====
    
    def select_user_secure(self, username: str) -> Tuple[List, str]:
        """
        SECURE SELECT: Parameterized query + input validation
        
        Defense: ? placeholders + username validation
        
        Attack Attempt: username = "admin' --"
        - Validation fails: contains single quote (not in allowed characters)
        - Even if validation passed, ? treats entire string as literal value
        - Database looks for username EXACTLY equal to "admin' --"
        - No such username exists, safe rejection
        
        Key Protection: SEPARATION OF CODE AND DATA
        Vulnerable: "WHERE username='" + username + "'"
        Secure:     "WHERE username=?" with (username,)
        """
        # Validate input FIRST
        is_valid, message = Validation.validate_username(username)
        if not is_valid:
            return [], f"Invalid input: {message}"
        
        # Parameterized query with ? placeholder
        query = "SELECT user_id, username, email, full_name, role FROM users WHERE username=?"
        
        print(f"\n[SECURE] SELECT Query with parameterization:")
        print(f"  Query Template: {query}")
        print(f"  Parameters: ('{username}')")
        print(f"  Key: Data passed separately from query structure")
        
        try:
            # ? is replaced with value, but value is NEVER interpreted as code
            self.cursor.execute(query, (username,))
            results = self.cursor.fetchall()
            return results, "Success"
        except sqlite3.Error as e:
            return [], "Database error occurred"
    
    def select_with_join_secure(self, product_id: str) -> Tuple[List, str]:
        """
        SECURE SELECT with JOIN: Parameterized query + type validation
        
        Defense: ? placeholders + numeric validation
        
        Attack Attempt: product_id = "1 OR 1=1"
        - Validation: int("1 OR 1=1") throws ValueError
        - Attack rejected BEFORE query execution
        - Type validation acts as first line of defense
        
        Key Protection: TYPE VALIDATION CATCHES NUMERIC INJECTION
        """
        # Validate as numeric ID
        is_valid, id_int, message = Validation.validate_numeric_id(product_id)
        if not is_valid:
            return [], f"Invalid input: {message}"
        
        # Parameterized JOIN query
        query = """
            SELECT p.product_id, p.product_name, p.price
            FROM products p
            WHERE p.product_id = ?"""
        
        print(f"\n[SECURE] SELECT with JOIN Query:")
        print(f"  Query Template: {query}")
        print(f"  Parameters: ({id_int})")
        print(f"  Key: Type conversion to int prevents OR injection")
        
        try:
            self.cursor.execute(query, (id_int,))
            results = self.cursor.fetchall()
            return results, "Success"
        except sqlite3.Error as e:
            return [], "Database error occurred"
    
    # ===== INSERT (Create) Operations - SECURE =====
    
    def insert_user_secure(self, username: str, email: str, full_name: str, password: str) -> Tuple[bool, str]:
        """
        SECURE INSERT: Parameterized query + validation on all fields + password hashing
        
        Defense: ? placeholders + validation + bcrypt hashing
        
        Attack Attempt: email = "hack@evil.com'); DROP TABLE users; --"
        - Validation fails: contains special characters not allowed
        - Even if validation passed, ? treats entire string as email VALUE
        - Cannot inject additional statements or columns
        - Stacked query injection impossible
        
        Key Protection: COMPREHENSIVE VALIDATION ON ALL FIELDS + PARAMETERIZATION
        """
        # Validate ALL inputs before database operation
        is_valid, msg = Validation.validate_username(username)
        if not is_valid:
            return False, f"Invalid username: {msg}"
        
        is_valid, msg = Validation.validate_email(email)
        if not is_valid:
            return False, f"Invalid email: {msg}"
        
        is_valid, msg = Validation.validate_text(full_name, max_length=100)
        if not is_valid:
            return False, f"Invalid full_name: {msg}"
        
        is_valid, msg = Validation.validate_password(password)
        if not is_valid:
            return False, f"Invalid password: {msg}"
        
        # Hash password using bcrypt (or SHA256 in demo)
        password_hash = PasswordSecurity.hash_password(password)
        
        # Parameterized INSERT with all values as parameters
        query = """
            INSERT INTO users (username, email, full_name, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)"""
        
        print(f"\n[SECURE] INSERT Query with parameterization:")
        print(f"  Query Template: {query}")
        print(f"  Parameters: ('{username}', '{email}', '{full_name}', '***hash***', 'user', timestamp)")
        print(f"  Key: Password is hashed, not stored as plain text")
        
        try:
            self.cursor.execute(query, (username, email, full_name, password_hash, 'user', datetime.now().isoformat()))
            self.conn.commit()
            return True, "User inserted successfully"
        except sqlite3.IntegrityError:
            return False, "Username or email already exists"
        except sqlite3.Error:
            return False, "Database error occurred"
    
    def insert_product_secure(self, product_name: str, category: str, price: str, stock: str) -> Tuple[bool, str]:
        """
        SECURE INSERT: Parameterized query + validation for each field type
        
        Defense: ? placeholders + type-specific validation
        
        Attack Attempt: stock = "10); DELETE FROM products; --"
        - Validation: int("10); DELETE...") throws ValueError
        - Invalid integer rejected immediately
        - Stacked query attack blocked before reaching database
        
        Key Protection: TYPE VALIDATION ON NUMERIC FIELDS
        """
        # Validate each field with appropriate validation
        is_valid, msg = Validation.validate_text(product_name, max_length=100)
        if not is_valid:
            return False, f"Invalid product_name: {msg}"
        
        is_valid, msg = Validation.validate_text(category, max_length=50)
        if not is_valid:
            return False, f"Invalid category: {msg}"
        
        # Price must be float
        is_valid, price_float, msg = Validation.validate_price(price)
        if not is_valid:
            return False, f"Invalid price: {msg}"
        
        # Stock must be integer
        is_valid, stock_int, msg = Validation.validate_stock(stock)
        if not is_valid:
            return False, f"Invalid stock: {msg}"
        
        # Parameterized INSERT with converted types
        query = """
            INSERT INTO products (product_name, category, price, stock, created_at)
            VALUES (?, ?, ?, ?, ?)"""
        
        print(f"\n[SECURE] INSERT Product Query:")
        print(f"  Query Template: {query}")
        print(f"  Parameters: ('{product_name}', '{category}', {price_float}, {stock_int}, timestamp)")
        print(f"  Key: Price converted to float, stock to int - type checking prevents injection")
        
        try:
            self.cursor.execute(query, (product_name, category, price_float, stock_int, datetime.now().isoformat()))
            self.conn.commit()
            return True, "Product inserted successfully"
        except sqlite3.Error:
            return False, "Database error occurred"
    
    # ===== UPDATE (Modify) Operations - SECURE =====
    
    def update_user_email_secure(self, user_id: str, new_email: str) -> Tuple[bool, str]:
        """
        SECURE UPDATE: Parameterized query + validation on WHERE and SET clauses
        
        Defense: ? placeholders + numeric + email validation
        
        Attack Attempt: new_email = "hack@evil.com', role='admin"
        - Email validation fails: contains single quote (not allowed)
        - Can't modify role field because email parameter is separate
        - Parameter isolation prevents field escaping
        
        Attack Attempt: user_id = "1 OR 1=1"
        - Numeric validation: int("1 OR 1=1") throws ValueError
        - Attack rejected before query execution
        
        Key Protection: VALIDATION + PARAMETERIZATION + PARAMETER ISOLATION
        """
        # Validate user_id as numeric
        is_valid, id_int, msg = Validation.validate_numeric_id(user_id)
        if not is_valid:
            return False, f"Invalid user_id: {msg}"
        
        # Validate new_email
        is_valid, msg = Validation.validate_email(new_email)
        if not is_valid:
            return False, f"Invalid email: {msg}"
        
        # Parameterized UPDATE
        query = "UPDATE users SET email=? WHERE user_id=?"
        
        print(f"\n[SECURE] UPDATE Query:")
        print(f"  Query Template: {query}")
        print(f"  Parameters: ('{new_email}', {id_int})")
        print(f"  Key: WHERE clause value validated as integer - can't use OR conditions")
        
        try:
            self.cursor.execute(query, (new_email, id_int))
            self.conn.commit()
            affected = self.cursor.rowcount
            return True, f"Updated {affected} user(s)"
        except sqlite3.IntegrityError:
            return False, "Email already in use"
        except sqlite3.Error:
            return False, "Database error occurred"
    
    def update_product_price_secure(self, product_id: str, new_price: str) -> Tuple[bool, str]:
        """
        SECURE UPDATE: Type validation prevents bulk updates
        
        Defense: ? placeholders + numeric validation
        
        Attack Attempt: product_id = "1 OR 1=1"
        - int() conversion fails
        - Attack rejected at validation stage
        - Only specified product can be updated
        
        Key Protection: TYPE CONVERSION + PARAMETERIZATION
        """
        # Validate product_id
        is_valid, id_int, msg = Validation.validate_numeric_id(product_id)
        if not is_valid:
            return False, f"Invalid product_id: {msg}"
        
        # Validate price
        is_valid, price_float, msg = Validation.validate_price(new_price)
        if not is_valid:
            return False, f"Invalid price: {msg}"
        
        # Parameterized UPDATE
        query = "UPDATE products SET price=? WHERE product_id=?"
        
        print(f"\n[SECURE] UPDATE Price Query:")
        print(f"  Query Template: {query}")
        print(f"  Parameters: ({price_float}, {id_int})")
        print(f"  Key: Both values validated - numeric type prevents OR injection")
        
        try:
            self.cursor.execute(query, (price_float, id_int))
            self.conn.commit()
            affected = self.cursor.rowcount
            return True, f"Updated {affected} product(s)"
        except sqlite3.Error:
            return False, "Database error occurred"
    
    # ===== DELETE (Remove) Operations - SECURE =====
    
    def delete_user_secure(self, user_id: str) -> Tuple[bool, str]:
        """
        SECURE DELETE: Type validation prevents bulk deletion
        
        Defense: ? placeholders + numeric validation
        
        Attack Attempt: user_id = "1 OR 1=1"
        - int("1 OR 1=1") throws ValueError
        - Only valid integer IDs accepted
        - Can't delete all users with OR condition
        
        Attack Attempt: user_id = "1; DROP TABLE users; --"
        - int() conversion fails (contains semicolon and text)
        - Stacked query injection impossible
        
        Key Protection: TYPE VALIDATION + PARAMETERIZATION
        """
        # Validate user_id as numeric
        is_valid, id_int, msg = Validation.validate_numeric_id(user_id)
        if not is_valid:
            return False, f"Invalid user_id: {msg}"
        
        # Parameterized DELETE
        query = "DELETE FROM users WHERE user_id=?"
        
        print(f"\n[SECURE] DELETE Query:")
        print(f"  Query Template: {query}")
        print(f"  Parameters: ({id_int})")
        print(f"  Key: Type validation rejects non-numeric - prevents OR and stacked queries")
        
        try:
            self.cursor.execute(query, (id_int,))
            self.conn.commit()
            affected = self.cursor.rowcount
            return True, f"Deleted {affected} user(s)"
        except sqlite3.Error:
            return False, "Database error occurred"
    
    def delete_orders_secure(self, order_id: str) -> Tuple[bool, str]:
        """
        SECURE DELETE: Type validation protects against stacked queries
        
        Defense: ? placeholders + numeric validation
        
        Attack Attempt: order_id = "1; DROP TABLE orders; --"
        - int() conversion fails
        - Attack blocked at validation
        
        Key Protection: TYPE CONVERSION REJECTS STATEMENTS
        """
        # Validate order_id
        is_valid, id_int, msg = Validation.validate_numeric_id(order_id)
        if not is_valid:
            return False, f"Invalid order_id: {msg}"
        
        # Parameterized DELETE
        query = "DELETE FROM orders WHERE order_id=?"
        
        print(f"\n[SECURE] DELETE Orders Query:")
        print(f"  Query Template: {query}")
        print(f"  Parameters: ({id_int})")
        print(f"  Key: Stacked queries impossible with type validation")
        
        try:
            self.cursor.execute(query, (id_int,))
            self.conn.commit()
            affected = self.cursor.rowcount
            return True, f"Deleted {affected} order(s)"
        except sqlite3.Error:
            return False, "Database error occurred"