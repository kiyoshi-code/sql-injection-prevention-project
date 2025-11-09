#password hashing
"""
SQL INJECTION PREVENTION PROJECT - PART 3: VULNERABLE CRUD OPERATIONS
Shows how NOT to write SQL queries - vulnerable to injection attacks
EDUCATIONAL PURPOSE ONLY - DO NOT USE IN PRODUCTION
"""

import sqlite3
from typing import List, Tuple
from datetime import datetime

class VulnerableCRUD:
    """
    VULNERABLE CODE - Shows SQL injection attacks
    
    WHY VULNERABLE:
    - Uses string concatenation instead of parameterization
    - No separation between SQL code and user input
    - Database can't distinguish code from data
    - All attack types possible: comment, OR, UNION, stacked queries
    
    ⚠️ IMPORTANT: This is for educational demonstration only
    Never use this pattern in real applications!
    """
    
    def __init__(self, db):
        """Initialize with database connection"""
        self.conn = db.get_connection()
        self.cursor = db.get_cursor()
    
    # ===== SELECT (Read) Operations - VULNERABLE =====
    
    def select_user_vulnerable(self, username: str) -> Tuple[List, str]:
        """
        VULNERABLE SELECT: String concatenation
        
        Attack Vector: Comment Injection
        Attacker Input: username = "admin' --"
        
        Normal Query:   SELECT * FROM users WHERE username='john_doe'
        Attacked Query: SELECT * FROM users WHERE username='admin' --'
        
        The -- comments out password check, allowing login without password
        Result: Admin account accessed without authorization
        """
        # String concatenation - THE VULNERABILITY
        query = "SELECT user_id, username, email, full_name, role FROM users WHERE username='" + username + "'"
        
        print(f"\n[VULNERABLE] SELECT Query built with string concatenation:")
        print(f"  Query: {query}")
        
        try:
            self.cursor.execute(query)
            results = self.cursor.fetchall()
            return results, "Success"
        except sqlite3.Error as e:
            return [], f"Error: {str(e)}"
    
    def select_with_join_vulnerable(self, product_id: str) -> Tuple[List, str]:
        """
        VULNERABLE SELECT with JOIN: String concatenation in JOIN condition
        
        Attack Vector: OR Injection
        Attacker Input: product_id = "1 OR 1=1"
        
        Normal Query:   SELECT ... WHERE p.product_id = 1
        Attacked Query: SELECT ... WHERE p.product_id = 1 OR 1=1
        
        Since 1=1 is always TRUE, returns ALL products and reviews
        Result: Complete product database + customer reviews exposed
        """
        query = """
            SELECT p.product_id, p.product_name, p.price,
                   r.review_text, r.rating, c.full_name, c.email
            FROM products p
            WHERE p.product_id = """ + product_id  # String concatenation
        
        print(f"\n[VULNERABLE] SELECT with JOIN Query:")
        print(f"  Query: {query}")
        
        try:
            self.cursor.execute(query)
            results = self.cursor.fetchall()
            return results, "Success"
        except sqlite3.Error as e:
            return [], f"Error: {str(e)}"
    
    # ===== INSERT (Create) Operations - VULNERABLE =====
    
    def insert_user_vulnerable(self, username: str, email: str, full_name: str) -> Tuple[bool, str]:
        """
        VULNERABLE INSERT: String concatenation in VALUES
        
        Attack Vector: Stacked Query Injection
        Attacker Input: email = "hack@evil.com'); DROP TABLE users; --"
        
        Normal Query:   INSERT INTO users VALUES (..., 'hack@evil.com', ...)
        Attacked Query: INSERT INTO users VALUES (..., 'hack@evil.com'); DROP TABLE users; --...)
        
        First statement creates unauthorized account
        Second statement DELETES entire users table
        Result: Data destruction + account creation
        """
        query = "INSERT INTO users (username, email, full_name, password_hash, role, created_at) VALUES ('" + username + "', '" + email + "', '" + full_name + "', 'demo_hash', 'user', '" + datetime.now().isoformat() + "')"
        
        print(f"\n[VULNERABLE] INSERT Query:")
        print(f"  Query: {query}")
        
        try:
            self.cursor.execute(query)
            self.conn.commit()
            return True, "User inserted"
        except sqlite3.Error as e:
            return False, f"Error: {str(e)}"
    
    def insert_product_vulnerable(self, product_name: str, category: str, price: str, stock: str) -> Tuple[bool, str]:
        """
        VULNERABLE INSERT: Multiple statements in numeric field
        
        Attack Vector: Stacked Query + Numeric Injection
        Attacker Input: stock = "10); DELETE FROM products; --"
        
        Normal Query:   INSERT INTO products (..., 10, ...)
        Attacked Query: INSERT INTO products (..., 10); DELETE FROM products; --...)
        
        Creates product, then DELETES ALL products
        Result: Data destruction
        """
        query = "INSERT INTO products (product_name, category, price, stock, created_at) VALUES ('" + product_name + "', '" + category + "', " + price + ", " + stock + ", '" + datetime.now().isoformat() + "')"
        
        print(f"\n[VULNERABLE] INSERT Product Query:")
        print(f"  Query: {query}")
        
        try:
            self.cursor.execute(query)
            self.conn.commit()
            return True, "Product inserted"
        except sqlite3.Error as e:
            return False, f"Error: {str(e)}"
    
    # ===== UPDATE (Modify) Operations - VULNERABLE =====
    
    def update_user_email_vulnerable(self, user_id: str, new_email: str) -> Tuple[bool, str]:
        """
        VULNERABLE UPDATE: String concatenation in WHERE and SET
        
        Attack Vector: Field Escape + Privilege Escalation
        Attacker Input: new_email = "hack@evil.com', role='admin"
        
        Normal Query:   UPDATE users SET email='newemail@gmail.com' WHERE user_id=1
        Attacked Query: UPDATE users SET email='hack@evil.com', role='admin' WHERE user_id=1
        
        Changes email AND promotes user to admin role
        Result: Account takeover + privilege escalation
        """
        query = "UPDATE users SET email='" + new_email + "' WHERE user_id=" + user_id
        
        print(f"\n[VULNERABLE] UPDATE Query:")
        print(f"  Query: {query}")
        
        try:
            self.cursor.execute(query)
            self.conn.commit()
            affected = self.cursor.rowcount
            return True, f"Updated {affected} user(s)"
        except sqlite3.Error as e:
            return False, f"Error: {str(e)}"
    
    def update_product_price_vulnerable(self, product_id: str, new_price: str) -> Tuple[bool, str]:
        """
        VULNERABLE UPDATE: OR injection in WHERE clause
        
        Attack Vector: OR Injection (Bulk Update)
        Attacker Input: product_id = "1 OR 1=1"
        
        Normal Query:   UPDATE products SET price=99.99 WHERE product_id=1
        Attacked Query: UPDATE products SET price=99.99 WHERE product_id=1 OR 1=1
        
        Since 1=1 is always TRUE, updates ALL products
        Result: All prices changed to attacker-controlled value
        """
        query = "UPDATE products SET price=" + new_price + " WHERE product_id=" + product_id
        
        print(f"\n[VULNERABLE] UPDATE Price Query:")
        print(f"  Query: {query}")
        
        try:
            self.cursor.execute(query)
            self.conn.commit()
            affected = self.cursor.rowcount
            return True, f"Updated {affected} product(s)"
        except sqlite3.Error as e:
            return False, f"Error: {str(e)}"
    
    # ===== DELETE (Remove) Operations - VULNERABLE =====
    
    def delete_user_vulnerable(self, user_id: str) -> Tuple[bool, str]:
        """
        VULNERABLE DELETE: OR injection in WHERE clause
        
        Attack Vector: OR Injection (Bulk Delete)
        Attacker Input: user_id = "1 OR 1=1"
        
        Normal Query:   DELETE FROM users WHERE user_id=1
        Attacked Query: DELETE FROM users WHERE user_id=1 OR 1=1
        
        Since 1=1 is always TRUE, deletes ALL users
        Result: Complete data destruction
        """
        query = "DELETE FROM users WHERE user_id=" + user_id
        
        print(f"\n[VULNERABLE] DELETE Query:")
        print(f"  Query: {query}")
        
        try:
            self.cursor.execute(query)
            self.conn.commit()
            affected = self.cursor.rowcount
            return True, f"Deleted {affected} user(s)"
        except sqlite3.Error as e:
            return False, f"Error: {str(e)}"
    
    def delete_orders_vulnerable(self, order_id: str) -> Tuple[bool, str]:
        """
        VULNERABLE DELETE: Stacked query injection
        
        Attack Vector: Stacked Query (Multiple Statements)
        Attacker Input: order_id = "1; DROP TABLE orders; --"
        
        Normal Query:   DELETE FROM orders WHERE order_id=1
        Attacked Query: DELETE FROM orders WHERE order_id=1; DROP TABLE orders; --
        
        Deletes one order, then DROPS entire orders table
        Result: Table structure destroyed, all data lost
        """
        query = "DELETE FROM orders WHERE order_id=" + order_id
        
        print(f"\n[VULNERABLE] DELETE Orders Query:")
        print(f"  Query: {query}")
        
        try:
            self.cursor.execute(query)
            self.conn.commit()
            affected = self.cursor.rowcount
            return True, f"Deleted {affected} order(s)"
        except sqlite3.Error as e:
            return False, f"Error: {str(e)}"