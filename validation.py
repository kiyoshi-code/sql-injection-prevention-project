"""
SQL INJECTION PREVENTION PROJECT - PART 2: INPUT VALIDATION & PASSWORD SECURITY
Handles all input validation and bcrypt password hashing
"""

import re
from typing import Tuple
import hashlib

# Note: For production, use: pip install bcrypt
# For this demo, we'll use a simple hash (production should use bcrypt)
# import bcrypt

class Validation:
    """
    Comprehensive input validation for all CRUD operations
    
    WHY VALIDATION IS CRITICAL:
    - Prevents SQL injection before it reaches the database
    - Type checking catches numeric injection attempts
    - Length validation prevents buffer overflow
    - Format validation ensures data integrity
    """
    
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        """
        Validates username
        Rules:
        - 3-20 characters long
        - Alphanumeric and underscore only
        - No special characters that could be used in SQL injection
        """
        if not username:
            return False, "Username is required"
        
        if len(username) < 3 or len(username) > 20:
            return False, "Username must be 3-20 characters"
        
        if not re.match("^[a-zA-Z0-9_]+$", username):
            return False, "Username can only contain letters, numbers, and underscore (no quotes, dashes, or semicolons)"
        
        return True, "Valid"
    
    @staticmethod
    def validate_email(email: str) -> Tuple[bool, str]:
        """
        Validates email format
        Rules:
        - Must be valid email format
        - No SQL keywords or special characters
        - Under 100 characters
        """
        if not email:
            return False, "Email is required"
        
        if len(email) > 100:
            return False, "Email must be under 100 characters"
        
        # RFC-compliant email validation
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_pattern, email):
            return False, "Invalid email format"
        
        return True, "Valid"
    
    @staticmethod
    def validate_text(text: str, max_length: int = 100, min_length: int = 1) -> Tuple[bool, str]:
        """
        Validates general text input (names, descriptions)
        Rules:
        - Between min_length and max_length
        - No special SQL characters
        """
        if not text:
            return False, f"Text is required"
        
        if len(text) < min_length or len(text) > max_length:
            return False, f"Text must be {min_length}-{max_length} characters"
        
        # Allow alphanumeric, spaces, hyphens, and periods (for names like "Mary-Jane")
        if not re.match("^[a-zA-Z0-9\\s\\-\\.]+$", text):
            return False, "Text contains invalid characters (quotes, semicolons not allowed)"
        
        return True, "Valid"
    
    @staticmethod
    def validate_numeric_id(value: str) -> Tuple[bool, int, str]:
        """
        Validates numeric ID fields
        Rules:
        - Must be convertible to integer
        - Must be positive
        - Prevents: OR injection (1 OR 1=1), comment injection (1; DROP TABLE)
        
        Attack attempts that will be rejected:
        - "1 OR 1=1" → int() conversion fails
        - "1; DROP TABLE users" → int() conversion fails
        - "-5" → negative check rejects it
        """
        if not value:
            return False, 0, "ID is required"
        
        try:
            id_int = int(value)
            if id_int <= 0:
                return False, 0, "ID must be a positive number"
            return True, id_int, "Valid"
        except ValueError:
            return False, 0, f"ID must be a number (you entered: {value})"
    
    @staticmethod
    def validate_price(price: str) -> Tuple[bool, float, str]:
        """
        Validates price field
        Rules:
        - Must be convertible to float
        - Must be positive
        - Prevents numeric injection in price field
        """
        if not price:
            return False, 0.0, "Price is required"
        
        try:
            price_float = float(price)
            if price_float <= 0:
                return False, 0.0, "Price must be a positive number"
            if price_float > 1000000:
                return False, 0.0, "Price seems too high (max 1,000,000)"
            return True, price_float, "Valid"
        except ValueError:
            return False, 0.0, f"Price must be a number (you entered: {price})"
    
    @staticmethod
    def validate_stock(stock: str) -> Tuple[bool, int, str]:
        """
        Validates stock quantity
        Rules:
        - Must be convertible to integer
        - Must be non-negative
        """
        if not stock:
            return False, 0, "Stock is required"
        
        try:
            stock_int = int(stock)
            if stock_int < 0:
                return False, 0, "Stock cannot be negative"
            if stock_int > 1000000:
                return False, 0, "Stock seems too high (max 1,000,000)"
            return True, stock_int, "Valid"
        except ValueError:
            return False, 0, f"Stock must be a whole number (you entered: {stock})"
    
    @staticmethod
    def validate_password(password: str) -> Tuple[bool, str]:
        """
        Validates password strength
        Rules:
        - At least 5 characters (real apps should require 8+)
        - Under 100 characters
        """
        if not password:
            return False, "Password is required"
        
        if len(password) < 5:
            return False, "Password must be at least 5 characters"
        
        if len(password) > 100:
            return False, "Password must be under 100 characters"
        
        return True, "Valid"
    
    @staticmethod
    def validate_date(date_str: str) -> Tuple[bool, str]:
        """
        Validates date format
        Rules:
        - Must be in YYYY-MM-DD format
        - Prevents date injection attempts
        """
        if not date_str:
            return False, "Date is required"
        
        date_pattern = r"^\d{4}-\d{2}-\d{2}$"
        if not re.match(date_pattern, date_str):
            return False, "Date must be in YYYY-MM-DD format"
        
        try:
            from datetime import datetime
            datetime.strptime(date_str, "%Y-%m-%d")
            return True, "Valid"
        except ValueError:
            return False, "Invalid date (check month/day values)"


class PasswordSecurity:
    """
    Password security using hashing
    
    WHY WE USE HASHING:
    - Never store plain text passwords
    - Even if database is breached, passwords are protected
    - bcrypt includes salt and slow hashing for brute-force resistance
    - Same password always produces different hash (due to salt)
    
    For production, install: pip install bcrypt
    Then replace this with actual bcrypt calls
    """
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash password using secure method
        
        Production version (uncomment after: pip install bcrypt):
        import bcrypt
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
        
        This demo version uses SHA256 (NOT production-safe):
        """
        # Demo: Simple SHA256 (NOT secure - use bcrypt in production)
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """
        Verify password against hash
        
        Production version (uncomment after: pip install bcrypt):
        import bcrypt
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        
        This demo version:
        """
        # Demo: Simple SHA256 comparison (NOT secure - use bcrypt in production)
        return hashlib.sha256(password.encode()).hexdigest() == password_hash
    
    @staticmethod
    def generate_demo_hash(password: str) -> str:
        """
        Generate hash for demo passwords in database
        (Used for pre-loading sample users)
        """
        return hashlib.sha256(password.encode()).hexdigest()