"""
SQL INJECTION PREVENTION PROJECT - PART 1: DATABASE SETUP
Handles database initialization with proper schema and relationships
"""

import sqlite3

class Database:
    """
    Database initialization with complete schema
    - Users table: For authentication and user management
    - Products table: For inventory management
    - Orders table: For order management with foreign key to users
    - Relationships: orders → users (many-to-one)
    """
    
    def __init__(self, db_name=':memory:'):
        """Initialize database connection"""
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.cursor.execute("PRAGMA foreign_keys = ON")
        self.create_tables()
    
    def create_tables(self):
        """Create all necessary tables with proper relationships"""
        
        # Users table - stores user credentials and profile
        # password_hash: Stores bcrypt hashed password (never store plain text)
        self.cursor.execute('''
            CREATE TABLE users (
                user_id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TEXT NOT NULL
            )
        ''')
        
        # Products table - stores product information
        self.cursor.execute('''
            CREATE TABLE products (
                product_id INTEGER PRIMARY KEY,
                product_name TEXT NOT NULL,
                category TEXT NOT NULL,
                price REAL NOT NULL,
                stock INTEGER NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL
            )
        ''')
        
        # Orders table - stores orders with foreign key to users
        # Demonstrates: one user can have many orders (one-to-many relationship)
        self.cursor.execute('''
            CREATE TABLE orders (
                order_id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                order_date TEXT NOT NULL,
                total_amount REAL NOT NULL,
                status TEXT DEFAULT 'pending',
                shipping_address TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        
        # Insert sample data
        self._insert_sample_data()
        self.conn.commit()
    
    def _insert_sample_data(self):
        """Insert sample data for testing"""
        
        # Sample users (passwords will be hashed using bcrypt in validation.py)
        users = [
            (1, 'john_doe', 'hashed_pass123', 'john@email.com', 'John Doe', 'user', '2024-01-01'),
            (2, 'admin', 'hashed_admin@pass', 'admin@company.com', 'Admin User', 'admin', '2024-01-01'),
            (3, 'jane_smith', 'hashed_jane@pass', 'jane@email.com', 'Jane Smith', 'user', '2024-01-05'),
        ]
        self.cursor.executemany(
            'INSERT INTO users VALUES (?,?,?,?,?,?,?)',
            users
        )
        
        # Sample products
        products = [
            (1, 'Laptop Pro', 'Electronics', 1299.99, 10, 'High-end laptop', '2024-01-01'),
            (2, 'Wireless Mouse', 'Electronics', 29.99, 150, 'Ergonomic design', '2024-01-02'),
            (3, 'USB Cable', 'Accessories', 9.99, 500, '2-meter cable', '2024-01-03'),
        ]
        self.cursor.executemany(
            'INSERT INTO products VALUES (?,?,?,?,?,?,?)',
            products
        )
        
        # Sample orders (linked to users via foreign key)
        orders = [
            (1, 1, '2024-01-15', 1299.99, 'Shipped', '123 Main St, USA'),
            (2, 2, '2024-01-20', 29.99, 'Delivered', '456 Oak Ave, USA'),
            (3, 3, '2024-02-01', 49.99, 'Processing', '789 Oak St, Canada'),
        ]
        self.cursor.executemany(
            'INSERT INTO orders VALUES (?,?,?,?,?,?)',
            orders
        )
    
    def get_connection(self):
        """Get database connection"""
        return self.conn
    
    def get_cursor(self):
        """Get database cursor"""
        return self.cursor
    
    def close(self):
        """Close database connection"""
        self.conn.close()