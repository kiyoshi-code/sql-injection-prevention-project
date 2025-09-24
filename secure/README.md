## Secure SQL Injection Prevention Project


This project demonstrates a secure Node.js/Express server using SQLite, with protection against SQL injection attacks and secure password storage.

## Features

- Uses parameterized queries (prepared statements) for all database access to prevent SQL injection
- Validates user input to prevent malicious data
- Uses Helmet for basic HTTP security headers
- Logs suspicious activity
- Passwords are hashed using bcrypt before storage and checked securely during login

## How to run

1. Install dependencies: `npm install`
2. Initialize the database: `node init_db.js`
3. Start the server: `node server.js`

## Endpoints

- `/login` (POST): Secure login endpoint

## Security Notes

- Never concatenate user input directly into SQL queries
- Always use parameterized queries
- Validate and sanitize all user input
- Passwords are never stored in plain text; bcrypt is used for hashing

## Demo Credentials

- Username: `admin`
- Password: `admin123` (hashed in DB)
