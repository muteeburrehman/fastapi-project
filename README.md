# FastAPI User Registration and Authentication

This is a simple FastAPI project that provides user registration, login, and logout functionalities.

## Features

- User registration with hashed password storage.
- User login with authentication using bcrypt for password verification.
- Basic structure for a token-based authentication system.
- Logout API (Note: Logout may involve client-side actions for token/session revocation).

## Getting Started

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/muteeburrehman/fastapi-user-auth.git
   cd fastapi-user-auth

2. Install the dependencies
   ```bash
   pip install -r requirements.txt
   ```
3. Running the Application
   ```bash
   uvicorn main:app --reload
   ```
- The FastAPI application will be running at http://127.0.0.1:8000. 
- You can access the interactive documentation at http://127.0.0.1:8000/docs and explore the available APIs.
  
Usage
1. User Registeration
   
- Endpoint: POST /register
```bash 
Request Body:{
  "name": "John Doe",
  "email": "john.doe@example.com",
  "password": "secretpassword"
}
```

2. User Login
- Endpoint: POST /login
```bash
Request Body:
{
  "username": "john.doe@example.com",
  "password": "secretpassword"
}
```

3. User Logout 
- Endpoint: POST /logout
- Note: Logout in a token-based system usually involves client-side actions for token revocation.

Dependencies:

- FastAPI
- SQLAlchemy
- bcrypt
- passlib

