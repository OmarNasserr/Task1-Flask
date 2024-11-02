### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/OmarNasserr/Task1-Flask.git
   
2. Install Requirements:
   ```bash
   cd Task1-Flask
   pip install -r requirements.txt
3. Run Server:
   ```bash
   python app.py

## API Endpoints

### User Endpoints

- **POST /register**
    - **Description**: Register a new user by providing a username and password.
    - **Request Body**:
      ```json
      {
        "username": "string",
        "password": "string"
      }
      ```
    - **Response (Success)**:
      ```json
      {
        "message": "User registered successfully",
        "id": "string",
        "username": "string",
        "token": "string"
      }
      ```

- **POST /login**
    - **Description**: Log in an existing user with valid credentials.
    - **Request Body**:
      ```json
      {
        "username": "string",
        "password": "string"
      }
      ```
    - **Response (Success)**:
      ```json
      {
        "message": "Login successful",
        "id": "string",
        "username": "string",
        "token": "string"
      }
      ```

- **POST /logout**
    - **Description**: Log out the currently logged-in user.
    - **Request Header**:
      ```
      Authorization: Bearer <token>
      ```
    - **Response (Success)**:
      ```json
      {
        "message": "Logout successful"
      }
      ```

### Book Endpoints

- **GET /books**
    - **Description**: List all books available in the system.
    - **Request Header**:
      ```
      Authorization: Bearer <token>
      ```
    - **Response (Success)**:
      ```json
      [
        {
          "id": "string",
          "title": "string",
          "author": "string",
          "description": "string"
        },
        ...
      ]
      ```

- **GET /books/<book_id>**
    - **Description**: Retrieve details of a specific book by its ID.
    - **Request Header**:
      ```
      Authorization: Bearer <token>
      ```
    - **Response (Success)**:
      ```json
      {
        "id": "string",
        "title": "string",
        "author": "string",
        "description": "string"
      }
      ```

- **POST /books**
    - **Description**: Add a new book with details like title, author, and description.
    - **Request Header**:
      ```
      Authorization: Bearer <token>
      ```
    - **Request Body**:
      ```json
      {
        "title": "string",
        "author": "string",
        "description": "string"
      }
      ```
    - **Response (Success)**:
      ```json
      {
        "message": "Book added successfully",
        "id": "string",
        "title": "string",
        "author": "string",
        "description": "string"
      }
      ```

- **PUT /books/<book_id>**
    - **Description**: Update an existing book's details by its ID.
    - **Request Header**:
      ```
      Authorization: Bearer <token>
      ```
    - **Request Body**:
      ```json
      {
        "title": "string",
        "author": "string",
        "description": "string"
      }
      ```
    - **Response (Success)**:
      ```json
      {
        "message": "Book updated successfully",
        "id": "string",
        "title": "string",
        "author": "string",
        "description": "string"
      }
      ```

- **DELETE /books/<book_id>**
    - **Description**: Delete a book from the system by its ID.
    - **Request Header**:
      ```
      Authorization: Bearer <token>
      ```
    - **Response (Success)**:
      ```json
      {
        "message": "Book was deleted successfully"
      }
      ```
