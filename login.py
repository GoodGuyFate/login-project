import bcrypt
import re
import sqlite3


def login(username, password, database_file="credentials.db"):
    try:
        # Connect to the database
        conn = sqlite3.connect(database_file)
        cursor = conn.cursor()

        # Prepare SQL statement to select password hash
        sql = "SELECT password FROM Users WHERE username = ?"

        # Execute the statement with username
        cursor.execute(sql, (username,))

        # Fetch the first (and hopefully only) result
        stored_hash = cursor.fetchone()

        if stored_hash: 
            # Decode the stored hash (assuming it's a byte string)
            stored_hash_bytes = stored_hash[0]

            # Encode password using utf-8 for consistent hashing
            password_utf8 = password.encode("utf-8")

            # Verify password using bcrypt.checkpw (compares password with stored hash)
            if bcrypt.checkpw(password_utf8, stored_hash_bytes):
                print(f"Login successful for user '{username}'!")
                return True
            else:
                print("Invalid password!")
                return False
        else:
            print(f"Username '{username}' not found!")
            return False

    except sqlite3.Error as e:
        print(f"Error during login: {e}")
        return False

    finally:
        # Close the connection
        if conn:
            conn.close()


def register(username, password, database_file="credentials.db"):
    # Password complexity check using regular expression
    password_regex = (
        r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?.&])[A-Za-z\d@$!%*?.&]{8,}$"
    )

    if not re.match(password_regex, password):
        print("Error: Password must be at least 8 characters and contain:")
        print("  * Uppercase letter (A-Z)")
        print("  * Lowercase letter (a-z)")
        print("  * Number (0-9)")
        print("  * Special character (@.$!%*?&)")
        return False

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    try:
        # Connect to the database
        conn = sqlite3.connect(database_file)
        cursor = conn.cursor()

        # Prepare SQL statement to check for duplicate usernames
        sql_check = "SELECT username FROM Users WHERE username = ?"
        cursor.execute(sql_check, (username,))

        # Check if username exists (fetch only the first row)
        existing_user = cursor.fetchone()

        if existing_user:
            print(f"Error: Username '{username}' already exists!")
            return False

        # Username not found, proceed with registration
        sql_insert = "INSERT INTO Users (username, password) VALUES (?, ?)"
        cursor.execute(sql_insert, (username, hashed_password))
        conn.commit()  # Save changes to the database

        print(f"User '{username}' registered successfully!")
        return True

    except sqlite3.Error as e:
        print(f"Error during registration: {e}")
        return False

    finally:
        # Close the connection
        if conn:
            conn.close()


def main():
    # Valid Login Test
    username = "alice"
    password = "wonderland"
    success = login(username, password)
    print(f"Valid Login Test (alice:wonderland): {success}")  # Should print True

    # Invalid Username Test
    username = "charlie"
    password = "unknown"
    success = login(username, password)
    print(f"Invalid Username Test (charlie:unknown): {success}")  # Should print False

    # Invalid Password Test
    username = "bob"
    password = "wrongpassword"
    success = login(username, password)
    print(f"Invalid Password Test (bob:wrongpassword): {success}")  # Should print False


if __name__ == "__main__":
    main()
