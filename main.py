from login import login, register


def main():
    while True:
        print("Menu:")
        print("1. Login")
        print("2. Register")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            username = input("Enter Username: ")
            password = input("Enter Password: ")
            if login(username, password):
                print("Login Successful!")
            else:
                print("Login Failed!")
        elif choice == "2":
            username = input("Enter Username: ")
            password = input("Enter Password: ")
            if register(username, password):
                print("Registration Successful!")
            else:
                print("Registration Failed!")
        elif choice == "3":
            break
        else:
            print("Invalid choice!")


if __name__ == "__main__":
    main()
