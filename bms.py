import json
import os
import bcrypt


class BuildingSystem:
    def __init__(self):
        self.users_file = "users.json"
        self.users = []
        self.load_users()

    def load_users(self):
        if not os.path.exists(self.users_file):
            print("⚠ No users.json found — creating default admin...")
            default_admin = {
                "username": "admin",
                "password": bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
            }
            self.users.append(default_admin)
            self.save_users()
            print("✔ Default admin created: admin / admin123")
        else:
            with open(self.users_file, "r") as f:
                self.users = json.load(f)

    def save_users(self):
        with open(self.users_file, "w") as f:
            json.dump(self.users, f, indent=4)

    # Render login (no input allowed)
    def login(self):
        username = os.getenv("ADMIN_USER")
        password = os.getenv("ADMIN_PASS")

        if not username or not password:
            print("❌ Missing ADMIN_USER or ADMIN_PASS environment variables!")
            return None

        for user in self.users:
            if user["username"] == username:
                if bcrypt.checkpw(password.encode(), user["password"].encode()):
                    print("✔ Login successful (Render mode)")
                    return "admin"

        print("❌ Login failed!")
        return None

    # Dummy placeholder functions
    def add_family(self):
        print("Add family - placeholder")

    def view_vacant_flats(self):
        print("Vacant flats - placeholder")

    def post_notice(self):
        print("Post notice - placeholder")


def main():
    system = BuildingSystem()

    # Render Login
    user = system.login()

    if user == "admin":
        print("Admin panel loaded successfully on Render.")
    else:
        print("❌ Login failed!")
        return


if __name__ == "__main__":
    main()
