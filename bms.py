from datetime import datetime
import json
import bcrypt
import os

import os, json, bcrypt

# Auto-create default admin if users.json does not exist
if not os.path.exists("users.json"):
    print("⚠ No users.json found — creating default admin...")

    default_admin = {
        "username": "admin",
        "password": bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode(),
        "role": "admin"
    }

    with open("users.json", "w") as f:
        json.dump({"users": [default_admin]}, f, indent=4)

    print("✔ Default admin created: admin / admin123")



# -----------------------------

# Classes

# -----------------------------

class Family:
    def __init__(self, flat_no, head_member, phone, members, email, password, nid):
        self.flat_no = flat_no
        self.head_member = head_member
        self.phone = phone
        self.members = members
        self.email = email
        self.password = password
        self.nid = nid

    class Notice:
        def __init__(self, title, content, date_posted=None):
            self.title = title
            self.content = content
            self.date_posted = date_posted if date_posted else datetime.now().strftime("%Y-%m-%d %H:%M")

# -----------------------------

# Building System

# -----------------------------

class BuildingSystem:
    def __init__(self):
        self.families = []
        self.notices = []
        self.admin_email = None
        self.admin_password_hash = None
        self.total_flats = set()


        self._load_config()
        self.load_data()

    def _load_config(self):
        try:
            with open("config.json", "r") as f:
                config = json.load(f)
                self.admin_email = config["admin_email"]
                self.admin_password_hash = config["admin_password_hash"].encode('utf-8')
                self.total_flats = set(config["total_flats"])
        except (FileNotFoundError, KeyError):
            self.admin_email = os.getenv("BMS_ADMIN_EMAIL")
            admin_password = os.getenv("BMS_ADMIN_PASSWORD")
            num_floors = int(os.getenv("BMS_FLOORS", 3))
            units_per_floor = int(os.getenv("BMS_UNITS_PER_FLOOR", 2))

            if not self.admin_email or not admin_password:
                raise RuntimeError("Admin credentials missing. Set BMS_ADMIN_EMAIL and BMS_ADMIN_PASSWORD.")

            self.admin_password_hash = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
            flats_list = [f"{floor}{chr(ord('A') + i)}" for floor in range(1, num_floors + 1) for i in range(units_per_floor)]
            self.total_flats = set(flats_list)

            config = {
                "admin_email": self.admin_email,
                "admin_password_hash": self.admin_password_hash.decode('utf-8'),
                "total_flats": sorted(flats_list)
            }
            with open("config.json", "w") as f:
                json.dump(config, f, indent=4)
            print(f"✅ Config created with {len(flats_list)} flats.")

    def save_data(self):
        data = {"families": [vars(f) for f in self.families], "notices": [vars(n) for n in self.notices]}
        with open("data.json", "w") as f:
            json.dump(data, f, indent=4)

    def load_data(self):
        try:
            with open("data.json", "r") as f:
                data = json.load(f)
                self.families = [Family(**f) for f in data.get("families", [])]
                self.notices = [Notice(**n) for n in data.get("notices", [])]
        except FileNotFoundError:
            self.families, self.notices = [], []

    def login(self):
        import os

    # Read login from environment variables
        username = os.getenv("ADMIN_USER")
        password = os.getenv("ADMIN_PASS")

        if not username or not password:
            print("❌ No ADMIN_USER or ADMIN_PASS in environment.")
            return False

        for user in self.users:
            if user["username"] == username:
                if bcrypt.checkpw(password.encode(), user["password"].encode()):
                    print("✔ Logged in successfully (Render mode)")
                    return True

        print("❌ Login failed!")
        return False


    def add_family(self, flat_no, head_member, phone, members, email, password, nid):
        if flat_no not in self.total_flats:
            print(f"❌ Invalid flat number: {flat_no}")
            return
        if any(f.flat_no == flat_no for f in self.families):
            print(f"❌ Flat {flat_no} is already occupied.")
            return
        self.families.append(Family(flat_no, head_member, phone, members, email, password, nid))
        self.save_data()
        print(f"✅ Family added to flat {flat_no}")

    def view_vacant_flats(self):
        occupied = {f.flat_no for f in self.families}
        vacant = self.total_flats - occupied
        print("🏠 Vacant flats:", sorted(vacant))

    def post_notice(self, title, content):
        self.notices.append(Notice(title, content))
        self.save_data()
        print(f"📢 Notice posted: {title}")


# -----------------------------

# Main Program (non-interactive)

# -----------------------------

def main():
    system = BuildingSystem()

    email = os.getenv("BMS_ADMIN_EMAIL")
    password = os.getenv("BMS_ADMIN_PASSWORD")

    user = system.login(email, password)

    if user == "admin":
        print(f"✅ Admin {email} logged in successfully!")
        system.view_vacant_flats()

        if os.getenv("BMS_ADD_FAMILY_FLAT"):
            system.add_family(
                flat_no=os.getenv("BMS_ADD_FAMILY_FLAT"),
                head_member=os.getenv("BMS_ADD_FAMILY_HEAD", "John Doe"),
                phone=os.getenv("BMS_ADD_FAMILY_PHONE", "0123456789"),
                members=int(os.getenv("BMS_ADD_FAMILY_MEMBERS", 3)),
                email=os.getenv("BMS_ADD_FAMILY_EMAIL", "family@example.com"),
                password=os.getenv("BMS_ADD_FAMILY_PASSWORD", "password"),
                nid=os.getenv("BMS_ADD_FAMILY_NID", "0000000000")
            )

        if os.getenv("BMS_POST_NOTICE_TITLE"):
            system.post_notice(
                title=os.getenv("BMS_POST_NOTICE_TITLE"),
                content=os.getenv("BMS_POST_NOTICE_CONTENT", "Notice content")
            )

    elif user:
        print(f"Family {user.head_member} (Flat {user.flat_no}) logged in!")
    else:
        print("❌ Login failed!")


if __name__ == "__main__":
    main()
