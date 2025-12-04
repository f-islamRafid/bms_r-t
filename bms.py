from datetime import datetime
import json
import bcrypt

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
        self.nid = NotImplemented

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
            self.first_time_setup()

    def first_time_setup(self):
        print("\n--- First-Time Setup ---")
        self.admin_email = input("Enter admin email: ")
        password = input("Enter admin password: ")
        self.admin_password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        num_floors = int(input("Number of floors: "))
        units_per_floor = int(input("Units per floor: "))
        flats_list = [f"{floor}{chr(ord('A')+i)}" for floor in range(1, num_floors+1) for i in range(units_per_floor)]
        self.total_flats = set(flats_list)

        config = {
            "admin_email": self.admin_email,
            "admin_password_hash": self.admin_password_hash.decode('utf-8'),
            "total_flats": sorted(flats_list)
        }
        with open("config.json", "w") as f:
            json.dump(config, f, indent=4)
        print("Setup complete!\nGenerated flats:", sorted(flats_list))

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

    def login(self, email, password):
        if email == self.admin_email and bcrypt.checkpw(password.encode('utf-8'), self.admin_password_hash):
            return "admin"
        for f in self.families:
            if f.email == email and f.password == password:
                return f
        return None

    def add_family(self):
        flat_no = input("Flat no: ").upper()
        if flat_no not in self.total_flats:
            print("Invalid flat number."); return
        if any(f.flat_no == flat_no for f in self.families):
            print("Flat already occupied."); return
        head_member = input("Head member: ")
        phone = input("Phone: ")
        email = input("Email: ")
        password = input("Password: ")
        nid = input("NID: ")
        members = int(input("Family members: "))
        self.families.append(Family(flat_no, head_member, phone, members, email, password, nid))
        self.save_data()
        print("Family added successfully.")

    def view_vacant_flats(self):
        occupied = {f.flat_no for f in self.families}
        vacant = self.total_flats - occupied
        print("Vacant flats:", sorted(vacant))

    def post_notice(self):
        title = input("Notice title: ")
        content = input("Notice content: ")
        self.notices.append(Notice(title, content))
        self.save_data()
        print("Notice posted.")


# -----------------------------

# Main Program

# -----------------------------

def main():
    system = BuildingSystem()
    email = input("Email: ")
    password = input("Password: ")
    user = system.login(email, password)

    if user == "admin":
        print("Admin logged in!")
        while True:
            print("\n1. Add Family\n2. View Vacant Flats\n3. Post Notice\n4. Logout")
            choice = input("Choice: ")
            if choice == "1":
                system.add_family()
            elif choice == "2":
                system.view_vacant_flats()
            elif choice == "3":
                system.post_notice()
            elif choice == "4":
                break
            else:
                print("Invalid choice.")
    elif user:
        print(f"Family {user.head_member} logged in!")
    else:
        print("Login failed.")

if __name__ == "__main__":
    main() 
