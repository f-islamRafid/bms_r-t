from datetime import datetime
import json
import bcrypt
import os

# --- Constants & Utility ---

class Notice:
    def __init__(self, title, content, date_posted=None):
        self.title = title
        self.content = content
        self.date_posted = date_posted if date_posted else datetime.now().strftime("%Y-%m-%d %H:%M")

    def __str__(self):
        return f"[{self.date_posted}] **{self.title}**\n{self.content}"

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
        
        # 🔑 Hashing password if not already a hash
        if password and not password.startswith("$2b$"):
            self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        else:
            self.password_hash = password
        self.nid = nid

    def check_password(self, password):
        """Checks if the given password matches the stored hash."""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def to_dict(self):
        """Prepares the object for JSON serialization."""
        return {
            "flat_no": self.flat_no,
            "head_member": self.head_member,
            "phone": self.phone,
            "members": self.members,
            "email": self.email,
            "password_hash": self.password_hash,
            "nid": self.nid,
        }

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
        """Loads or creates the config.json file."""
        try:
            with open("config.json", "r") as f:
                config = json.load(f)
                self.admin_email = config["admin_email"]
                self.admin_password_hash = config["admin_password_hash"].encode('utf-8')
                self.total_flats = set(config["total_flats"])
        except (FileNotFoundError, KeyError):
            # Fallback/creation logic (use custom defaults here if you haven't used env vars)
            self.admin_email = os.getenv("BMS_ADMIN_EMAIL", "admin@bms.com")
            admin_password = os.getenv("BMS_ADMIN_PASSWORD", "supersecure")
            num_floors = int(os.getenv("BMS_FLOORS", 3))
            units_per_floor = int(os.getenv("BMS_UNITS_PER_FLOOR", 2))

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
            print(f"Config created with {len(flats_list)} flats. Default Admin: {self.admin_email} / {admin_password}")

    def save_data(self):
        """Saves family and notice data to data.json."""
        families_data = [f.to_dict() for f in self.families]
        notices_data = [vars(n) for n in self.notices]
        data = {"families": families_data, "notices": notices_data}
        with open("data.json", "w") as f:
            json.dump(data, f, indent=4)

    def load_data(self):
        """Loads family and notice data from data.json."""
        try:
            with open("data.json", "r") as f:
                data = json.load(f)
                
                self.families = []
                for f_data in data.get("families", []):
                    family_obj = Family(
                        flat_no=f_data["flat_no"],
                        head_member=f_data["head_member"],
                        phone=f_data["phone"],
                        members=f_data["members"],
                        email=f_data["email"],
                        password=f_data.get("password_hash"),
                        nid=f_data["nid"]
                    )
                    family_obj.password_hash = f_data.get("password_hash")
                    self.families.append(family_obj)

                self.notices = [Notice(**n) for n in data.get("notices", [])]
        except FileNotFoundError:
            self.families, self.notices = [], []
        except Exception as e:
            print(f"❌ Error loading data: {e}")
            self.families, self.notices = [], []

    def authenticate_admin(self, email, password):
        """Authenticates an administrator. Exposed for targeted login."""
        if email != self.admin_email:
            return False
        if bcrypt.checkpw(password.encode('utf-8'), self.admin_password_hash):
            return "admin"
        return False

    def get_family_user(self, email, password):
        """Authenticates a family user using email and password. (UPDATED LOGIC)"""
        for family in self.families:
            if family.email.lower() == email.lower(): # Match on email
                if family.check_password(password):
                    return family
                break # Email found, but password failed
        return None

    def add_family(self, flat_no, head_member, phone, members, email, password, nid):
        """Adds a new family to the system."""
        flat_no = flat_no.upper()
        if flat_no not in self.total_flats:
            print(f"\nInvalid flat number: {flat_no}. Must be one of: {sorted(self.total_flats)}")
            return
        if any(f.flat_no == flat_no for f in self.families):
            print(f"\nFlat {flat_no} is already occupied.")
            return

        new_family = Family(flat_no, head_member, phone, members, email, password, nid)
        self.families.append(new_family)
        self.save_data()
        print(f"\nFamily added to flat **{flat_no}**. Head: {head_member}.")

    def view_vacant_flats(self):
        """Displays all unoccupied flats."""
        occupied = {f.flat_no for f in self.families}
        vacant = self.total_flats - occupied
        print("\n--- Vacant Flats ---")
        if vacant:
            print("Flats available:", sorted(vacant))
        else:
            print("The building is fully occupied!")
        print("----------------------")

    def post_notice(self, title, content):
        """Posts a new building notice."""
        self.notices.append(Notice(title, content))
        self.save_data()
        print(f"\n📢 Notice posted: **{title}**")
    
    def view_notices(self):
        """Displays all posted notices."""
        print("\n--- 📢 Building Notices (Latest First) ---")
        if not self.notices:
            print("No notices posted yet.")
            print("------------------------------------------")
            return

        sorted_notices = sorted(self.notices, key=lambda n: n.date_posted, reverse=True)
        for i, notice in enumerate(sorted_notices):
            print(f"[{i+1}] {notice}")
            print("---")


# -----------------------------
# Menu Functions
# -----------------------------

def run_admin_menu(system):
    """Admin interactive menu."""
    while True:
        print("\n--- Admin Menu ---")
        print("1. Add New Family")
        print("2. View Vacant Flats")
        print("3. Post New Notice")
        print("4. View All Notices")
        print("5. Logout")
        
        choice = input("Enter choice (1-5): ").strip()

        if choice == '1':
            print("\n--- Add Family Details ---")
            flat_no = input("Flat No (e.g., 1A): ").upper().strip()
            if flat_no not in system.total_flats:
                 print(f"❌ Error: Flat {flat_no} is not a valid flat number.")
                 continue
            if any(f.flat_no == flat_no for f in system.families):
                 print(f"❌ Error: Flat {flat_no} is already occupied.")
                 continue

            head_member = input("Head Member Name: ").strip()
            phone = input("Phone Number: ").strip()
            
            while True:
                try:
                    members = int(input("Number of Members: ").strip())
                    break
                except ValueError:
                    print("Invalid number. Please enter an integer.")

            email = input("Email: ").strip()
            password = input("Password (will be hashed): ").strip()
            nid = input("NID/ID Card No: ").strip()
            
            system.add_family(flat_no, head_member, phone, members, email, password, nid)

        elif choice == '2':
            system.view_vacant_flats()
        
        elif choice == '3':
            title = input("Notice Title: ").strip()
            content = input("Notice Content: ").strip()
            if title and content:
                system.post_notice(title, content)
            else:
                print("Title and content cannot be empty.")

        elif choice == '4':
            system.view_notices()

        elif choice == '5':
            print("Admin logged out.")
            break
        
        else:
            print("Invalid choice. Please try again.")

def run_family_menu(system, user):
    """Family user interactive menu."""
    while True:
        print(f"\n--- Flat {user.flat_no} Menu (Head: {user.head_member}) ---")
        print("1. View My Details")
        print("2. View Building Notices")
        print("3. Logout")
        
        choice = input("Enter choice (1-3): ").strip()

        if choice == '1':
            print("\n--- Your Details ---")
            print(f"Flat No: {user.flat_no}")
            print(f"Head Member: {user.head_member}")
            print(f"Phone: {user.phone}")
            print(f"Email: {user.email}")
            print(f"Members: {user.members}")
            print(f"NID/ID: {user.nid}")
            print("--------------------")

        elif choice == '2':
            system.view_notices()
        
        elif choice == '3':
            print(f"Family from flat {user.flat_no} logged out.")
            break
        
        else:
            print("Invalid choice. Please try again.")


# -----------------------------
# Main Program (Interactive)
# -----------------------------

def main():
    """Initializes the system and runs the interactive login process with a user-type choice."""
    print("--- Building Management System (CLI) ---")
    system = BuildingSystem()
    
    while True:
        print("\n================================")
        print("   WHO ARE YOU?")
        print("================================")
        print("1. Admin")
        print("2. Family User (Flat Owner)")
        print("3. Exit")
        print("--------------------------------")

        user_type_choice = input("Enter choice (1-3): ").strip()

        if user_type_choice == '1':
            # --- Admin Login ---
            print("\n--- Admin Login ---")
            email = input("Enter Admin Email: ").strip()
            password = input("Enter Password: ").strip()

            user = system.authenticate_admin(email, password)

            if user == "admin":
                print(f"Admin logged in successfully!")
                run_admin_menu(system)
            else:
                print("Login failed! Invalid Admin Email or Password.")

        elif user_type_choice == '2':
            # --- Family User Login (UPDATED PROMPT) ---
            print("\n--- 🏡 Family Login ---")
            email = input("Enter User Email: ").strip() # Changed from Flat No
            password = input("Enter Password: ").strip()

            user = system.get_family_user(email, password) # Changed function call to use email

            if isinstance(user, Family):
                print(f"✅ Flat {user.flat_no} logged in successfully!")
                run_family_menu(system, user)
            else:
                print("❌ Login failed! Invalid User Email or Password.")

        elif user_type_choice == '3':
            print("Goodbye! Shutting down BMS.")
            break

        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
