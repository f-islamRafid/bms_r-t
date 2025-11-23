from datetime import datetime
import json
import socket
import threading
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
        self.nid = nid


class Notice:
    def __init__(self, title, content, date_posted=None):
        self.title = title
        self.content = content
        if date_posted is None:
            self.date_posted = datetime.now().strftime("%Y-%m-%d %H:%M")
        else:
            self.date_posted = date_posted


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
                self.total_flats = set(config["total_flats"])  # Load the master list of flats
        except (FileNotFoundError, KeyError):
            print("--- First-Time Setup ---")
            self._first_time_setup()

    def _first_time_setup(self):

        # --- Admin Account Setup ---
        print("\n[Admin Account Creation]")
        self.admin_email = input("Enter the new admin email: ")
        password = input("Enter the new admin password: ")
        salt = bcrypt.gensalt()
        self.admin_password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)

        # --- Building Structure Setup ---
        print("\n[Building Layout Configuration]")
        while True:
            try:
                num_floors = int(input("How many floors are in the building? "))
                units_per_floor = int(input("How many flats per floor? "))
                if num_floors > 0 and units_per_floor > 0:
                    break
                else:
                    print("Please enter positive numbers.")
            except ValueError:
                print("Invalid input. Please enter numbers.")

        flats_list = []
        for floor in range(1, num_floors + 1):
            for i in range(units_per_floor):
                unit_char = chr(ord('A') + i)  # Generates A, B, C...
                flats_list.append(f"{floor}{unit_char}")

        self.total_flats = set(flats_list)
        print(f"\nGenerated flats: {sorted(flats_list)}")

        config = {
            "admin_email": self.admin_email,
            "admin_password_hash": self.admin_password_hash.decode('utf-8'),
            "total_flats": sorted(flats_list)  # Save as a sorted list
        }
        with open("config.json", "w") as f:
            json.dump(config, f, indent=4)
        print("\n✅ Admin account and building layout created successfully!")

    def add_family(self):
        flat_no = input("Flat no: ").upper()


        if flat_no not in self.total_flats:
            print(f"Error: '{flat_no}' is not a valid flat number in this building.")
            return


        for f in self.families:
            if f.flat_no == flat_no:
                print(f"Error: Flat {flat_no} is already occupied.")
                return

        # ... (rest of the add_family function is the same)
        head_member = input("Name of head member: ")
        phone = input("Phone: ")
        email = input("Email: ")
        password = input("Password: ")
        nid = input("NID no: ")
        while True:
            try:
                members = int(input("Total Family Member: "))
                break
            except ValueError:
                print("Invalid input. Please enter a whole number.")
        family = Family(flat_no, head_member, phone, members, email, password, nid)
        self.families.append(family)
        self.save_data()
        print(f"Family for Flat {flat_no} added successfully!")

    # view vacant flats ---

    def view_vacant_flats(self):

        occupied_flats = {f.flat_no for f in self.families}
        vacant_flats = self.total_flats - occupied_flats

        print("\n" + "=" * 25)
        print("--- Building Occupancy ---")
        if not vacant_flats:
            print("Status: All flats are currently occupied.")
        else:
            print("Vacant Flats:")
            for flat in sorted(list(vacant_flats)):
                print(f"  - {flat}")

        print(f"\nSummary: {len(occupied_flats)} occupied | {len(vacant_flats)} vacant")
        print("=" * 25)


    def save_data(self):
        data = {"families": [vars(f) for f in self.families], "notices": [vars(n) for n in self.notices]}
        with open("data.json", "w") as f: json.dump(data, f, indent=4)

    def load_data(self):
        try:
            with open("data.json", "r") as f:
                data = json.load(f)
                self.families = [Family(**f) for f in data.get("families", [])]
                self.notices = [Notice(**n) for n in data.get("notices", [])]
        except FileNotFoundError:
            self.families, self.notices = [], []

    def login(self, email, password):
        if email == self.admin_email and bcrypt.checkpw(password.encode('utf-8'),
            self.admin_password_hash): return "admin"
        for family in self.families:
            if family.email == email and family.password == password: return family
        return None

    def remove_family(self):
        flat_no = input("Enter Flat no to remove: ").upper()
        family_to_remove = next((f for f in self.families if f.flat_no == flat_no), None)
        if family_to_remove:
            self.families.remove(family_to_remove)
            self.save_data()
            print(f"Family in Flat {flat_no} removed successfully! This flat is now vacant.")
        else:
            print("No family found with that flat number.")

    def post_notice(self):
        title = input("Notice Title: ")
        content = input("Notice Content: ")
        self.notices.append(Notice(title, content))
        self.save_data();
        print("Notice posted successfully!")

    def view_all_flats(self):
        if not self.families: print("No families found."); return
        print("\n--- All Occupied Flats ---")
        for f in sorted(self.families, key=lambda x: x.flat_no):
            print(f"Flat: {f.flat_no} | Head: {f.head_member} | NID: {f.nid} | Phone: {f.phone} | Members: {f.members}")

    def view_notices(self):
        if not self.notices: print("No notices found."); return
        print("\n--- Building Notices ---")
        for n in reversed(self.notices): print(f"[{n.date_posted}] - {n.title}\n\t{n.content}\n")

    def start_chat_client(self, user):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(('127.0.0.1', 12345))
        except ConnectionRefusedError:
            print("\n[!] Chat server is not running."); return
        chat_name = f"{user.head_member} (Flat {user.flat_no})" if isinstance(user, Family) else "SYSTEM ADMIN"
        print("\n--- Welcome to the Group Chat! (Type 'quit' to exit) ---\n")

        def receive_messages():
            while True:
                try:
                    message = client_socket.recv(1024).decode('utf-8')
                    if not message: print("\n[!] Disconnected from server."); break
                    print(f"\r{message}\n> ", end="")
                except:
                    break

        receive_thread = threading.Thread(target=receive_messages);
        receive_thread.daemon = True;
        receive_thread.start()
        while True:
            message_to_send = input("> ")
            if message_to_send.lower() == 'quit': break
            full_message = f"{chat_name}: {message_to_send}"
            client_socket.send(full_message.encode('utf-8'))
        client_socket.close();
        print("\n--- You have left the chat. ---")


# -----------------------------
# Main Program
# -----------------------------
def main():
    system = BuildingSystem()
    while True:
        print("\n\t" + "=" * 40);
        print("\t\t\tWelcome to Rangs Kanon\n\t\t  Building Management System");
        print("\t\t(Developed by Tasfiq and Rafid)");
        print("\t"+"=" * 40)
        user = system.login(input("Email: "), input("Password: "))

        if user == "admin":
            while True:
                print("\n--- Admin Panel ---")
                print(
                    "1. Add Family\n2. Remove Family\n3. Post Notice\n4. View All Occupied Flats\n5. View Vacant Flats\n6. View Notices\n7. Join Group Chat\n8. Logout")
                try:
                    choice = int(input("Enter option: "))
                except ValueError:
                    print("Enter a valid number!"); continue

                if choice == 1:
                    system.add_family()
                elif choice == 2:
                    system.remove_family()
                elif choice == 3:
                    system.post_notice()
                elif choice == 4:
                    system.view_all_flats()
                elif choice == 5:
                    system.view_vacant_flats()  # New option call
                elif choice == 6:
                    system.view_notices()
                elif choice == 7:
                    system.start_chat_client("admin")
                elif choice == 8:
                    print("Logging out..."); break
                else:
                    print("Invalid! Choose 1 to 8.")

        elif isinstance(user, Family):
            while True:
                print(f"\nWelcome! {user.head_member} (Flat {user.flat_no})")
                print("1. View My Info\n2. View Notices\n3. Join Group Chat\n4. Logout")
                try:
                    choice = int(input("Enter option: "))
                except ValueError:
                    print("Enter a valid number!"); continue
                if choice == 1:
                    print(
                        f"\n--- My Information ---\nFlat: {user.flat_no}\nHead: {user.head_member}\nNID: {user.nid}\nPhone: {user.phone}\nMembers: {user.members}")
                elif choice == 2:
                    system.view_notices()
                elif choice == 3:
                    system.start_chat_client(user)
                elif choice == 4:
                    print("Logging out..."); break
                else:
                    print("Invalid! Choose 1 to 4.")
        else:
            print("\n!!! Login Failed. Incorrect email or password. Please try again. !!!")


if __name__ == "__main__":
    main()