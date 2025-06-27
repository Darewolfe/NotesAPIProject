import requests

BASE_URL = "http://127.0.0.1:5000"

USER = {"username": "jw", "password": "mpassword"}

# Register user
print("Registering user...")
reg_res = requests.post(f"{BASE_URL}/register", json=USER)
print("Register:", reg_res.status_code, reg_res.json())

# Login and get token
print("\nLogging in...")
login_res = requests.post(f"{BASE_URL}/login", json=USER)
print("Login:", login_res.status_code, login_res.json())

# Check if login was successful
if login_res.status_code != 200:
    print("Login failed!")
    exit()

token = login_res.json().get("access_token")  # Changed from "token" to "access_token"
print(f"TOKEN: {token}")

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"  # Added Content-Type header
}

# Create a note
note_id = 1
note_data = {
    "title": "Test Note",
    "content": "This is the first test note."
}
print("\nCreating note...")
post_res = requests.post(f"{BASE_URL}/notes/{note_id}", headers=headers, json=note_data)
print("POST:", post_res.status_code, post_res.json())

# Retrieve the note
print("\nRetrieving note...")
get_res = requests.get(f"{BASE_URL}/notes/{note_id}", headers=headers)
print("GET:", get_res.status_code, get_res.json())

# Update the note
update_data = {
    "title": "Updated Note",
    "content": "Updated content here."
}
print("\nUpdating note...")
patch_res = requests.patch(f"{BASE_URL}/notes/{note_id}", headers=headers, json=update_data)
print("PATCH:", patch_res.status_code, patch_res.json())

# Delete the note
print("\nDeleting note...")
delete_res = requests.delete(f"{BASE_URL}/notes/{note_id}", headers=headers)
print("DELETE:", delete_res.status_code)
