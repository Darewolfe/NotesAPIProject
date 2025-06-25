import requests

BASE_URL = "http://127.0.0.1:5000"

# Test user credentials
USER = {"username": "james", "password": "mypassword"}

# Register user
print("Registering user...")
reg_res = requests.post(f"{BASE_URL}/register", json=USER)
print("Register:", reg_res.status_code, reg_res.json())

# Login and get token
print("\nLogging in...")
login_res = requests.post(f"{BASE_URL}/login", json=USER)
print("Login:", login_res.status_code, login_res.json())
token = login_res.json().get("access_token")

# Headers with Bearer token
headers = {
    "Authorization": f"Bearer {token}"
}

# Create a new note
note_id = 1
note_data = {
    "title": "My First Note",
    "content": "This is a test note created via REST API"
}
print("\nCreating note...")
post_res = requests.post(f"{BASE_URL}/notes/{note_id}", headers=headers, data=note_data)
print("POST:", post_res.status_code, post_res.json())

# Get the note
print("\nRetrieving note...")
get_res = requests.get(f"{BASE_URL}/notes/{note_id}", headers=headers)
print("GET:", get_res.status_code, get_res.json())

# Update the note
update_data = {
    "title": "Updated Title",
    "content": "Updated content of the note"
}
print("\nUpdating note...")
patch_res = requests.patch(f"{BASE_URL}/notes/{note_id}", headers=headers, data=update_data)
print("PATCH:", patch_res.status_code, patch_res.json())

# Delete the note
print("\nDeleting note...")
delete_res = requests.delete(f"{BASE_URL}/notes/{note_id}", headers=headers)
print("DELETE:", delete_res.status_code)
