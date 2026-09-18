"""
Task Manager with User Authentication
Course-End Project

A menu-driven, file-persisted task manager. Each user registers with a
username/password (password stored only as a salted SHA-256 hash), logs in,
and then manages their own tasks (add / view / mark completed / delete).
Every user's tasks are kept separate, so an authenticated user only ever
sees their own data.

Data files (created in the same directory as this script on first run):
  users.json  ->  { username: {"salt": "...", "password_hash": "..."} }
  tasks.json  ->  { username: [ {"id": 1, "description": "...", "status": "Pending"}, ... ] }
"""

import json
import os
import hashlib
import secrets

USERS_FILE = "users.json"
TASKS_FILE = "tasks.json"


# --------------------------------------------------------------------------
# File handling helpers
# --------------------------------------------------------------------------

def _load_json(path, default):
    """Load a JSON file, returning `default` if it doesn't exist or is empty/corrupt."""
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r") as f:
            content = f.read().strip()
            if not content:
                return default
            return json.loads(content)
    except (json.JSONDecodeError, OSError):
        return default


def _save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def load_users():
    return _load_json(USERS_FILE, {})


def save_users(users):
    _save_json(USERS_FILE, users)


def load_tasks():
    return _load_json(TASKS_FILE, {})


def save_tasks(tasks):
    _save_json(TASKS_FILE, tasks)


# --------------------------------------------------------------------------
# Password hashing
# --------------------------------------------------------------------------

def hash_password(password, salt=None):
    """Return (salt, hash) using PBKDF2-HMAC-SHA256. A random salt is
    generated per user so identical passwords never produce identical
    stored hashes."""
    if salt is None:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
    ).hex()
    return salt, pw_hash


def verify_password(password, salt, stored_hash):
    _, pw_hash = hash_password(password, salt)
    return secrets.compare_digest(pw_hash, stored_hash)


# --------------------------------------------------------------------------
# User authentication
# --------------------------------------------------------------------------

def register():
    """Prompt for a new username/password, enforce a unique username, and
    store a salted hash of the password (never the plaintext password)."""
    users = load_users()
    print("\n--- Register ---")
    username = input("Choose a username: ").strip()

    if not username:
        print("Username cannot be empty.")
        return
    if username in users:
        print(f"Username '{username}' is already taken. Please choose another.")
        return

    password = input("Choose a password: ").strip()
    if not password:
        print("Password cannot be empty.")
        return

    salt, pw_hash = hash_password(password)
    users[username] = {"salt": salt, "password_hash": pw_hash}
    save_users(users)

    # Give the new user an empty task list right away
    tasks = load_tasks()
    tasks.setdefault(username, [])
    save_tasks(tasks)

    print(f"User '{username}' registered successfully. You can now log in.")


def login():
    """Prompt for credentials and validate against stored (hashed) data.
    Returns the username on success, or None on failure."""
    users = load_users()
    print("\n--- Login ---")
    username = input("Username: ").strip()
    password = input("Password: ").strip()

    user_record = users.get(username)
    if user_record is None:
        print("No such user. Please register first.")
        return None

    if verify_password(password, user_record["salt"], user_record["password_hash"]):
        print(f"Welcome back, {username}!")
        return username

    print("Incorrect password.")
    return None


# --------------------------------------------------------------------------
# Task management
# --------------------------------------------------------------------------

def _next_task_id(user_tasks):
    if not user_tasks:
        return 1
    return max(task["id"] for task in user_tasks) + 1


def add_task(username):
    tasks = load_tasks()
    user_tasks = tasks.setdefault(username, [])

    description = input("Enter task description: ").strip()
    if not description:
        print("Task description cannot be empty. Task not added.")
        return

    task = {
        "id": _next_task_id(user_tasks),
        "description": description,
        "status": "Pending",
    }
    user_tasks.append(task)
    save_tasks(tasks)
    print(f"Task added (ID {task['id']}).")


def view_tasks(username):
    tasks = load_tasks()
    user_tasks = tasks.get(username, [])

    print(f"\n--- Tasks for {username} ---")
    if not user_tasks:
        print("You have no tasks yet.")
        return

    print(f"{'ID':<5}{'Status':<12}Description")
    print("-" * 40)
    for task in user_tasks:
        print(f"{task['id']:<5}{task['status']:<12}{task['description']}")


def _find_task(user_tasks, task_id):
    for task in user_tasks:
        if task["id"] == task_id:
            return task
    return None


def mark_completed(username):
    tasks = load_tasks()
    user_tasks = tasks.get(username, [])

    if not user_tasks:
        print("You have no tasks to update.")
        return

    view_tasks(username)
    raw_id = input("Enter the task ID to mark as completed: ").strip()
    if not raw_id.isdigit():
        print("Please enter a valid numeric task ID.")
        return

    task = _find_task(user_tasks, int(raw_id))
    if task is None:
        print(f"No task found with ID {raw_id}.")
        return

    if task["status"] == "Completed":
        print(f"Task {task['id']} is already marked as Completed.")
        return

    task["status"] = "Completed"
    save_tasks(tasks)
    print(f"Task {task['id']} marked as Completed.")


def delete_task(username):
    tasks = load_tasks()
    user_tasks = tasks.get(username, [])

    if not user_tasks:
        print("You have no tasks to delete.")
        return

    view_tasks(username)
    raw_id = input("Enter the task ID to delete: ").strip()
    if not raw_id.isdigit():
        print("Please enter a valid numeric task ID.")
        return

    task = _find_task(user_tasks, int(raw_id))
    if task is None:
        print(f"No task found with ID {raw_id}.")
        return

    user_tasks.remove(task)
    tasks[username] = user_tasks
    save_tasks(tasks)
    print(f"Task {task['id']} deleted.")


# --------------------------------------------------------------------------
# Menus
# --------------------------------------------------------------------------

def task_menu(username):
    """The logged-in menu loop: add / view / complete / delete / logout."""
    options = {
        "1": ("Add a Task", add_task),
        "2": ("View Tasks", view_tasks),
        "3": ("Mark a Task as Completed", mark_completed),
        "4": ("Delete a Task", delete_task),
    }

    while True:
        print(f"\n=== Task Manager — logged in as {username} ===")
        for key, (label, _) in options.items():
            print(f"{key}. {label}")
        print("5. Logout")

        choice = input("Choose an option: ").strip()

        if choice == "5":
            print(f"Logging out {username}. Goodbye!")
            return

        action = options.get(choice)
        if action is None:
            print("Invalid option. Please choose 1-5.")
            continue

        _, func = action
        func(username)


def main_menu():
    """Top-level menu: register, login, or exit the program."""
    while True:
        print("\n=== Welcome to Task Manager ===")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            register()
        elif choice == "2":
            username = login()
            if username:
                task_menu(username)
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please choose 1-3.")


if __name__ == "__main__":
    main_menu()
