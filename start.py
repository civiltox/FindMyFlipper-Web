import os
import sys
import subprocess
import urllib.request
import urllib.error

ANISSETTE_URL = "http://localhost:6969"
SERVER_URL = "http://localhost:8000"

def print_header():
    print("🔍 Find My Flipper - Web Interface")
    print("==================================\n")

def check_anisette():
    print("Checking anisette server...")
    try:
        urllib.request.urlopen(ANISSETTE_URL, timeout=3)
        print("✓ Anisette server is running")
    except urllib.error.URLError:
        print("⚠️  Warning: Anisette server not detected on localhost:6969")
        print("   You may need to start it with:")
        print("   docker run -d --restart always --name anisette -p 6969:6969 dadoum/anisette-v3-server")
        sys.exit(1)

def create_directories():
    required_dirs = ["static", "keys"]

    created = False
    for directory in required_dirs:
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            created = True

    if created:
        print("Creating directories...")

def check_dependencies():
    try:
        import flask
    except ImportError:
        print("Installing dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

def start_server():
    print(f"\nStarting server on {SERVER_URL}")
    print("Press Ctrl+C to stop\n")

    try:
        subprocess.call([sys.executable, "app.py"])
    except KeyboardInterrupt:
        print("\nServer stopped.")

def main():
    print_header()
    check_anisette()
    create_directories()
    check_dependencies()
    start_server()

if __name__ == "__main__":
    main()