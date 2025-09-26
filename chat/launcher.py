import subprocess
import sys
import os

project_dir = r"C:\Users\Owner\Downloads\Chat-LLM-main\Chat-LLM-main"

def run_command(cmd, cwd=None):
    try:
        subprocess.run(cmd, shell=True, check=True, cwd=cwd)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
        input("Press Enter to exit...")
        sys.exit(1)

# Check if Docker image exists
def image_exists(image_name):
    result = subprocess.run(f"docker images -q {image_name}", shell=True, capture_output=True, text=True)
    return bool(result.stdout.strip())

if not image_exists("chat:latest"):
    print("Building Docker image...")
    run_command("docker build -t chat:latest .", cwd=project_dir)
else:
    print("Docker image already exists. Skipping build.")

print("Running Docker container...")
run_command("docker run -it --rm --user modeluser chat:latest python chat.py")

print("Docker container exited.")
input("Press Enter to close this window...")
