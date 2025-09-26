import subprocess
import sys

def main():
    print("======================================")
    print("Welcome to BitNet Chat!")
    print("Type 'chat -h' inside the container for help.")
    print("Press Ctrl+D or type 'exit' to close.\n")
    
    try:
        subprocess.run([
            "docker", "run", "-it", "--rm", "--user", "modeluser", "chat:latest", "bash"
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[Error] Docker failed: {e}")
        input("Press Enter to close...")  # Keeps terminal open on error

if __name__ == "__main__":
    main()
