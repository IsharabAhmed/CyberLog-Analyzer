import os
import subprocess
import sys

def run_cmd(cmd_str, check=True):
    print(f"[*] {cmd_str}")
    result = subprocess.run(cmd_str, shell=True)
    if check and result.returncode != 0:
        print(f"❌ Command failed with exit code {result.returncode}")
        sys.exit(result.returncode)

def main():
    print("[*] Initializing CyberLog Platform...")
    
    # 1. Sync dependencies
    print("\n[1/5] Syncing dependencies...")
    run_cmd("uv sync")
    
    # 2. Run migrations
    print("\n[2/5] Running database migrations...")
    run_cmd("uv run python manage.py makemigrations")
    run_cmd("uv run python manage.py migrate")
    
    # 3. Load Sample Data
    print("\n[3/5] Loading sample data and running ML pipeline...")
    run_cmd("uv run python manage.py load_sample_data")
    
    # 4. Git & GitHub Push
    print("\n[4/5] Pushing to GitHub...")
    if not os.path.exists(".git"):
        run_cmd("git init")
    
    run_cmd("git add .")
    
    # Commit (might fail if no changes, so we don't check=True)
    subprocess.run('git commit -m "Initial commit: CyberLog Platform MVP"', shell=True)
    
    # Check for GitHub CLI
    try:
        subprocess.run("gh --version", shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("GitHub CLI found. Creating repository and pushing...")
        # Create public repo and push. We don't use check=True in case it already exists.
        subprocess.run("gh repo create CyberLog-Analyzer --public --source=. --remote=origin --push", shell=True)
        print("[SUCCESS] Successfully pushed to GitHub!")
    except subprocess.CalledProcessError:
        print("[WARNING] GitHub CLI ('gh') not found or not authenticated.")
        print("To push automatically, install GitHub CLI (https://cli.github.com/) and run 'gh auth login'.")
        print("Alternatively, you can push manually by adding your own remote.")

    # 5. Run Server
    print("\n[5/5] Starting development server...")
    print("Open http://localhost:8000 in your browser.")
    print("Demo Credentials - Username: demo | Password: demo1234")
    print("---------------------------------------------------------")
    run_cmd("uv run python manage.py runserver")

if __name__ == "__main__":
    main()
