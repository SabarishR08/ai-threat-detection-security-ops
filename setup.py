"""
Setup Script for Threat Detection Platform

This script helps initialize the project for development.
Run this after cloning the repository.
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def print_header(message):
    """Print formatted header."""
    print("\n" + "="*60)
    print(f"  {message}")
    print("="*60 + "\n")

def print_step(step, message):
    """Print formatted step."""
    print(f"[Step {step}] {message}")

def run_command(command, description):
    """Run a shell command and handle errors."""
    print(f"  → {description}")
    try:
        result = subprocess.run(command, shell=True, check=True, 
                              capture_output=True, text=True)
        print(f"  ✓ Success")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  ✗ Failed: {e.stderr}")
        return False

def check_python_version():
    """Check if Python version is compatible."""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 11):
        print(f"  ✗ Python 3.11+ required (you have {version.major}.{version.minor})")
        return False
    print(f"  ✓ Python {version.major}.{version.minor}.{version.micro}")
    return True

def create_virtual_environment():
    """Create Python virtual environment."""
    venv_path = Path("backend/.venv")
    if venv_path.exists():
        print("  ⚠ Virtual environment already exists")
        return True
    
    return run_command("python -m venv backend/.venv", 
                      "Creating virtual environment")

def get_activation_command():
    """Get the appropriate activation command for the OS."""
    if platform.system() == "Windows":
        return "backend\\.venv\\Scripts\\activate"
    else:
        return "source backend/.venv/bin/activate"

def install_dependencies():
    """Install Python dependencies."""
    pip_command = "backend/.venv/Scripts/pip" if platform.system() == "Windows" else "backend/.venv/bin/pip"
    return run_command(f"{pip_command} install -r backend/requirements.txt",
                      "Installing dependencies")

def create_env_file():
    """Create .env file from example."""
    env_path = Path(".env")
    env_example_path = Path(".env.example")
    
    if env_path.exists():
        print("  ⚠ .env file already exists")
        return True
    
    if not env_example_path.exists():
        print("  ⚠ .env.example not found")
        return False
    
    try:
        env_example_path.rename(env_path) if not env_path.exists() else None
        with open(env_example_path, 'r') as src:
            content = src.read()
        with open(env_path, 'w') as dst:
            dst.write(content)
        print("  ✓ Created .env file from .env.example")
        print("  ⚠ Remember to add your API keys to .env")
        return True
    except Exception as e:
        print(f"  ✗ Failed to create .env: {e}")
        return False

def create_directories():
    """Create necessary directories."""
    directories = [
        "backend/database",
        "backend/logs",
        "backend/uploads",
        "backend/cache",
        "cache",
        "test_outputs"
    ]
    
    success = True
    for directory in directories:
        path = Path(directory)
        try:
            path.mkdir(parents=True, exist_ok=True)
            print(f"  ✓ {directory}")
        except Exception as e:
            print(f"  ✗ Failed to create {directory}: {e}")
            success = False
    
    return success

def create_gitkeep_files():
    """Create .gitkeep files in empty directories."""
    directories = [
        "backend/database",
        "backend/logs",
        "backend/uploads",
        "backend/cache",
        "cache",
        "test_outputs"
    ]
    
    for directory in directories:
        gitkeep = Path(directory) / ".gitkeep"
        try:
            gitkeep.touch(exist_ok=True)
        except Exception:
            pass

def verify_structure():
    """Verify project structure is correct."""
    required_paths = [
        "backend/app.py",
        "backend/requirements.txt",
        "backend/tests/conftest.py",
        "README.md",
        "PROJECT_STRUCTURE.md"
    ]
    
    all_exist = True
    for path_str in required_paths:
        path = Path(path_str)
        if path.exists():
            print(f"  ✓ {path_str}")
        else:
            print(f"  ✗ Missing: {path_str}")
            all_exist = False
    
    return all_exist

def main():
    """Main setup function."""
    print_header("Threat Detection Platform - Setup")
    
    # Change to project root
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    # Step 1: Check Python version
    print_step(1, "Checking Python version")
    if not check_python_version():
        print("\n❌ Setup failed: Incompatible Python version")
        sys.exit(1)
    
    # Step 2: Verify project structure
    print_step(2, "Verifying project structure")
    if not verify_structure():
        print("\n⚠ Warning: Some files are missing")
    
    # Step 3: Create directories
    print_step(3, "Creating required directories")
    create_directories()
    create_gitkeep_files()
    
    # Step 4: Create virtual environment
    print_step(4, "Setting up virtual environment")
    if not create_virtual_environment():
        print("\n❌ Setup failed: Could not create virtual environment")
        sys.exit(1)
    
    # Step 5: Install dependencies
    print_step(5, "Installing Python dependencies")
    if not install_dependencies():
        print("\n❌ Setup failed: Could not install dependencies")
        sys.exit(1)
    
    # Step 6: Create .env file
    print_step(6, "Creating environment configuration")
    create_env_file()
    
    # Success message
    print_header("Setup Complete!")
    print("Next steps:")
    print(f"  1. Activate virtual environment:")
    print(f"     {get_activation_command()}")
    print(f"  2. Add your API keys to .env file")
    print(f"  3. (Optional) Add Gmail credentials to backend/credentials/credentials.json")
    print(f"  4. Run the application:")
    print(f"     cd backend")
    print(f"     python app.py")
    print(f"  5. Run tests:")
    print(f"     pytest backend/tests/unit/ -v")
    print("\n📚 Documentation:")
    print("  - README.md - Project overview")
    print("  - PROJECT_STRUCTURE.md - Code organization")
    print("  - CONTRIBUTING.md - Development guidelines")
    print("  - docs/README.md - Full documentation index")
    print("\n✨ Happy coding!\n")

if __name__ == "__main__":
    main()
