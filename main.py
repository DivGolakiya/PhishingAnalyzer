# main.py
import glob
from analyzer import analyze_email
from utils import clear_screen
import os # Import os to check for the api key file

def get_api_key():
    """Reads the API key from api_key.txt."""
    if os.path.exists('api_key.txt'):
        with open('api_key.txt', 'r') as f:
            return f.read().strip()
    return None

def run_interactive_mode():
    """
    Main function to run the interactive analyzer.
    """
    clear_screen()
    print("Welcome to the Phishing Email Analyzer 🕵️")
    
    # Read the API key once at the start
    api_key = get_api_key()
    if not api_key:
        print("\n⚠️ WARNING: api_key.txt not found. URL reputation check will be skipped.")
    
    while True:
        # ... (the menu logic is the same as before) ...
        print("\n" + "="*50)
        eml_files = sorted(glob.glob('*.eml'))
        if not eml_files:
            print("No .eml files found in this directory. Exiting."); break
        print("Found the following email files:")
        for i, file_name in enumerate(eml_files): print(f"  [{i+1}] {file_name}")
        exit_option_number = len(eml_files) + 1
        print(f"  [{exit_option_number}] Exit")
        
        try:
            choice_str = input(f"\nEnter your choice (1-{exit_option_number}): ")
            choice = int(choice_str)
            if choice == exit_option_number:
                print("Exiting analyzer. Goodbye!"); break
            choice_index = choice - 1
            if 0 <= choice_index < len(eml_files):
                selected_file = eml_files[choice_index]
                clear_screen()
                # Pass the API key to the analyzer
                analyze_email(selected_file, api_key)
            else:
                print("Invalid choice."); continue
        except (ValueError, IndexError):
            print("Invalid input."); continue
        
        another = input("\nDo you want to analyze another email? (y/n): ").lower()
        if another != 'y':
            print("Exiting analyzer. Goodbye!"); break
        else:
            clear_screen()

if __name__ == "__main__":
    run_interactive_mode()
