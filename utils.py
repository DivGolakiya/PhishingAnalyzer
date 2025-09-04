# utils.py
import os

def clear_screen():
    """Clears the terminal screen."""
    if os.name == 'nt':
        _ = os.system('cls')
    else:
        _ = os.system('clear')
