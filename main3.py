# main3.py
import os

def run_script(script):
    os.system(f"python {script}")

def main():
    while True:
        print("\n--- Main Menu ---")
        print("1. Key Generation")
        print("2. Encrypt")
        print("3. Decrypt")
        print("4. Exit")
        choice = input("Choose option: ")

        if choice == "1":
            run_script("key.py")
        elif choice == "2":
            run_script("encrypt.py")
        elif choice == "3":
            run_script("decrypt.py")
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()
