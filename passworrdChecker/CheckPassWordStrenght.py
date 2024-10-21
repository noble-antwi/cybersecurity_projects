import subprocess
import re

symbols = r'[!@#$%^&*()_\-+=\[\]{}|\\:;"\'<>,.?/~`§±°•¶≈≠∞←→↑↓√∑]'
letters_upper = r'[A-Z]'
letters_lower = r'[a-z]'
numbers = r'[0-9]'

def Password_Length_Checker():

# While loop runs until the correct password is entered
    while True:
        Password_Value = input("Kindly Input Your Password: ")
#Checking length of Password entered
        if len(Password_Value) < 8:
            print("Your password must be at least eight (8) characters long, kindly re-enter a new password.")
            continue
# Checking for Upper Case letters
        if not re.search(letters_upper, Password_Value):
            print("Your password must contain at least one uppercase , kindly re-enter a new password.")
            continue
# Checking for lower Case Letters
        if not re.search(letters_lower, Password_Value):
            print("Your Password must contain at least one lowercase letter, kindly re-enter a new password.")
            continue
# Checking for Numbers in password
        if not re.search(numbers, Password_Value):
            print("Your Password must contain at least one number, kindly re-enter a new password.")
            continue
# Checking for Symbols in the pasword
        if not re.search(symbols, Password_Value):
            print("Your Password must contain at least one symbol, kindly re-enter a new password")
            continue


        return Password_Value

# Funtcion check/tests the strength of Password with Cracklib
def testWithCracklib(Password_Value):
    result = subprocess.run(['wsl','cracklib-check'], input=Password_Value.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode().strip()
    if "OK" in output:
        print(f"Your Password is strong according to Cracklib.\t and your  password is {Password_Value}")
    else:
        print(f"This is what Cracklib has to say since the password is apparently not strong enough :: {output}")


# Main Fucntion to initiate the job
def main():
    Password_Value = Password_Length_Checker()
    testWithCracklib(Password_Value)


if __name__ == "__main__":
    main()
