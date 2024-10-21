# Password Checker

## Overview

The Password Checker is a Python script that validates user passwords based on specific criteria and tests their strength using Cracklib. The script ensures that passwords meet certain complexity requirements and provides feedback on their strength.

## Code Explanation

### Regular Expressions

The script uses regular expressions to check the complexity of passwords. Here's a breakdown of the regular expressions used:

- **Symbols: `r'[!@#$%^&*()_\-+=\[\]{}|\\:;"\'<>,.?/~`§±°•¶≈≠∞←→↑↓√∑]'`**
  - This expression checks for the presence of special characters in the password. It includes a wide range of symbols to ensure password diversity.

- **Uppercase Letters: `r'[A-Z]'`**
  - This expression ensures the password contains at least one uppercase letter, which adds to the complexity.

- **Lowercase Letters: `r'[a-z]'`**
  - This expression ensures the password contains at least one lowercase letter, which is essential for creating a varied password.

- **Numbers: `r'[0-9]'`**
  - This expression ensures that the password includes at least one numeric digit, which helps in increasing password strength.

### Functions

#### `Password_Length_Checker()`

This function prompts the user to enter a password and validates it against several criteria:

- **Length Check:** Ensures the password is at least 8 characters long.
- **Uppercase Check:** Validates that the password contains at least one uppercase letter.
- **Lowercase Check:** Ensures the presence of at least one lowercase letter.
- **Number Check:** Confirms that the password includes at least one numeric digit.
- **Symbol Check:** Verifies the inclusion of at least one special symbol.

The function uses a `while` loop to repeatedly prompt the user until a valid password is entered. 

**Example:**

```python
def Password_Length_Checker():
    while True:
        Password_Value = input("Kindly Input Your Password: ")
        if len(Password_Value) < 8:
            print("Your password must be at least eight (8) characters long, kindly re-enter a new password.")
            continue
        if not re.search(letters_upper, Password_Value):
            print("Your password must contain at least one uppercase, kindly re-enter a new password.")
            continue
        if not re.search(letters_lower, Password_Value):
            print("Your Password must contain at least one lowercase letter, kindly re-enter a new password.")
            continue
        if not re.search(numbers, Password_Value):
            print("Your Password must contain at least one number, kindly re-enter a new password.")
            continue
        if not re.search(symbols, Password_Value):
            print("Your Password must contain at least one symbol, kindly re-enter a new password.")
            continue
        return Password_Value
```

`testWithCracklib(Password_Value)`

This function uses Cracklib to assess the strength of the provided password:

**Cracklib Integration:** It runs a subprocess command to check the password strength using cracklib-check.
**Feedback Handling**: Processes the output from Cracklib and prints whether the password is strong or if improvements are needed.
```python

def testWithCracklib(Password_Value):
    result = subprocess.run(['wsl', 'cracklib-check'], input=Password_Value.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode().strip()
    if "OK" in output:
        print(f"Your Password is strong according to Cracklib. Your password is {Password_Value}")
    else:
        print(f"This is what Cracklib has to say since the password is apparently not strong enough: {output}")

```

```main()```

The *main* function serves as the entry point of the script:

**Password Validation:** Calls Password_Length_Checker() to get a valid password.
**Strength Testing:** Passes the password to testWithCracklib() for strength assessment.

```python

def main():
    Password_Value = Password_Length_Checker()
    testWithCracklib(Password_Value)

if __name__ == "__main__":
    main()

```