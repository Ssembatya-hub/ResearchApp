import pyotp

# Replace with your key
secret_key = "CEFD3ACZYEJ63556RTA4BSSKUYCUCIM2"
totp = pyotp.TOTP(secret_key)

# Generate TOTP
print("Your Authenticator Code is:", totp.now())
