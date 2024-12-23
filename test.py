# Generate a secure key in production
import secrets
secret_key = secrets.token_urlsafe(32)

print(secret_key)

