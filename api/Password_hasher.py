from werkzeug.security import generate_password_hash

hashed_password = generate_password_hash('4a5ff9fe!A')
print(hashed_password)
