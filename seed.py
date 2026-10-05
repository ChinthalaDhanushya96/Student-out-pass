from main import SessionLocal, User, pwd_context

db = SessionLocal()

users = [
    User(
        name="Demo Student",
        email="student@example.com",
        password_hash=pwd_context.hash("student123"),
        role="student"
    ),
    User(
        name="Demo Admin",
        email="admin@example.com",
        password_hash=pwd_context.hash("admin123"),
        role="admin"
    )
]

for user in users:
    existing = db.query(User).filter(User.email == user.email).first()
    if not existing:
        db.add(user)

db.commit()
db.close()

print("Demo users created.")
print("Student: student@example.com / student123")
print("Admin: admin@example.com / admin123")
