import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, status, Header
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from bson.objectid import ObjectId

from database import db, create_document
from schemas import User as UserSchema, Post as PostSchema

# App setup
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth settings
SECRET_KEY = os.getenv("SECRET_KEY", "devsecret_change_me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Models
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserOut(BaseModel):
    id: str
    name: str
    email: EmailStr
    admin: bool

class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class PostIn(BaseModel):
    title: str
    content: str
    status: str

class PostOut(BaseModel):
    id: str
    title: str
    content: str
    status: str
    user_id: str
    author_name: Optional[str] = None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def user_from_token(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db["user"].find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user["id"] = str(user["_id"])
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def admin_required(current_user: dict = Depends(user_from_token)) -> dict:
    if not current_user.get("admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


@app.get("/")
def read_root():
    return {"message": "Content Tracker API"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_name"] = getattr(db, "name", "✅ Connected")
            collections = db.list_collection_names()
            response["collections"] = collections[:10]
            response["database"] = "✅ Connected & Working"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# Auth endpoints
@app.post("/auth/signup", response_model=UserOut)
def signup(payload: SignupRequest):
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = get_password_hash(payload.password)
    # First user becomes admin for convenience; otherwise False
    is_first_user = db["user"].count_documents({}) == 0
    user_doc = UserSchema(
        name=payload.name,
        email=payload.email,
        password_hash=hashed,
        admin=is_first_user,
    )
    user_id = create_document("user", user_doc)
    return UserOut(id=user_id, name=payload.name, email=payload.email, admin=is_first_user)


@app.post("/auth/login", response_model=Token)
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token({"sub": str(user["_id"]), "email": user["email"], "admin": user.get("admin", False)})
    return Token(access_token=access_token)


@app.get("/auth/me", response_model=UserOut)
def me(current_user: dict = Depends(user_from_token)):
    return UserOut(id=str(current_user["_id"]), name=current_user["name"], email=current_user["email"], admin=current_user.get("admin", False))


# Posts endpoints
@app.get("/posts", response_model=List[PostOut])
def list_my_posts(current_user: dict = Depends(user_from_token)):
    posts = db["post"].find({"user_id": str(current_user["_id"])})
    result = []
    for p in posts:
        result.append(PostOut(
            id=str(p["_id"]),
            title=p.get("title", ""),
            content=p.get("content", ""),
            status=p.get("status", "Draft"),
            user_id=p.get("user_id"),
            author_name=p.get("author_name"),
        ))
    return result


@app.post("/posts", response_model=PostOut)
def create_post(payload: PostIn, current_user: dict = Depends(user_from_token)):
    post_doc = PostSchema(
        title=payload.title,
        content=payload.content,
        status=payload.status if payload.status in ["Draft", "Published"] else "Draft",
        user_id=str(current_user["_id"]),
        author_name=current_user.get("name"),
    )
    new_id = create_document("post", post_doc)
    return PostOut(id=new_id, **post_doc.model_dump())


@app.put("/posts/{post_id}", response_model=PostOut)
def update_post(post_id: str, payload: PostIn, current_user: dict = Depends(user_from_token)):
    try:
        oid = ObjectId(post_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid post id")
    post = db["post"].find_one({"_id": oid})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("user_id") != str(current_user["_id"]) and not current_user.get("admin"):
        raise HTTPException(status_code=403, detail="Not authorized")
    update = {
        "title": payload.title,
        "content": payload.content,
        "status": payload.status if payload.status in ["Draft", "Published"] else "Draft",
        "updated_at": datetime.now(timezone.utc)
    }
    db["post"].update_one({"_id": oid}, {"$set": update})
    post = db["post"].find_one({"_id": oid})
    return PostOut(
        id=str(post["_id"]),
        title=post.get("title", ""),
        content=post.get("content", ""),
        status=post.get("status", "Draft"),
        user_id=post.get("user_id"),
        author_name=post.get("author_name"),
    )


@app.delete("/posts/{post_id}")
def delete_post(post_id: str, current_user: dict = Depends(user_from_token)):
    try:
        oid = ObjectId(post_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid post id")
    post = db["post"].find_one({"_id": oid})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("user_id") != str(current_user["_id"]) and not current_user.get("admin"):
        raise HTTPException(status_code=403, detail="Not authorized")
    db["post"].delete_one({"_id": oid})
    return {"status": "deleted"}


# Admin endpoint
@app.get("/admin/posts", response_model=List[PostOut])
def admin_list_posts(current_user: dict = Depends(admin_required)):
    posts = db["post"].find({}).sort("created_at", -1)
    result = []
    for p in posts:
        result.append(PostOut(
            id=str(p["_id"]),
            title=p.get("title", ""), 
            content=p.get("content", ""),
            status=p.get("status", "Draft"),
            user_id=p.get("user_id", ""),
            author_name=p.get("author_name")
        ))
    return result


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
