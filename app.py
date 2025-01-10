from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from typing import List, Optional
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
import firebase_admin
from firebase_admin import credentials, db
import json 
import os

FIREBASE_CREDENTIALS_PATH = "waffle.json"
FIREBASE_DB_URL = "https://wafflehouse-7b1c7-default-rtdb.asia-southeast1.firebasedatabase.app/"

# cred = credentials.Certificate(FIREBASE_CREDENTIALS_PATH)
# firebase_admin.initialize_app(cred, {"databaseURL": FIREBASE_DB_URL})

if not firebase_admin._apps:
    CredentialCertificate = os.environ.get('CREDENTIALCERTIFICATE')
    firebase_credentials_dict = json.loads(CredentialCertificate)
    cred = credentials.Certificate(firebase_credentials_dict)
    firebase_admin.initialize_app(cred, {
        'databaseURL': FIREBASE_DB_URL
    })

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class Item(BaseModel):
    category: str
    name: str
    price: float

class Sales(BaseModel):
    item_name: str
    quantity: int
    datetime: Optional[str] = None

class Admin(BaseModel):
    username: str
    password: str

ADMIN_CREDENTIALS = {"admin": "password123"}

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

#login
@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password
    if username!="admin" or password!="password123":
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = 1234567890
    return {"access_token": access_token, "token_type": "bearer"}


#add item
@app.post("/add_item")
def add_item(items: List[Item], token: str = Depends(oauth2_scheme)):
    ref = db.reference("inventory")
    for item in items:
        category_ref = ref.child(item.category)
        category_ref.child(item.name).set({"price": item.price})
    return {"message": "Items added successfully"}


#display inventory
@app.get("/display_inventory")
def display_inventory():
    ref = db.reference("inventory")
    if ref.get() is None:
        raise HTTPException(status_code=404, detail="Inventory not found")
    inventory = ref.get()
    return inventory


#add sales
@app.post("/add_sales")
def add_sales(sales: Sales, token: str = Depends(oauth2_scheme)):
    ref = db.reference("sales")
    sales.datetime = datetime.utcnow().isoformat()
    ref.push(sales.dict())
    return {"message": "Sales record added successfully"}


#total sales
@app.get("/total_sales")
def total_sales():
    sales_ref = db.reference("sales").get() or {}
    inventory_ref = db.reference("inventory").get() or {}

    total = 0
    items_sold = {}
    category_counts = {}

    for sale in sales_ref.values():
        item_price = None
        for category, items in inventory_ref.items():
            if sale["item_name"] in items:
                item_price = items[sale["item_name"]]["price"]
                category_counts[category] = category_counts.get(category, 0) + sale["quantity"]
                if category not in items_sold:
                    items_sold[category] = {}
                if sale["item_name"] in items_sold[category]:
                    items_sold[category][sale["item_name"]]["quantity"] += sale["quantity"]
                else:
                    items_sold[category][sale["item_name"]] = {"quantity": sale["quantity"], "price": item_price}
                break
        if item_price is not None:
            total += item_price * sale["quantity"]

    most_sold_category = max(category_counts, key=category_counts.get, default=None)
    return {
        "total_sales_amount": total,
        "items_sold": items_sold,
        "most_sold_category": most_sold_category,
    }


#total sales by date
@app.get("/total_sales_by_date")
def total_sales_by_date(date: str):
    try:
        target_date = datetime.strptime(date, "%Y-%m-%d").date()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use 'YYYY-MM-DD'.")

    sales_ref = db.reference("sales").get() or {}
    inventory_ref = db.reference("inventory").get() or {}

    total = 0
    items_sold = {}
    category_counts = {}

    for sale in sales_ref.values():
        sale_datetime = datetime.fromisoformat(sale["datetime"])
        if sale_datetime.date() == target_date:
            item_price = None
            for category, items in inventory_ref.items():
                if sale["item_name"] in items:
                    item_price = items[sale["item_name"]]["price"]
                    category_counts[category] = category_counts.get(category, 0) + sale["quantity"]
                    if category not in items_sold:
                        items_sold[category] = {}
                    if sale["item_name"] in items_sold[category]:
                        items_sold[category][sale["item_name"]]["quantity"] += sale["quantity"]
                    else:
                        items_sold[category][sale["item_name"]] = {"quantity": sale["quantity"], "price": item_price}
                    break
            if item_price is not None:
                total += item_price * sale["quantity"]

    most_sold_category = max(category_counts, key=category_counts.get, default=None)
    return {
        "date": str(target_date),
        "total_sales_amount": total,
        "items_sold": items_sold,
        "most_sold_category": most_sold_category,
    }


#delete item
@app.delete("/delete_item")
def delete_item(category: str, item_name: str, token: str = Depends(oauth2_scheme)):
    ref = db.reference(f"inventory/{category}/{item_name}")
    if ref.get():
        ref.delete()
        return {"message": f"Item '{item_name}' in category '{category}' deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="Item not found")