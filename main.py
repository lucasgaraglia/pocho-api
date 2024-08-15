from fastapi import FastAPI, status, HTTPException, Depends, APIRouter
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import create_engine, MetaData, Table, Column, ForeignKey
from sqlalchemy.sql.sqltypes import Integer, String, DateTime, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from typing import Annotated, List
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import timedelta, datetime
from jose import jwt, JWTError

# db setup
engine = create_engine("mysql+pymysql://root:@localhost:3306/pocho_sports")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
meta = MetaData()

# models
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(255), unique=True)
    email = Column(String(255), unique=True)
    password = Column(String(255))
    first_name = Column(String(255))
    last_name = Column(String(255))
    role = Column(String(10))
    country = Column(String(255))
    province = Column(String(255))
    party = Column(String(255))
    locality = Column(String(255))
    address = Column(String(255))
    orders = relationship("Order", back_populates="client")

order_product_table = Table('order_product', Base.metadata,
    Column('order_id', Integer, ForeignKey('orders.id')),
    Column('product_id', Integer, ForeignKey('products.id')),
    Column('quantity', Integer)
)

class Product(Base):
    __tablename__ = 'products'
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(120))
    description = Column(String(500))
    price = Column(Float)
    stock = Column(Integer)
    code = Column(String(255))
    category = Column(String(50))
    orders = relationship("Order", secondary=order_product_table, back_populates="products")

class Order(Base):
    __tablename__ = 'orders'
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    client_id = Column(Integer, ForeignKey('users.id'))
    client = relationship("User", back_populates="orders")
    products = relationship("Product", secondary=order_product_table, back_populates="orders")
    sale = relationship("Sale", back_populates="order")

class Sale(Base):
    __tablename__ ='sales'
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    order_id = Column(Integer, ForeignKey('orders.id'))
    order = relationship("Order", back_populates="sale")
    datetime = Column(DateTime, default=datetime.utcnow)
    state = Column(String(20), default="In progress")

Base.metadata.create_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

SECRET_KEY = "pochososadasdasd"
ALGORITHM = "HS256"
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer("/auth/login")


def authenticate_user(username: str, password: str, db):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.password):
        return False
    return user

def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {"sub":username,"id":user_id}
    expires = datetime.utcnow() + expires_delta
    encode.update({"exp": expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: db_dependency):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("id")
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        user = db.query(User).filter(User.id == user_id).first()
        return user
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

user_dependency = Annotated[dict, Depends(get_current_user)]

# Routers
auth = APIRouter()

class Register(BaseModel):
    username: str
    email: str
    password: str
    first_name: str
    last_name : str
    role: str
    country: str
    province: str
    party: str
    locality: str
    address: str

class Token(BaseModel):
    access_token: str
    token_type: str

@auth.post("/auth/register", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency, register_request: Register):
    create_user_model = User(
        username=register_request.username,
        email=register_request.email,
        password=bcrypt_context.hash(register_request.password),
        first_name=register_request.first_name,
        last_name=register_request.last_name,
        role=register_request.role,
        country=register_request.country,
        province=register_request.province,
        party=register_request.party,
        locality=register_request.locality,
        address=register_request.address
    )
    db.add(create_user_model)
    db.commit()

@auth.post("/auth/login")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credentials not valid")
    token = create_access_token(user.username, user.id, timedelta(minutes=60))
    return {"access_token":token, "token_type":"bearer"}

user = APIRouter()

@user.get("/users/me", status_code=status.HTTP_200_OK)
async def get_user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Auth failed")
    # print(user)
    return {"User": user}

order = APIRouter()


class ProductOrder(BaseModel):
    product_id: int
    quantity: int

class OrderCreate(BaseModel):
    products: List[ProductOrder]

@user.post("/order", status_code=status.HTTP_200_OK)
async def create_order(order_data: OrderCreate, user: user_dependency, db: db_dependency):
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Auth failed")

    # asocio con user
    new_order = Order(client_id=user.id)
    db.add(new_order)
    db.commit()
    db.refresh(new_order)

    # agg products a la order
    for product in order_data.products:
        product_instance = db.query(Product).filter(Product.id == product.product_id).first()
        if not product_instance:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Product {product.product_id} not found")
        db.execute(order_product_table.insert().values(order_id=new_order.id, product_id=product.product_id, quantity=product.quantity))

    # creo la sale asociada con la order
    new_sale = Sale(order_id=new_order.id, datetime=datetime.utcnow())
    db.add(new_sale)
    db.commit()

    return {"order_id": new_order.id, "message": "Order created successfully"}



product_router = APIRouter()

class ProductCreate(BaseModel):
    name: str
    description: str
    price: float
    stock: int
    code: str
    category: str

# create product

@product_router.post("/products", status_code=status.HTTP_201_CREATED)
async def create_product(user: user_dependency, product: ProductCreate, db: db_dependency):

    existing_product = db.query(Product).filter(Product.code == product.code).first()
    if existing_product:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Product with this code already exists")

    new_product = Product(
        name=product.name,
        description=product.description,
        price=product.price,
        stock=product.stock,
        code=product.code,
        category=product.category
    )
    
    db.add(new_product)
    db.commit()
    db.refresh(new_product)

    return {"message": "Product created successfully", "product": new_product}

# get products
@product_router.get("/products", status_code=status.HTTP_200_OK)
async def get_all_products(user: user_dependency, db: db_dependency):
    products = db.query(Product).all()
    return {"products": products}


# get specific product
@product_router.get("/products/{product_id}", status_code=status.HTTP_200_OK)
async def get_product(user: user_dependency, product_id: int, db: db_dependency):
    # Consultar el producto por su ID
    product = db.query(Product).filter(Product.id == product_id).first()
    
    # Verificar si el producto existe
    if not product:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")
    
    # Devolver los detalles del producto
    return {
        "id": product.id,
        "name": product.name,
        "description": product.description,
        "price": product.price,
        "stock": product.stock,
        "code": product.code,
        "category": product.category
    }

# editar status de la venta
sale_router = APIRouter()

class SaleStatusUpdate(BaseModel):
    status: str

@sale_router.put("/sales/{sale_id}", status_code=status.HTTP_200_OK)
async def update_sale_status(user: user_dependency, sale_id: int, status_update: SaleStatusUpdate, db: db_dependency):
    sale = db.query(Sale).filter(Sale.id == sale_id).first()
    if not sale:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sale not found")
    
    sale.state = status_update.status 
    db.commit()
    db.refresh(sale)
    
    return {"message": "Sale status updated successfully", "sale": sale}

# get orders
@sale_router.get("/orders", status_code=status.HTTP_200_OK)
async def get_all_orders(user: user_dependency, db: db_dependency):
    orders = db.query(Order).all()
    return {"orders": orders}





# endpoint para devolver el rol del usuario




# FastAPI app setup
app = FastAPI()

app.include_router(auth)
app.include_router(user)
app.include_router(order)
app.include_router(product_router)
app.include_router(sale_router)
