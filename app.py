# app.py
# =============================================================================
# FastAPI + SQLAlchemy + JWT - VERSÃO COM PERSISTÊNCIA DE CAMADAS
# =============================================================================

import os
import sys
import re
import json
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from sqlalchemy import String, Integer, DateTime, func, select, Text, ForeignKey, update
from sqlalchemy.orm import Mapped, mapped_column, declarative_base, relationship
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
)

from passlib.context import CryptContext
from jose import jwt, JWTError

# =============================================================================
# Configurações de Ambiente
# =============================================================================

DATABASE_URL_RAW = os.getenv("DATABASE_URL", "postgresql://user:password@host/dbname").strip()
if not DATABASE_URL_RAW or DATABASE_URL_RAW == "postgresql://user:password@host/dbname":
    raise RuntimeError("A variável de ambiente DATABASE_URL não foi definida.")

JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key-change-me")
JWT_ALG = "HS256"
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "360"))

INIT_ADMIN = os.getenv("INIT_ADMIN", "true").lower() == "true"
INIT_ADMIN_USER = os.getenv("INIT_ADMIN_USER", "admin")
INIT_ADMIN_PASS = os.getenv("INIT_ADMIN_PASS", "123")

# =============================================================================
# Normalização de DATABASE_URL para asyncpg
# =============================================================================

u = urlparse(DATABASE_URL_RAW)
scheme = u.scheme or "postgresql"
if scheme == "postgresql":
    scheme = "postgresql+asyncpg"
elif scheme.startswith("postgresql+") and "asyncpg" not in scheme:
    scheme = "postgresql+asyncpg"

host = (u.hostname or "")
is_external = "." in host

qs = dict(parse_qsl(u.query or "", keep_blank_values=True))
qs.pop("sslmode", None)
qs.pop("ssl", None)

if is_external:
    qs["ssl"] = "true"

DATABASE_URL = urlunparse(u._replace(scheme=scheme, query=urlencode(qs)))

# =============================================================================
# Banco de Dados (SQLAlchemy 2.0 assíncrono)
# =============================================================================

Base = declarative_base()

class Layer(Base):
    __tablename__ = "layers"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(50), default="vector")
    
    geojson_data: Mapped[str] = mapped_column(Text, nullable=False)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    
    owner_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    
    owner: Mapped["User"] = relationship(back_populates="layers")
    
    group_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(150), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    
    layers: Mapped[List["Layer"]] = relationship(back_populates="owner", cascade="all, delete-orphan")


engine_kwargs = dict(echo=False, pool_pre_ping=True)
if is_external:
    engine_kwargs["connect_args"] = {"ssl": True}

engine = create_async_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# =============================================================================
# Utilidades de Autenticação
# =============================================================================

def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return pwd_ctx.verify(password, password_hash)

def create_access_token(sub: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRES_MIN)
    payload = {"sub": sub, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_access_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        sub: str = payload.get("sub")
        if sub is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido (sem sub).")
        return sub
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token inválido: {str(e)}")

# =============================================================================
# Schemas (Pydantic)
# =============================================================================

class LoginIn(BaseModel):
    username: str
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class MeOut(BaseModel):
    id: int
    username: str
    created_at: datetime

class LayerBase(BaseModel):
    name: str
    type: str = "vector"
    geojson_data: str
    group_name: Optional[str] = None

class LayerCreate(LayerBase):
    pass

class LayerOut(LayerBase):
    id: int
    created_at: datetime
    owner_id: int

    class Config:
        orm_mode = True

# +++ ADIÇÃO (CORREÇÃO #3): Schema para Renomear Grupo +++
class GroupRenameIn(BaseModel):
    old_name: str
    new_name: str

# =============================================================================
# App FastAPI
# =============================================================================

app = FastAPI(title="TerraSRF API", version="1.2.0", description="API para autenticação e persistência de dados GIS.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# Startup / Shutdown
# =============================================================================

@app.on_event("startup")
async def startup() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    if INIT_ADMIN:
        async with SessionLocal() as session:
            res = await session.execute(select(User).where(User.username == INIT_ADMIN_USER))
            user = res.scalar_one_or_none()
            if not user:
                user = User(username=INIT_ADMIN_USER, password_hash=hash_password(INIT_ADMIN_PASS))
                session.add(user)
                await session.commit()
                print(f"[startup] Usuário admin criado: {INIT_ADMIN_USER}/{INIT_ADMIN_PASS}", file=sys.stderr)
            else:
                print("[startup] Usuário admin já existe; pulando criação.", file=sys.stderr)

# =============================================================================
# Dependências
# =============================================================================

async def get_db() -> AsyncSession:
    async with SessionLocal() as session:
        yield session

async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Header Authorization ausente ou mal formatado.")
    
    token = auth_header.split(" ", 1)[1].strip()
    username = decode_access_token(token)
    
    res = await db.execute(select(User).where(User.username == username))
    user = res.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário do token não encontrado.")
        
    return user

# =============================================================================
# Rotas
# =============================================================================

@app.get("/health", tags=["Status"])
async def health():
    return {"status": "ok"}

@app.post("/auth/login", response_model=TokenOut, tags=["Autenticação"])
async def login(body: LoginIn, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(User).where(User.username == body.username))
    user = res.scalar_one_or_none()

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha inválidos."
        )
    
    token = create_access_token(sub=user.username)
    return TokenOut(access_token=token)


@app.get("/users/me", response_model=MeOut, tags=["Autenticação"])
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/api/layers/", response_model=LayerOut, status_code=status.HTTP_201_CREATED, tags=["Camadas"])
async def create_layer(
    layer: LayerCreate, 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    db_layer = Layer(**layer.model_dump(), owner_id=current_user.id)
    db.add(db_layer)
    await db.commit()
    await db.refresh(db_layer)
    return db_layer

# Em app.py, substitua a função get_user_layers inteira por esta:

@app.get("/api/layers/", response_model=List[LayerOut], tags=["Camadas"])
async def get_user_layers(
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    res = await db.execute(select(Layer).where(Layer.owner_id == current_user.id))
    layers = res.scalars().all()

    # --- INÍCIO DA CORREÇÃO ---
    # Garante que todas as camadas enviadas ao frontend tenham a estrutura de
    # rótulo esperada pelo novo código (2.html), mesmo que os dados no BD sejam antigos.
    for layer in layers:
        try:
            # Carrega o GeoJSON de texto para um dicionário Python
            geojson_dict = json.loads(layer.geojson_data)

            # Verifica se a chave 'labelConfig' NÃO existe
            if "labelConfig" not in geojson_dict:
                # Se não existir, adiciona uma configuração vazia (padrão)
                geojson_dict["labelConfig"] = {}

                # Converte o dicionário de volta para texto JSON e atualiza o objeto
                layer.geojson_data = json.dumps(geojson_dict)
        except (json.JSONDecodeError, TypeError):
            # Se o geojson_data for inválido, ignora esta camada para evitar que a API quebre
            print(f"Aviso: geojson_data inválido para a camada ID {layer.id}", file=sys.stderr)
            continue
    # --- FIM DA CORREÇÃO ---

    return layers

@app.put("/api/layers/{layer_id}", response_model=LayerOut, tags=["Camadas"])
async def update_layer(
    layer_id: int,
    layer_update: LayerCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    res = await db.execute(select(Layer).where(Layer.id == layer_id))
    db_layer = res.scalar_one_or_none()

    if not db_layer:
        raise HTTPException(status_code=404, detail="Camada não encontrada")

    if db_layer.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Acesso negado: você não é o dono desta camada.")

    db_layer.name = layer_update.name
    db_layer.type = layer_update.type
    db_layer.geojson_data = layer_update.geojson_data
    db_layer.group_name = layer_update.group_name
    
    await db.commit()
    await db.refresh(db_layer)
    return db_layer

# +++ ADIÇÃO (CORREÇÃO #3): Rota para Renomear Grupo +++
@app.put("/api/groups/rename", status_code=status.HTTP_200_OK, tags=["Camadas"])
async def rename_group(
    body: GroupRenameIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Renomeia um grupo de camadas, atualizando todas as camadas associadas
    que pertencem ao usuário logado.
    """
    if not body.old_name or not body.new_name or body.old_name == body.new_name:
        raise HTTPException(status_code=400, detail="Nomes de grupo inválidos.")

    stmt = (
        update(Layer)
        .where(Layer.owner_id == current_user.id)
        .where(Layer.group_name == body.old_name)
        .values(group_name=body.new_name)
    )
    result = await db.execute(stmt)
    await db.commit()
    
    return {"message": f"Grupo '{body.old_name}' renomeado para '{body.new_name}'.", "updated_rows": result.rowcount}

@app.delete("/api/layers/{layer_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Camadas"])
async def delete_layer(
    layer_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    res = await db.execute(select(Layer).where(Layer.id == layer_id))
    db_layer = res.scalar_one_or_none()

    if db_layer and db_layer.owner_id == current_user.id:
        await db.delete(db_layer)
        await db.commit()
    
    return

@app.get("/", tags=["Status"])
async def root():
    return {"message": "API TerraSRF no ar. Use /docs para ver a documentação interativa."}

# =============================================================================
# Execução local
# =============================================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=True)