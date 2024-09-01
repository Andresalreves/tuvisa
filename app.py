from fastapi import FastAPI, HTTPException, Depends, status, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, Boolean, update, Date
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import date

app = FastAPI()

# Configuración de la base de datos
SQLALCHEMY_DATABASE_URL = "sqlite:///./tuvisa.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Modelo de la tabla
class Activation(Base):
    __tablename__ = "activation"

    id = Column(Integer, primary_key=True, autoincrement = True, index=True)
    tipo = Column(Integer)
    fecha_activacion = Column(Date)
    fecha_limite = Column(Date)
    cuentas_agendadas = Column(Integer)
    limite_cuentas = Column(Integer)
    token = Column(String(30), unique=True, index=True)
    mac = Column(String(30), unique=True, index=True)
    activation = Column(Integer)

# Crear la base de datos y la tabla si no existen
Base.metadata.create_all(bind=engine)

# Modelos Pydantic para la validación de datos
#C70gDdqGKyynnIg29Jb4OLuPmbnl
class ActivationCreate(BaseModel):
    tipo: int = Field(..., ge=0, le=2)
    fecha_activacion: date = Field(...)
    fecha_limite: date = Field(...)
    cuentas_agendadas: int = Field(..., ge=0, le=300)
    limite_cuentas: int = Field(..., ge=0, le=300)
    token: str = Field(..., max_length=30)
    #mac: str = Field(..., max_length=30)
    activation: int = Field(..., ge=0, le=99)

class ActivationUpdate(BaseModel):
    id: int
    tipo: int = Field(None, ge=0, le=2)
    fecha_activacion: date = Field(None)
    fecha_limite: date = Field(None)
    cuentas_agendadas: int = Field(None, ge=0, le=300)
    limite_cuentas: int = Field(None, ge=0, le=300)
    token: str = Field(None, max_length=30)
    mac: str = Field(None, max_length=30)
    activation: int = Field(None, ge=0, le=99)

class TokenValidation(BaseModel):
    mac: str
    token: str

class FirstUse(BaseModel):
    mac: str

class ActivationResponse(BaseModel):
    id: int
    token: str
    mac: str
    activation: int


security = HTTPBearer()

# Este sería tu token secreto. En una aplicación real, deberías almacenarlo de forma segura.
SECRET_TOKEN = "8CTlPkbrMeeukhg3Iw0cqPEicffo9YLCZv4Q8KNb0RHyQui4vf"

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.credentials != SECRET_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials

@app.post("/activation/")
def create_activation(activation: ActivationCreate, token: str = Depends(verify_token)):
    db = SessionLocal()
    db_activation = Activation(**activation.dict())
    try:
        db.add(db_activation)
        db.commit()
        db.refresh(db_activation)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail="Error al crear la activación")
    finally:
        db.close()
    return jsonable_encoder({"message": "Activación creada exitosamente"})

@app.put("/activation/")
def update_activation(activation: ActivationUpdate, token: str = Depends(verify_token)):
    db = SessionLocal()
    try:
        db_activation = db.query(Activation).filter(Activation.id == activation.id).first()
        if db_activation is None:
            raise HTTPException(status_code=404, detail="Activación no encontrada")
        if activation.tipo:
            db_activation.tipo = activation.tipo
        if activation.fecha_activacion:
            db_activation.fecha_activacion = activation.fecha_activacion
        if activation.fecha_limite:
            db_activation.fecha_limite = activation.fecha_limite
        if activation.cuentas_agendadas:
            db_activation.cuentas_agendadas = activation.cuentas_agendadas
        if activation.limite_cuentas:
            db_activation.limite_cuentas = activation.limite_cuentas
        if activation.token:
            db_activation.token = activation.token
        if activation.mac:
            db_activation.mac = activation.mac
        if activation.activation:
            db_activation.activation = activation.activation
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail="Error al actualizar la activación")
    finally:
        db.close()
    return jsonable_encoder({"message": "Actualizacion realizada exitosamente"})

@app.get("/activations")
def list_activations(token: str = Depends(verify_token)):
    db = SessionLocal()
    try:
        activations = db.query(Activation).all()
        return activations
    except Exception as e:
        return e
    finally:
        db.close()

@app.delete("/activation/{activation_id}")
def delete_activation(activation_id: int, token: str = Depends(verify_token)):
    db = SessionLocal()
    try:
        activation = db.query(Activation).filter(Activation.id == activation_id).first()
        if activation is None:
            raise HTTPException(status_code=404, detail="Activación no encontrada")
        db.delete(activation)
        db.commit()
        return jsonable_encoder({"message": f"Activación con ID {activation_id} eliminada exitosamente"})
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail="Error al eliminar la activación")
    finally:
        db.close()


@app.post("/validate_token")
async def validate_token(validation: TokenValidation):
    db = SessionLocal()
    try:
        db_activation = db.query(Activation).filter(Activation.token == validation.token).first()
        if db_activation is None:
            response = {"activation":0,"message":"Token invalido."}
            return jsonable_encoder(response)
        elif db_activation.activation != 1 and not db_activation.mac:
            try:
                result = db.execute(
                    update(Activation)
                    .where(Activation.id == db_activation.id)
                    .values(mac=validation.mac, activation=1)
                )
                db.commit()
                if result.rowcount == 0:
                    response = {"activation": 0,"message":"No fue posible activar este token, por favor contacte al desarrollador."}
                    return jsonable_encoder(response)
                else: 
                    response = {"activation": 1,"message":"Aplicacion activada."}
                    return jsonable_encoder(response)
            except Exception as e:
                db.rollback()
                response = {"activation":0,"message":f"Ha ocurrido un error en el proceso de activacion."}
                return jsonable_encoder(response)
            finally:
                db.close()
        elif db_activation.mac != validation.mac:
            response = {"activation":0,"message":"Esta licencia ya fue registrada en otro equipo"}
            return jsonable_encoder(response)
    except Exception as e:
        response = {"activation":0,"message":"Ha ocurrido un error en el proceso de activacion."}
        return jsonable_encoder(response)
    finally:
        db.close()


@app.post("/validar_licencia")
async def validar_licencia(licencia: FirstUse):
    try:
        db = SessionLocal()
        db_activation = db.query(Activation).filter(Activation.mac == licencia.mac).first()
        agendadas  = db_activation.cuentas_agendadas + 1
        if db_activation.tipo == 2:
            try:
                if agendadas >= db_activation.limite_cuentas:
                    result = db.execute(
                        update(Activation)
                        .where(Activation.id == db_activation.id)
                        .values(cuentas_agendadas=agendadas, activation=0)
                    )
                    db.commit()
                    if result.rowcount > 0:
                        response = {"activation": 0,"message":"Se alcanzo el limite de cuentas para esta licencia."}
                        return jsonable_encoder(response)
                    else: 
                        response = {"activation": 0,"message":"Ha ocurrido un error critico, por favor contacte con el desarrollador."}
                        return jsonable_encoder(response)
                else:
                    result = db.execute(
                        update(Activation)
                        .where(Activation.id == db_activation.id)
                        .values(cuentas_agendadas=agendadas)
                    )
                    db.commit()
                    if result.rowcount > 0:
                        response = {"activation": 1,"message":"Cuenta registrada."}
                        return jsonable_encoder(response)
                    else: 
                        response = {"activation": 1,"message":"Ha ocurrido un error critico, por favor contacte con el desarrollador."}
                        return jsonable_encoder(response)
            except Exception as e:
                db.rollback()
                response = {"activation":0,"message":f"Ha ocurrido un error critico, por favor contacte con el desarrollador."}
                return jsonable_encoder(response)
        else:
            if date.today() >= db_activation.fecha_limite:
                result = db.execute(
                    update(Activation)
                    .where(Activation.id == db_activation.id)
                    .values(cuentas_agendadas=agendadas, activation=0)
                )
                db.commit()
                if result.rowcount > 0:
                    response = {"activation": 0,"message":"Esta licencia ha finalizado su periodo util."}
                    return jsonable_encoder(response)
                else: 
                    response = {"activation": 0,"message":"Ha ocurrido un error critico, por favor contacte con el desarrollador."}
                    return jsonable_encoder(response)
            else:
                result = db.execute(
                    update(Activation)
                    .where(Activation.id == db_activation.id)
                    .values(cuentas_agendadas=agendadas)
                )
                db.commit()
                if result.rowcount > 0:
                    response = {"activation": 0,"message":"Cuenta Agendada."}
                    return jsonable_encoder(response)
                else: 
                    response = {"activation": 0,"message":"Ha ocurrido un error critico, por favor contacte con el desarrollador."}
                    return jsonable_encoder(response)
    except Exception as e:
        response = {"activation":0,"message":"Ha ocurrido un error en el proceso de activacion."}
        return jsonable_encoder(response)
    finally:
        db.close()

@app.post("/init")
async def first_use(pc:FirstUse):
    db = SessionLocal()
    try:
        activation = db.query(Activation).filter(Activation.mac == pc.mac).first()
        if activation:
            if activation.activation == 1:
                return True
            else:
                return False
        else:
            return False
    except Exception as e:
        print(e)
        return False

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)