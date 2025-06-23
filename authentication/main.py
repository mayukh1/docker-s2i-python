from fastapi import FastAPI
from authentication.database import engine, Base 
from authentication.routes import login

app = FastAPI()

Base.metadata.create_all(bind=engine)

# it will route to every single page where the link was given
app.include_router(login.router)

