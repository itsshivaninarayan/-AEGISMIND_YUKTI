from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from edith2 import EDITHController

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

edith = EDITHController()

@app.get("/")
def home():
    return {"message": "Backend working"}

@app.get("/start")
def start_detection():
    edith.run_detection_cycle()
    return {"status": "Detection system started"}