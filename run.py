#!/usr/bin/env python3
import uvicorn
from app.config import HOST, PORT

if __name__ == "__main__":
    uvicorn.run("app.main:app", host=HOST, port=PORT)
