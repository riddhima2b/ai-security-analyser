from fastapi import FastAPI

app = FastAPI(title = "AI Security Vulnerability Analyser")

@app.get("/")
def root():
    return {"message": "Welcome to the AI Security Vulnerability Analyser API!"}