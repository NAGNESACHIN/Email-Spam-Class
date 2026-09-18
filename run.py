import subprocess
import sys

subprocess.run([sys.executable, "-m", "ml.train"], check=True)
subprocess.run([
    sys.executable, "-m", "uvicorn",
    "backend.main:app",
    "--reload",
    "--host", "0.0.0.0",
    "--port", "8000",
], check=True)
