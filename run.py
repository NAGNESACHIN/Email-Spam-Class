import argparse
import subprocess
import sys

parser=argparse.ArgumentParser(description="Run MailGuard AI locally.")
parser.add_argument("--train",action="store_true",help="Train/rebuild the spam classifier before starting the API.")
parser.add_argument("--port",type=int,default=8000)
args=parser.parse_args()

if args.train:
    subprocess.run([sys.executable,"-m","ml.train"],check=True)

subprocess.run([
    sys.executable,"-m","uvicorn",
    "backend.main:app",
    "--reload",
    "--host","0.0.0.0",
    "--port",str(args.port),
],check=True)
