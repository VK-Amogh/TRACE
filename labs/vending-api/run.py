"""Launcher for Vending API lab target."""

import sys
from pathlib import Path
import uvicorn

# Add lab root to sys.path so app.main imports work
lab_dir = Path(__file__).parent.resolve()
sys.path.insert(0, str(lab_dir))

from app.main import app

def start(port: int = 18080):
    print(f"Starting Vending API Lab on http://127.0.0.1:{port}")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
    start(port)
