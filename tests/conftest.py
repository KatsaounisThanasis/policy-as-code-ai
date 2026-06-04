import sys
from pathlib import Path

# Insert the src directory onto sys.path to allow importing explainer
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))
