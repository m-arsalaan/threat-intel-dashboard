import logging
import os
from datetime import datetime

# Create logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)

# Log filename with today's date
log_filename = f"logs/threatintel_{datetime.now().strftime('%Y-%m-%d')}.log"

# Configure logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        # Write to file
        logging.FileHandler(log_filename),
        # Also print to terminal
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("threatintel")
