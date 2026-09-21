import sys

from services.legacy_device.device import run

if __name__ == "__main__":
    sys.exit(0 if run() >= 0 else 1)
