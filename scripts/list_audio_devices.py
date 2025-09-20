from __future__ import annotations

import sounddevice as sd

def main():
    print("Input devices:")
    for idx, dev in enumerate(sd.query_devices()):
        if dev.get('max_input_channels', 0) > 0:
            print(f"#{idx}: {dev['name']} | {dev['hostapi']} | in={dev['max_input_channels']}")

if __name__ == "__main__":
    main()

