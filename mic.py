import subprocess

try:
    subprocess.run(["ffmpeg", "-version"], check=True)
    print("FFmpeg is installed and accessible.")
except FileNotFoundError:
    print("FFmpeg not found. Make sure it is installed and added to PATH.")
