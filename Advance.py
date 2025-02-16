import os
import sys
import pandas as pd
import numpy as np
import tensorflow as tf
import joblib
import hashlib
import subprocess
import time
import threading
from sklearn.metrics import classification_report, confusion_matrix
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from tensorflow.keras.layers import Dense, Conv2D, MaxPooling2D, Dropout, Flatten
from tensorflow.keras.models import Sequential
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Global directories (initially empty)
MALWARE_DIR = ""
BENIGN_DIR = ""
DYNAMIC_ANALYSIS_DIR = ""

def set_directories(malware, benign, dynamic):
    """Set the global directories for malware, benign, and dynamic analysis."""
    global MALWARE_DIR, BENIGN_DIR, DYNAMIC_ANALYSIS_DIR
    MALWARE_DIR, BENIGN_DIR, DYNAMIC_ANALYSIS_DIR = malware, benign, dynamic
    print(f"Directories set:\n- Malware: {MALWARE_DIR}\n- Benign: {BENIGN_DIR}\n- Dynamic Analysis: {DYNAMIC_ANALYSIS_DIR}")

    # Ensure directories exist
    for directory in [MALWARE_DIR, BENIGN_DIR, DYNAMIC_ANALYSIS_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)

def analyze_file(file_path):
    """Analyze a given APK file and determine if it's malware or benign."""
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} does not exist.")
        return "Error: File not found."

    print(f"Analyzing file: {file_path}")

    # Placeholder logic (replace with actual analysis)
    if "malware" in file_path.lower():
        result = "Malware Detected"
    else:
        result = "Benign File"

    print(f"Analysis result: {result}")
    return result

class FileHandler(FileSystemEventHandler):
    def on_created(self, event):
        print(f"New file detected: {event.src_path}")

def start_observer():
    """Start monitoring directories for changes using the set directories."""
    if not MALWARE_DIR or not BENIGN_DIR or not DYNAMIC_ANALYSIS_DIR:
        print("Error: Directories not set. Call set_directories() first.")
        return

    observer = Observer()
    event_handler = FileHandler()
    
    observer.schedule(event_handler, MALWARE_DIR, recursive=True)
    observer.schedule(event_handler, BENIGN_DIR, recursive=True)
    observer.schedule(event_handler, DYNAMIC_ANALYSIS_DIR, recursive=True)

    print("Starting observer for:", MALWARE_DIR, BENIGN_DIR, DYNAMIC_ANALYSIS_DIR)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    """This script should only be executed when explicitly called with arguments."""
    if len(sys.argv) == 4:
        set_directories(sys.argv[1], sys.argv[2], sys.argv[3])
        start_observer()
    else:
        print("Usage: python Advance.py <malware_dir> <benign_dir> <dynamic_analysis_dir>")
        sys.exit(1)