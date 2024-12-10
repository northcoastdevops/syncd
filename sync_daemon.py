import os
import subprocess
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import daemon
import yaml
from logging.handlers import RotatingFileHandler
import sys

def setup_logging():
    """Configure logging with rotation and formatting."""
    log_dir = os.path.expanduser('~/.sync_daemon')
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'sync_daemon.log')
    
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler = RotatingFileHandler(log_file, maxBytes=1024*1024, backupCount=5)
    handler.setFormatter(formatter)
    
    logger = logging.getLogger('sync_daemon')
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger

logger = setup_logging()

def load_config():
    """Load configuration from YAML file with error handling."""
    config_paths = [
        'sync_daemon.yaml',
        os.path.expanduser('~/.sync_daemon/config.yaml'),
        '/etc/sync_daemon/config.yaml'
    ]
    
    for config_path in config_paths:
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as file:
                    config = yaml.safe_load(file)
                    if validate_config(config):
                        logger.info(f"Loaded configuration from {config_path}")
                        return config
        except Exception as e:
            logger.error(f"Error loading config from {config_path}: {str(e)}")
    
    logger.critical("No valid configuration file found")
    sys.exit(1)

def validate_config(config):
    """Validate the configuration file has all required fields."""
    required_fields = ['directories', 'remote_dir', 'remote_host', 'rsync_options']
    for field in required_fields:
        if field not in config:
            logger.error(f"Missing required configuration field: {field}")
            return False
    return True

config = load_config()

DIRECTORIES = config['directories']
REMOTE_DIR = config['remote_dir']
REMOTE_HOST = config['remote_host']
RSYNC_OPTIONS = config['rsync_options']

class SyncHandler(FileSystemEventHandler):
    """Handles file system events to trigger rsync."""
    def __init__(self, local_dir):
        self.local_dir = local_dir

    def on_any_event(self, event):
        logger.info(f"Change detected in {self.local_dir}: {event.src_path}")
        self.sync_to_remote()

    def sync_to_remote(self):
        """Executes the rsync command to sync files to the remote directory."""
        logger.info(f"Syncing {self.local_dir} to remote...")
        cmd = f"rsync {RSYNC_OPTIONS} --update {self.local_dir}/ {REMOTE_HOST}:{REMOTE_DIR}/"
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"Sync of {self.local_dir} completed successfully")
            else:
                logger.error(f"Error during sync of {self.local_dir}. Return code: {result.returncode}")
                logger.error(f"Error output: {result.stderr}")
        except Exception as e:
            logger.error(f"Exception during sync of {self.local_dir}: {str(e)}")

def start_sync_daemon():
    """Sets up the directory observer and starts syncing."""
    observers = []
    for local_dir in DIRECTORIES:
        if not os.path.exists(local_dir):
            logger.error(f"Directory does not exist: {local_dir}")
            continue
            
        event_handler = SyncHandler(local_dir)
        observer = Observer()
        observer.schedule(event_handler, path=local_dir, recursive=True)
        observer.start()
        observers.append(observer)
        logger.info(f"Daemon started, monitoring {local_dir} for changes...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
        for observer in observers:
            observer.stop()
    for observer in observers:
        observer.join()

def run_as_daemon():
    """Runs the script as a background daemon."""
    logger.info("Starting sync daemon")
    with daemon.DaemonContext():
        start_sync_daemon()

if __name__ == "__main__":
    run_as_daemon()