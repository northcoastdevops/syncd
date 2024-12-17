# syncd

A file synchronization daemon with real-time and batch sync capabilities.

## Features

- Real-time and batch synchronization modes
- Multiple host group support
- Configurable sync intervals
- Pattern-based file exclusion
- Automatic retry with exponential backoff
- Comprehensive logging
- Daemon and foreground operation modes

## Installation

### Using Homebrew (recommended)

```bash
brew tap northcoastdevops/tap
brew install syncd
```

### Manual Installation

From source:
```bash
git clone https://github.com/northcoastdevops/syncd.git
cd syncd
./install.sh
```

For user-specific installation:
```bash
./install.sh --user
```

## Configuration

The default configuration file is installed at:
- System-wide: `/etc/syncd/config.yaml`
- User-specific: `~/.config/syncd/config.yaml`

Example configuration:
```yaml
# Host groups define sets of hosts that should be kept in sync with each other
host_groups:
  - hosts:
      - localhost  # Add remote hosts as needed

    directories:
      - local: ~/Documents/sync   # Change this to your sync directory
        remote: ~/Documents/sync  # Change this to your remote sync path
        sync_type: batch         # 'batch' or 'event'
        batch_interval: 300      # Seconds between batch syncs
        exclude:
          - "*.tmp"
          - ".git"
          - "node_modules"

# Global Settings
unison_options: "-batch -prefer newer -times -perms 0 -auto -ui text"
log_level: info
log_file: ~/.local/var/log/syncd.log
daemon: false
noop: false

# Advanced Settings
host_check_interval: 300
consistency_check_interval: 3600
```

## Usage

### Basic Commands

1. Start the daemon:
   ```bash
   syncdctl start
   ```

2. Check status:
   ```bash
   syncdctl status
   ```

3. View logs:
   ```bash
   syncdctl logs
   ```

4. Stop the daemon:
   ```bash
   syncdctl stop
   ```

### Using with Homebrew Services

Start and enable at login:
```bash
brew services start syncd
```

Stop service:
```bash
brew services stop syncd
```

Restart service:
```bash
brew services restart syncd
```

### Additional Commands

Check configuration:
```bash
syncdctl check-config
```

Show help:
```bash
syncdctl --help
```

## Requirements

- macOS or Linux
- Unison (installed automatically with Homebrew)
- SSH keys configured for remote hosts

## License

MIT License - see LICENSE file for details 
