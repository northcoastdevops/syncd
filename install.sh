#!/bin/bash

# Default installation paths
PREFIX="/usr/local"
BINDIR="$PREFIX/bin"
SYSCONFDIR="/etc/syncd"
USER_CONFDIR="$HOME/.config/syncd"

# Function to show help
show_help() {
    echo "syncd installer"
    echo
    echo "Usage: ./install.sh [OPTIONS]"
    echo
    echo "Options:"
    echo "  --prefix=DIR      Installation prefix (default: /usr/local)"
    echo "  --bindir=DIR      Executables directory (default: /usr/local/bin)"
    echo "  --sysconfdir=DIR  System config directory (default: /etc/syncd)"
    echo "  --user            Install for current user only"
    echo "  --help            Show this help message"
    echo
    echo "Examples:"
    echo "  ./install.sh                      # Install system-wide"
    echo "  ./install.sh --user               # Install for current user only"
    echo "  ./install.sh --prefix=/opt/syncd  # Custom installation prefix"
}

# Parse command line arguments
USER_INSTALL=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --help)
            show_help
            exit 0
            ;;
        --prefix=*)
            PREFIX="${1#*=}"
            BINDIR="$PREFIX/bin"
            ;;
        --bindir=*)
            BINDIR="${1#*=}"
            ;;
        --sysconfdir=*)
            SYSCONFDIR="${1#*=}"
            ;;
        --user)
            USER_INSTALL=1
            BINDIR="$HOME/.local/bin"
            SYSCONFDIR="$HOME/.config/syncd"
            ;;
        *)
            echo "Error: Unknown option '$1'" >&2
            echo "Try './install.sh --help' for more information." >&2
            exit 1
            ;;
    esac
    shift
done

# Check if running with necessary privileges
if [ $USER_INSTALL -eq 0 ] && [ "$(id -u)" != "0" ]; then
    echo "Error: System-wide installation requires root privileges." >&2
    echo "Try 'sudo ./install.sh' or './install.sh --user' for user installation." >&2
    exit 1
fi

# Create necessary directories
echo "Creating directories..."
mkdir -p "$BINDIR"
mkdir -p "$SYSCONFDIR"

if [ $USER_INSTALL -eq 1 ]; then
    mkdir -p "$USER_CONFDIR"
fi

# Store the source directory
SOURCEDIR="$(pwd)"

# Build the project
echo "Building project..."
rm -rf build
mkdir build
cd build || exit 1
cmake .. || exit 1
make || exit 1

# Install binaries
echo "Installing binaries..."
install -m 755 sync_daemon "$BINDIR/syncd"
install -m 755 "$SOURCEDIR/syncdctl" "$BINDIR/syncdctl"

# Install configuration
echo "Installing configuration..."
if [ ! -f "$SYSCONFDIR/config.yaml" ]; then
    install -m 644 "$SOURCEDIR/syncd.yaml" "$SYSCONFDIR/config.yaml"
fi

# Create log directory
mkdir -p "$HOME/.local/var/log"

# Set up completion if possible
if [ -d "/etc/bash_completion.d" ] && [ $USER_INSTALL -eq 0 ]; then
    echo "Installing bash completion..."
    cat > "/etc/bash_completion.d/syncdctl" << 'EOL'
_syncdctl() {
    local cur prev opts commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="start stop restart status logs check-config help"
    opts="-h --help -c --config -p --pid-file"

    case $prev in
        -c|--config)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
        -p|--pid-file)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
        syncdctl)
            COMPREPLY=( $(compgen -W "${commands}" -- "$cur") )
            return 0
            ;;
    esac

    COMPREPLY=( $(compgen -W "${opts}" -- "$cur") )
}
complete -F _syncdctl syncdctl
EOL
fi

# Add shell detection function near the top:
get_shell_rc() {
    local shell_path="$SHELL"
    local shell_name=$(basename "$shell_path")
    
    case "$shell_name" in
        "bash")
            echo "$HOME/.bashrc"
            ;;
        "zsh")
            echo "$HOME/.zshrc"
            ;;
        "fish")
            echo "$HOME/.config/fish/config.fish"
            ;;
        *)
            echo ""
            ;;
    esac
}

echo
echo "Installation complete!"
echo
echo "Next steps:"
if [ $USER_INSTALL -eq 1 ]; then
    RC_FILE=$(get_shell_rc)
    if [ -n "$RC_FILE" ]; then
        echo "1. Add $BINDIR to your PATH if not already present:"
        case "$(basename "$SHELL")" in
            "fish")
                echo "   fish_add_path $BINDIR"
                ;;
            *)
                echo "   echo 'export PATH=\"\$PATH:$BINDIR\"' >> $RC_FILE"
                ;;
        esac
        echo
        echo "   Then run: source $RC_FILE"
    else
        echo "1. Add $BINDIR to your PATH"
    fi
    echo
    echo "2. Edit your configuration file:"
    echo "   $USER_CONFDIR/config.yaml"
else
    echo "1. Edit the system configuration file:"
    echo "   $SYSCONFDIR/config.yaml"
fi
echo
echo "3. Start the daemon:"
echo "   syncdctl start"
echo
echo "4. Check the status:"
echo "   syncdctl status"
echo
echo "For more information, run:"
echo "   syncdctl --help" 