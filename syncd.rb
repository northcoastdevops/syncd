class Syncd < Formula
  desc "File synchronization daemon with real-time and batch sync capabilities"
  homepage "https://github.com/northcoastdevops/syncd"
  url "https://github.com/northcoastdevops/syncd/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "UPDATE_WITH_ACTUAL_SHA256"
  license "MIT"
  head "https://github.com/northcoastdevops/syncd.git", branch: "main"

  depends_on "cmake" => :build
  depends_on "yaml-cpp"
  depends_on "spdlog"
  depends_on "cxxopts"
  depends_on "unison"

  def install
    system "cmake", "-S", ".", "-B", "build", *std_cmake_args
    system "cmake", "--build", "build"
    
    # Install binaries
    bin.install "build/sync_daemon" => "syncd"
    bin.install "syncdctl"

    # Install default config
    (etc/"syncd").install "config.yaml" if File.exist? "config.yaml"
    
    # Create default config if it doesn't exist
    unless File.exist? etc/"syncd/config.yaml"
      (etc/"syncd").mkpath
      (etc/"syncd/config.yaml").write <<~EOS
        # Default syncd configuration
        # Modify this file according to your needs

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
      EOS
    end

    # Install bash completion
    (bash_completion/"syncdctl").write <<~EOS
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
    EOS

    # Create log directory
    (var/"log/syncd").mkpath
  end

  def post_install
    (var/"log/syncd").mkpath
    chmod 0755, var/"log/syncd"
  end

  def caveats
    <<~EOS
      To start syncd now and restart at login:
        brew services start syncd

      Or, if you don't want/need a background service you can just run:
        syncdctl start

      Configuration file is located at:
        #{etc}/syncd/config.yaml

      Log files will be stored in:
        #{var}/log/syncd/

      For more information, run:
        syncdctl --help
    EOS
  end

  service do
    run [opt_bin/"syncdctl", "start"]
    keep_alive true
    log_path var/"log/syncd/daemon.log"
    error_log_path var/"log/syncd/daemon.error.log"
    working_dir HOMEBREW_PREFIX
  end

  test do
    system "#{bin}/syncdctl", "--help"
    system "#{bin}/syncd", "--help"
  end
end 