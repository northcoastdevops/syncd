# Contributing to syncd

Thank you for your interest in contributing to syncd! This document provides guidelines and instructions for contributing.

## Development Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/northcoastdevops/syncd.git
   cd syncd
   ```

2. Install dependencies:
   - On macOS:
     ```bash
     brew install cmake yaml-cpp spdlog cxxopts unison
     ```
   - On Ubuntu:
     ```bash
     sudo apt-get install cmake libyaml-cpp-dev libspdlog-dev unison xxhash libxxhash-dev nlohmann-json3-dev
     ```

3. Build the project:
   ```bash
   mkdir build
   cd build
   cmake ..
   make
   ```

## Making Changes

1. Create a new branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes, following these guidelines:
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed
   - Keep commits focused and atomic
   - Write clear commit messages

3. Test your changes:
   - Build and run tests
   - Test on both macOS and Linux if possible
   - Verify daemon functionality
   - Check configuration handling

4. Push your changes:
   ```bash
   git push origin feature/your-feature-name
   ```

5. Create a pull request:
   - Use a clear title and description
   - Reference any related issues
   - Ensure CI checks pass

## Code Style

- Use modern C++ features (C++17)
- Follow the existing code formatting
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and manageable

## Testing

- Add unit tests for new functionality
- Test edge cases and error conditions
- Verify platform-specific behavior
- Test both batch and event-based sync modes

## Documentation

- Update README.md for user-facing changes
- Document new configuration options
- Add inline documentation for complex code
- Update man pages if applicable

## Release Process

1. Update version numbers
2. Create changelog entry
3. Create a release tag
4. GitHub Actions will:
   - Build and test
   - Create release archive
   - Update Homebrew formula

## Getting Help

- Open an issue for questions
- Join discussions in existing issues
- Check the documentation
- Contact maintainers if needed

## Code of Conduct

Please follow our code of conduct:
- Be respectful and inclusive
- Focus on constructive feedback
- Help maintain a positive environment
- Report unacceptable behavior

## License

By contributing, you agree that your contributions will be licensed under the MIT License. 