# truffle-poc

## ⚠️ Disclaimer

This project is **for educational and security awareness purposes only**. This tool should be used exclusively on your own repositories or with explicit authorization. Misuse of this tool may violate terms of service and applicable laws. The authors are not responsible for any misuse of this software.

## Description

`truffle-poc` is an automated tool that monitors GitHub's public timeline for recent commits and analyzes the code for secrets or sensitive information using TruffleHog.

### What does it do?

The script performs the following tasks:

1. **Fetches public commits**: Accesses GitHub's public timeline (`https://github.com/timeline`) to retrieve recent commits
2. **Downloads files**: Downloads modified files from each commit (excluding binaries and media files)
3. **TruffleHog analysis**: Uses TruffleHog to scan files for:
   - API keys
   - Access tokens
   - Passwords
   - Secrets and credentials
   - Other sensitive information
4. **Saves findings**: If sensitive information is found, saves it to `findings.txt`
5. **Cleanup**: Removes all downloaded files after analysis to preserve storage

### Features

- ✅ Automatic TruffleHog binary download
- ✅ Concurrent analysis with multiple workers
- ✅ GitHub API rate limit management
- ✅ Local or remote analysis mode
- ✅ Single or continuous execution with configurable intervals
- ✅ Customizable configuration via YAML files

## Prerequisites

- Python 3.7 or higher
- GitHub token (for API access and higher rate limits)
- Internet connection :D

## Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/socketz/truffle-poc.git
   cd truffle-poc
   ```

2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure your GitHub token**:

   Create a `.env` file in the project root:

   ```env
   GITHUB_TOKEN=your_github_token_here
   ```

   To obtain a GitHub token:
   - Go to GitHub Settings → Developer settings → Personal access tokens
   - Generate a new token with read permissions for public repositories

## Usage

### Basic execution (one time)

```bash
python truffle-poc.py --once
```

### Continuous execution (constant monitoring)

```bash
python truffle-poc.py --interval 60
```

### Available options

```bash
python truffle-poc.py [options]
```

**Options:**

- `--once`: Run the analysis once and exit
- `--interval SECONDS`: Interval in seconds between each run (default: 5)
- `--max-workers NUM`: Maximum number of concurrent workers (default: 5)
- `--local-only`: Perform only local analysis by downloading commits
- `--debug`: Enable debug mode for verbose output

### Examples

**Single analysis with 10 workers:**

```bash
python truffle-poc.py --once --max-workers 10
```

**Continuous monitoring every 2 minutes:**

```bash
python truffle-poc.py --interval 120
```

**Local analysis only:**

```bash
python truffle-poc.py --local-only --once
```

## Project Structure

```sh
truffle-poc/
├── truffle-poc.py          # Main script
├── requirements.txt        # Python dependencies
├── findings.txt            # Security findings (generated)
├── .env                    # GitHub token (create manually)
├── binaries/               # TruffleHog binaries (downloaded automatically)
├── config/                 # TruffleHog configuration files
│   ├── generic.yml
│   └── generic_with_filters.yml
└── tmp/                    # Temporary directory (cleaned automatically)
```

## TruffleHog Configuration

Configuration files in `config/` allow you to customize:

- Enabled/disabled detectors
- Result filters
- Custom rules
- Secret verification

Edit `config/generic_with_filters.yml` to adjust the configuration according to your needs.

## Results

Findings are saved in `findings.txt` with the following format:

- Analyzed repository
- Specific commit
- Type of secret found
- Location in code
- Detector information

## Important Notes

- ⚠️ Respect GitHub API rate limits
- ⚠️ For ethical and educational use only
- ⚠️ Do not use this tool for malicious activities
- ⚠️ Obtain authorization before analyzing third-party repositories

## License

This project is for educational purposes only. Use it responsibly.
