# truffle-poc.py
# This script performs the following tasks:
# 1. Get the contents from this URL https://github.com/timeline
# 2. Download commits or files as needed for analysis
# 3. Use TruffleHog to analyze the downloaded files for any secrets or sensitive information.
# 4. If any interesting changes are found, save them to a local file called findings.txt.
# 5. Remove all the files downloaded after the analysis is complete to preserve storage.

from requests import Session
from pathlib import Path
import subprocess
import tempfile
import shutil
import re
import sys
import os
import platform
from concurrent.futures import ThreadPoolExecutor
import time
from dotenv import load_dotenv
import argparse

class TrufflePoc():
    def __init__(self, args):
        self.args = args
        self.initialize_environment()

    def initialize_environment(self):
        load_dotenv()
        self.github_token = os.getenv("GITHUB_TOKEN")
        Path('binaries').mkdir(exist_ok=True, parents=True)
        Path('config').mkdir(exist_ok=True, parents=True)
        Path('tmp').mkdir(exist_ok=True, parents=True)
        self.max_workers = self.args.max_workers
        self.session = Session()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
            "Authorization": f"{self.github_token}",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        self.session.headers.update(headers)
        self.get_trufflehog_config_files()

        # Download TruffleHog binary if not present
        if platform.system().lower() == 'windows':
            trufflehog_path = Path('binaries/trufflehog.exe')
            if not trufflehog_path.exists():
                trufflehog_url = self.get_trufflehog_binary_url()
                if trufflehog_url:
                    response = self.session.get(trufflehog_url, stream=True)
                    response.raise_for_status()
                    filename = trufflehog_url.split('/')[-1]
                    with open(filename, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)

                    if Path(filename).exists() and Path(filename).stat().st_size > 0:
                        shutil.unpack_archive(filename, 'binaries')
                        os.remove(filename)
                        os.remove("binaries/README.md") if os.path.exists("binaries/README.md") else None
                        os.remove("binaries/LICENSE") if os.path.exists("binaries/LICENSE") else None
        else:
            trufflehog_path = Path('binaries/trufflehog')
            if not trufflehog_path.exists():
                trufflehog_url = self.get_trufflehog_binary_url()
                if trufflehog_url:
                    response = self.session.get(trufflehog_url, stream=True)
                    response.raise_for_status()
                    filename = trufflehog_url.split('/')[-1]
                    with open(filename, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)

                    if Path(filename).exists() and Path(filename).stat().st_size > 0:
                        shutil.unpack_archive(filename, 'binaries')
                        os.remove(filename)
                        os.remove("binaries/README.md") if os.path.exists("binaries/README.md") else None
                        os.remove("binaries/LICENSE") if os.path.exists("binaries/LICENSE") else None
                        os.chmod(trufflehog_path, 0o755)

    def analyze_with_trufflehog(self, path):
        if platform.system().lower() == 'windows':
            trufflehog_cmd = '.\\binaries\\trufflehog.exe'
            config_path = '.\\config\\generic_with_filters.yml'
        else:
            trufflehog_cmd = './binaries/trufflehog'
            config_path = './config/generic_with_filters.yml'
        result = subprocess.run([trufflehog_cmd, 'filesystem', '--local-dev', '--results=verified', '--config', config_path, path, '--json'], capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"TruffleHog analysis failed: {result.stderr}")
        return result.stdout

    def analyze_with_github_with_trufflehog(self, repo_url):
        if platform.system().lower() == 'windows':
            trufflehog_cmd = '.\\binaries\\trufflehog.exe'
            config_path = '.\\config\\generic_with_filters.yml'
        else:
            trufflehog_cmd = './binaries/trufflehog'
            config_path = './config/generic_with_filters.yml'
        result = subprocess.run([trufflehog_cmd, 'github', '--local-dev', '--token', self.github_token, '--results=verified', '--config', config_path, '--repo', repo_url, '--json'], capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"TruffleHog analysis failed: {result.stderr}")
        return result.stdout
    
    def download_commit(self, repo, sha, download_dir):
        commit_url = f"https://api.github.com/repos/{repo}/commits/{sha}"
        response = self.session.get(commit_url)
        response.raise_for_status()
        commit_details = response.json()
        # Search for every raw_url in the commit details and download the files, except media files (like images, videos, gifs, etc.) and binaries. Just text alike files.
        for file_info in commit_details.get('files', []):
            raw_url = file_info.get('raw_url')
            if raw_url:
                # Skip media files and binaries based on file extension
                if not re.search(r'\.(jpg|jpeg|png|tif|nef|gif|bmp|mp4|avi|mov|wmv|flv|mkv|exe|dll|so|bin|pdf|zip|tar|gz|7z|xz)$', raw_url, re.IGNORECASE):
                    file_response = self.session.get(raw_url)
                    file_response.raise_for_status()
                    file_path = os.path.join(download_dir, os.path.basename(file_info.get('filename')))
                    with open(file_path, 'wb') as f:
                        f.write(file_response.content)

    def perform_local_analysis(self, repo, sha, tmp_dir):
        # Rate limiting: limit to 3 concurrent downloads with sleep if needed
        remaining, reset_time = self.check_rate_limit()
        while remaining < 1:
            sleep_time = reset_time - int(time.time()) + 1
            print(f"Rate limit exceeded. Sleeping for {sleep_time} seconds.")
            time.sleep(sleep_time)
            remaining, reset_time = self.check_rate_limit()

        # Download and analyze
        with tempfile.TemporaryDirectory(dir=tmp_dir) as download_dir:
            try:
                self.download_commit(repo, sha, download_dir)
                print(f"Downloaded commit {sha} of {repo} to {download_dir}")
                # Step 3: Use TruffleHog to analyze the downloaded files for any secrets or sensitive information.
                result = self.analyze_with_trufflehog(download_dir)
                if result.strip():
                    print(f"[*] Findings for {repo} commit {sha}:\n{result}")
                else:
                    print(f"[-] No findings for {repo} commit {sha}.")
                return result
            except Exception as e:
                print(f"Error processing {repo} commit {sha}: {e}")
                return None

    def check_rate_limit(self):
        rate_limit_url = "https://api.github.com/rate_limit"
        response = self.session.get(rate_limit_url)
        response.raise_for_status()
        rate_limit_data = response.json()
        remaining = rate_limit_data['rate']['remaining']
        reset_time = rate_limit_data['rate']['reset']
        if remaining == 0:
            sleep_time = reset_time - int(time.time()) + 1
            print(f"Rate limit exceeded. Sleeping for {sleep_time} seconds.")
            time.sleep(sleep_time)
        return remaining, reset_time

    def get_trufflehog_binary_url(self):
        # Placeholder function to get TruffleHog assets
        url = "https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest"
        self.check_rate_limit()
        response = self.session.get(url)
        response.raise_for_status()
        release_data = response.json()
        for asset in release_data.get('assets', []):
            system_name = platform.system().lower()
            machine_arch = platform.machine().lower()
            if asset['name'].endswith(f'{system_name}_{machine_arch}.tar.gz'):
                return asset['browser_download_url']
            else:
                continue
        return None
    
    def get_trufflehog_config_files(self):
        if Path('config').exists() and any(f.suffix == '.yml' for f in Path('config').iterdir()):
            return
        url = "https://api.github.com/repos/trufflesecurity/trufflehog/contents/examples"
        self.check_rate_limit()
        response = self.session.get(url)
        response.raise_for_status()
        config_files = response.json()
        for file_info in config_files:
            download_url = file_info.get('download_url')
            if download_url and file_info.get('name').endswith('.yml'):
                file_response = self.session.get(download_url)
                file_response.raise_for_status()
                config_path = os.path.join('config', file_info.get('name'))
                with open(config_path, 'wb') as f:
                    f.write(file_response.content)

    def run(self):
        # Step 1: Get the contents from the timeline URL (XML content)
        timeline_url = "https://github.com/timeline"
        self.check_rate_limit()
        response = self.session.get(timeline_url)
        response.raise_for_status()
        xml_content = response.text

        # Search in each URL with /commit/ in it
        commit_urls = re.findall(r'href=&quot;/([a-zA-Z0-9_-]+)/([a-zA-Z0-9_-]+)/commit/([^&\/;]+)', xml_content, re.DOTALL)
        findings = []

        tmp_dir = Path('tmp')
        tmp_dir.mkdir(exist_ok=True, parents=True)

        # Step 2: Download commits or files as needed for analysis.
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for repo_owner, repo_name, sha in commit_urls:
                repo = f"{repo_owner}/{repo_name}"

                # GitHub analysis
                if self.args.local_only:
                    # Local analysis (similar but downloading the commit and analyzing locally)
                    print("Processing repository:", repo, "commit:", sha)
                    futures.append(executor.submit(self.perform_local_analysis, repo, sha, tempfile.mkdtemp(dir=tmp_dir)))
                else:
                    repo_url = f"https://github.com/{repo}.git"
                    result = self.analyze_with_github_with_trufflehog(repo_url)
                    if result.strip():
                        print(f"[*] Findings for {repo} commit {sha}:\n{result}")
                    else:
                        print(f"[-] No findings for {repo} commit {sha}.")
            
            for future in futures:
                try:
                    result = future.result()
                    if result:
                        findings.append(f"Findings for {repo}:\n{result}\n")
                    else:
                        findings.append(f"No findings for {repo} commit {sha}.\n")
                except Exception as e:
                    print(f"Error downloading commit: {e}")

        # Step 4: If any interesting changes are found, save them to a local file called findings.txt.
        if findings:
            with open('findings.txt', 'w') as f:
                f.writelines(findings)

        # Step 5: Remove all the files downloaded after the analysis is complete to preserve storage.
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TrufflePoc - A tool for analyzing GitHub commits with TruffleHog")
    parser.add_argument('--interval', type=int, default=5, help="Interval in seconds between each run")
    parser.add_argument('--once', action='store_true', help="Run the analysis only once and exit")
    parser.add_argument('--debug', action='store_true', help="Enable debug mode for verbose output")
    parser.add_argument('--max-workers', type=int, default=5, help="Maximum number of concurrent workers for downloading commits")
    parser.add_argument('--local-only', action='store_true', help="Perform only local analysis without GitHub TruffleHog analysis")
    args = parser.parse_args()

    try:
        while True:
            tp = TrufflePoc(args)
            tp.run()
            if args.once:
                break
            time.sleep(args.interval)  # Sleep for 5 seconds before the next run
    except KeyboardInterrupt:
        print("Process interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)