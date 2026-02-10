import subprocess
result = subprocess.check_output(['nmap', "127.0.0.1"], text=True, timeout=120, stderr=subprocess.STDOUT)
print(result.split())