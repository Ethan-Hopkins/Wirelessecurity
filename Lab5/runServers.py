import subprocess
subprocess.call("ASserver.py", shell=True)
subprocess.call("TGSserver.py", shell=True)
subprocess.call("service.py", shell=True)
subprocess.call("client.py", shell=True)