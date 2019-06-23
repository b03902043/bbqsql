import os
import time

print('\033[0;33mplease login & setup db on localhost:9191 first\033[0m')
#time.sleep(5)
os.system('docker run --rm -it -p9191:80 vulnerables/web-dvwa')
