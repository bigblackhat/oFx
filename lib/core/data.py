# coding:utf-8

import time
import os
import queue
import threading
import sys
import requests

now = str(int(time.time()))

root_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
log_path = root_path + "/log/"
output_path = root_path + "/output/"
scan_path = root_path + "/scan/"
poc_path = root_path + "/poc/"
lib_path = root_path + "/lib/"

yso_path = lib_path + "thirdparty/ysoserial/ysoserial-master-SNAPSHOT.jar"
yso_tmpfile_path = lib_path + "thirdparty/ysoserial/tmp/"

MAX_NUMBER_OF_THREADS = 100
IS_WIN = True if (sys.platform in ["win32", "cygwin"] or os.name == "nt") else False
PYVERSION = sys.version.split()[0].split(".")[0]

qu = queue.Queue()
allpoc = queue.Queue()

vulnoutput = dict()
unvulnoutput = []
unreachoutput = []

lock = threading.Lock()

AliveTest = queue.Queue()
AliveList = set()
# AliveList = []
dnslog_cn_session = requests.session()

exploitModle = False
