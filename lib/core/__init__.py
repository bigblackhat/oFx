import os
import sys

try:
    os.path.dirname(os.path.realpath(__file__))
except Exception:
    err_msg = "your system does not properly handdle non-Ascii path"
    err_msg += "please move this ofx's directory to other location"
    exit(err_msg)

from lib.core.data import root_path

def check_environment():
    from lib.core.data import PYVERSION
    if PYVERSION.split(".")[0] == "2":
        err_msg = "oFx does not support python2"
        exit(err_msg)
check_environment()


def oFx_Refuse_Win():
    from lib.core.data import IS_WIN
    if IS_WIN:
        err_msg = "oFx does not support windows system, Kali Linux is recommended"
        exit(err_msg)
oFx_Refuse_Win()


def oFx_Init():
    from lib.core.data import log_path,output_path,scan_path
    if not os.path.exists(log_path):
        os.makedirs(log_path)

    if not os.path.exists(output_path):
        os.makedirs(output_path)

    if not os.path.exists(scan_path):
        os.makedirs(scan_path)
oFx_Init()

def clear_relog():
    from lib.core.data import now
    from lib.core.data import output_path,log_path
    deadline = int(now) - 12*60*60
    for i in os.listdir(output_path):
        try:
            if int(i.split(".")[0]) <= deadline :
                os.remove(output_path+i)
        except:
            pass
    for i in os.listdir(log_path):
        try:
            if int(i.split(".")[0]) <= deadline :
                os.remove(log_path+i)
        except:
            pass
clear_relog()

sys.path.append(root_path)
# exit("test success")