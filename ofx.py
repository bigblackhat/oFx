# coding: utf-8
from __future__ import print_function

import os
import sys
import argparse
import logging 
import time
import threading
import configparser
import requests
import ctypes
import inspect
import subprocess
import re
try:
    os.path.dirname(os.path.realpath(__file__))
except Exception:
    err_msg = "your system does not properly handdle non-Ascii path"
    err_msg += "please move this ofx's directory to other location"
    exit(err_msg)

from lib.core.data import now,root_path,qu,vulnoutput,unvulnoutput,unreachoutput

log_path = root_path+"/log/"
if not os.path.exists(log_path):
    os.makedirs(log_path)

from lib.core.htmloutput import output_html
from lib.core.common import get_title,url_handle,get_latest_revision,get_local_version,run
from lib.fofa import fofa_login,ukey_save,get_ukey,fofa_search
from lib.core.threads import run_threads
sys.path.append(root_path)

IS_WIN = True if (sys.platform in ["win32", "cygwin"] or os.name == "nt") else False
PYVERSION = sys.version.split()[0].split(".")[0]

target_list=[]

logo = """
\033[33m        _  ______      
\033[33m    ___ |  ___|_  __
\033[31m    / _ \| |_  \ \/ /\033[0m
\033[35m    | (_) |  _|  >  <__ _Author : jijue\033[0m
\033[32m    \___/|_| __/_/\_\__ __ __Version : {version}\033[0m

\033[32m    #*#*#  https://github.com/bigblackhat/oFx  #*#*#

\033[33m       _-___________________________________-_
                
\033[0m""".format(version=get_local_version(root_path+"/info.ini"))


print(logo)
# start and check envirement
output_path = root_path+"/output/"
if not os.path.exists(output_path):
    os.makedirs(output_path)

scan_path = root_path + "/scan/"
if not os.path.exists(scan_path):
    os.makedirs(scan_path)

from lib.core.log import loglogo,logvuln,logunvuln,logverifyerror,logwarning,logcritical

def get_module():
    return os.path.dirname(os.path.realpath(__file__))

def check_environment():
    
    if PYVERSION.split(".")[0] != "2":
        err_msg = "incompatible Python version detected ('%s'). To successfully run sqlmap you'll have to use version 2.x"%(PYVERSION)
        logcritical(err_msg)
        exit()

def clear_relog():
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
    

##########


def main():

    clear_relog()
    parser = argparse.ArgumentParser(description="ofx framewark of POC test",
    usage="python ofx.py -f [path] / -u [url] -s [poc_path] ")

    searchengine = parser.add_argument_group("SearchEngine")
    searchengine.add_argument("--fofa-search",action="store_true",help="Fofa Search Mode, This option does not need to enter the parameter value")#type=str,help="fofa搜索语句(空格用下划线代替)")

    # target = parser.add_argument_group("TARGET")
    target = parser.add_mutually_exclusive_group()
    target.add_argument("-u","--url",type=str,help="scan a single target url (e.g. www.baidu.com)")
    target.add_argument("-f","--file",type=str,help="load target from file (e.g. /root/urllist.txt)")

    script = parser.add_argument_group("Script")
    script.add_argument("-s","--script",type=str,help="load script by name (e.g. -s poc/jellyfin/jellyfin_fileread_scan/poc.py)")
    
    system = parser.add_argument_group("System")
    system.add_argument("--thread",default=10,type=int,help="Number of threads, the default is 10 threads")
    system.add_argument("--proxy",default=False,help="Http Proxy，Example：127.0.0.1:8080 OR http://127.0.0.1:8080")
    system.add_argument("--output",default=True,help="Scan report")
    system.add_argument("--version",action="store_true",help="Display the local oFx version, and give the latest version number depending on the network status")

    
    if len(sys.argv) == 1:
        sys.argv.append("-h")
    args=parser.parse_args()
    
    if args.version == True:
        LocalVer = get_local_version(root_path + "/info.ini")
        print("The current local version is {localv}".format(localv = LocalVer))
        print("Obtaining github warehouse information, please wait.......")
        LatestVer = get_latest_revision()
        if LatestVer == None:
            print("The current network condition is not good, unable to obtain the latest version information")
            exit()
        elif LatestVer and LocalVer != LatestVer:
            print("The latest version is {latestv}".format(latestv = LatestVer))
            exit()
        else:
            print("The currently used ofx is the latest version")
            exit()

    proxyhost = None
    if args.proxy != False:
        if args.proxy.startswith("http://"):
            proxyhost = args.proxy[7:]
        elif args.proxy.startswith("https://"):
            proxyhost = args.proxy[8:]
        else:
            proxyhost = args.proxy

        if proxyhost:
            if proxyhost.endswith("/"):
                proxyhost = proxyhost[:-1]
            else:
                pass
            args.proxy = {
            "http": "http://%s"%(proxyhost),
            "https": "http://%s"%(proxyhost),
            }


    if args.url or args.file:
        # mode verify
        if args.url:
            scan_mode=1
        elif args.file:
            scan_mode=2
        else:
            print("Please confirm the detection mode, -f is batch detection mode, -u is single detection mode")
            exit()


        # POC verify
        args.script = args.script[:-6] if args.script.endswith("poc.py") else args.script
        if os.path.exists(root_path+"/"+args.script):
            sys.path.append(str(root_path+"/"+args.script))
            from poc import POC#,_info#verify
            logvuln("POC - %s Loaded"%(POC._info["name"]))

        else:
            logvuln("POC failed to load, please confirm the path and re-specify")
            exit()

        # single mode
        if scan_mode == 1:
            
            single_mode = POC(args.url,args.proxy)
            single_verify = single_mode._verify()
            if single_verify[0] == True:
                print("URL: {url}  || POC: {script} \nServer return information: \n{text} \n【Vuln】\n".format(url = args.url,script = args.script,text = single_verify[1]))
            else:
                print("URL: {url}  || POC: {script} \nServer return information: \n{text} \n【UnVuln】\n".format(url = args.url,script = args.script,text = single_verify[1]))

        # enum mode
        elif scan_mode == 2:
            start_time = time.time()
            with open(args.file,"r") as f:
                target_list = [i.strip() for i in f.readlines()]
            # qu = queue.Queue()
            for i in target_list:
                qu.put(i) 
            run_threads(num_threads = args.thread,thread_function = run,args=(POC,qu,args.proxy))
            
            if args.output != False:
                html_output = now+".html" if args.output == True else args.output+".html"
                output_html(html_output,vulnoutput,unvulnoutput,unreachoutput)
                loglogo("The report has been output to：%s"%(html_output))

                txt_output = now + ".txt" if args.output == True else args.output+".txt"
                with open(root_path+"/output/"+txt_output,"w") as f:
                    for i in vulnoutput:
                        f.write(i.split("||")[0].strip()+"\n")
                loglogo("The report has been output to：%s"%(txt_output))
            
            loglogo("Total url %d 条， %d loophole"%(len(target_list),len(vulnoutput)))
            end_time = time.time()
            loglogo("This scan takes :  %d Second"%(end_time-start_time))


    if args.fofa_search:
        # verify and get user and key
        fofa_user,fofa_key = get_ukey(root_path+"/lib/fofa.ini")

        # logincheck
        FofaLogin = fofa_login(fofa_user,fofa_key)
        if FofaLogin[0]:
            log_msg = "User : {user} | Key : {key}".format(user = FofaLogin[1],key = FofaLogin[2])
            log_msg += " | Login Success"
            logvuln(log_msg)
            ukey_save(FofaLogin[1],FofaLogin[2],root_path+"/lib/fofa.ini")
        # No or login failure, raw_input function gets user input,
            # Login repeat, loop
        # Login success
            if PYVERSION == 2:
                fofa_save_path = root_path + "/scan/" + raw_input("Please enter the name of the file to save the result (no need to add file suffix)： ") + ".txt"
                FofaDork = raw_input("Please enter the search sentence：")
            else:
                fofa_save_path = scan_path + input("Please enter the name of the file to save the result (no need to add file suffix)： ") + ".txt"
                FofaDork = input("Please enter the search sentence：")
            loglogo("The Fofa search sentence is：{fofadork}，Start docking with Fofa Api".format(fofadork = FofaDork))
            FofaResultNum = fofa_search(FofaLogin[1],FofaLogin[2],FofaDork,fofa_save_path)
            if type(FofaResultNum) == int:
                log_msg = "The search is complete and the results are saved to{path}，After the process, remove the weight, a total of {FofaResultNum}条".format(path = fofa_save_path,FofaResultNum = FofaResultNum)
                logvuln(log_msg)
            # Get search results and save to scan directory
        pass
    
    
    
if __name__ == "__main__":
    main()