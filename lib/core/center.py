#coding:utf-8

import argparse
import sys
import queue
import os
import time


from lib.core.data import root_path,lock
from lib.core.common import get_local_version,get_latest_revision
from lib.core.log import logvuln,logwarning,logunvuln,logverifyerror,logcritical  
from lib.core.data import qu,allpoc,now,vulnoutput,unvulnoutput,unreachoutput,scan_path,poc_path
from lib.core.threads import run_threads
from lib.core.common import run
from lib.core.log import loglogo
from lib.core.htmloutput import output_html
from lib.fofa import get_ukey,fofa_login,ukey_save,fofa_search
from lib.core.output import Mkdn_output,Txt_output

def GetCommand():
    parser = argparse.ArgumentParser(description="ofx framewark of POC test",
    usage="python ofx.py -f [path] / -u [url] -s [poc_path] ")

    searchengine = parser.add_argument_group("SearchEngine")
    searchengine.add_argument("--fofa-search",action="store_true",help="Fofa Search Mode, This option does not need to enter the parameter value")

    # target = parser.add_argument_group("TARGET")
    target = parser.add_mutually_exclusive_group()
    target.add_argument("-u","--url",type=str,help="scan a single target url (e.g. www.baidu.com)")
    target.add_argument("-f","--file",type=str,help="load target from file (e.g. /root/urllist.txt)")

    script = parser.add_argument_group("Script")
    script.add_argument("-s","--script",type=str,help="load script by name (e.g. -s poc/jellyfin/jellyfin_fileread_scan/poc.py OR -s all)")
    
    system = parser.add_argument_group("System")
    system.add_argument("--thread",default=10,type=int,help="Number of threads, the default is 10 threads")
    system.add_argument("--proxy",default=False,help="Http Proxy，Example：127.0.0.1:8080 OR http://127.0.0.1:8080")
    system.add_argument("--output",default=True,help="Scan report")
    system.add_argument("--version",action="store_true",help="Display the local oFx version, and give the latest version number depending on the network status")

    
    if len(sys.argv) == 1:
        sys.argv.append("-h")
    args=parser.parse_args()
    return args 
    # pass
ScanMode = {
    "Single_Verify":1,
    "File_Verify":2,
    }
class oFxCenter():
    def __init__(self):
        self.Mode = None
        self.__version = None
        self.__threads = 10
        
        self.__proxy = None

        self.TargetList = []

        self.command_parser()

    def addpoc(self,pocpath):
        allpoc.put(pocpath)

    def show_version(self):
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

    def setproxy(self):
        """
        set the proxy for oFx running

        return:None
        """
        if self.CMD_ARGS.proxy.startswith("http://"):
            self.CMD_ARGS.proxy = self.CMD_ARGS.proxy[7:]
        elif self.CMD_ARGS.proxy.startswith("https://"):
            self.CMD_ARGS.proxy = self.CMD_ARGS.proxy[8:]
        else:
            pass

        if self.CMD_ARGS.proxy.endswith("/"):
            self.CMD_ARGS.proxy = self.CMD_ARGS.proxy[:-1]
        else:
            pass

        self.__proxy = {
        "http": "http://%s"%(self.CMD_ARGS.proxy),
        "https": "http://%s"%(self.CMD_ARGS.proxy),
        }
        self.getproxy()
    
    def getproxy(self):
        return self.__proxy

    def fromfofa(self):
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

            fofa_save_path = scan_path + input("Please enter the name of the file to save the result (no need to add file suffix)： ") + ".txt"
            FofaDork = input("Please enter the search sentence：")
            loglogo("The Fofa search sentence is：{fofadork}，Start docking with Fofa Api".format(fofadork = FofaDork))
            FofaResultNum = fofa_search(FofaLogin[1],FofaLogin[2],FofaDork,fofa_save_path)
            if type(FofaResultNum) == int:
                log_msg = "The search is complete and the results are saved to{path}，After the process, remove the weight, a total of {FofaResultNum}条".format(path = fofa_save_path,FofaResultNum = FofaResultNum)
                logvuln(log_msg)
            # Get search results and save to scan directory
        
    def getmode(self):
        return self.Mode

    def setmode(self,mode):
        global ScanMode
        if mode in ScanMode.keys():
            self.Mode = ScanMode[mode]
        pass

    def Load_POC(self,poc_path):
        sys.path.append(str(poc_path))
        from poc import POC
        logvuln("POC - %s Loaded"%(POC._info["name"]))
        return POC,poc_path

    def Unload_POC(self,poc_path):
        sys.path.remove(poc_path)
        del sys.modules["poc"]

    def get_some_poc(self,poc_path):
        poc_path = poc_path[:-7] if poc_path.endswith("poc.py") else poc_path
        poc_path = root_path+"/"+poc_path
        if os.path.exists(poc_path):
            loglogo("POC - %s Exist"%(poc_path))
            self.addpoc(poc_path)
        else:
            logvuln("POC - %s Does Not Exist, please confirm the path and re-specify"%(poc_path))
            exit()
        pass

    def get_all_poc(self):
        for app in os.listdir(poc_path):
            if app == "demo":
                continue
            app_path = poc_path +app
            for vulnname in os.listdir(app_path):
                if vulnname.startswith("."):
                    continue
                if vulnname.startswith("_"):
                    continue
                if vulnname.startswith("Url_Alive"):
                    continue
                vuln_path = app_path + "/" +vulnname
                vuln_path = vuln_path.split("/oFx/")[1]
                self.addpoc(vuln_path)

                

    def command_parser(self):
        self.CMD_ARGS = GetCommand()
        if self.CMD_ARGS.version == True:
            self.show_version()

        if self.CMD_ARGS.proxy != False:
            self.setproxy()

        if self.CMD_ARGS.fofa_search:
            self.fromfofa()

        if self.CMD_ARGS.url or self.CMD_ARGS.file:
            # mode verify
            if self.CMD_ARGS.url and self.CMD_ARGS.script:
                self.setmode("Single_Verify")
            elif self.CMD_ARGS.file and self.CMD_ARGS.script:
                self.setmode("File_Verify")
            
            else:
                print("Please confirm the detection mode,\
                     \nMust provide -f or -u parameter to specify the target,\
                     \nMust provide -s parameter to specify POC or [-s all] to load all POC")
                exit()


            # single mode
            if self.getmode() == 1:
                self.get_some_poc(self.CMD_ARGS.script)
                POC,POC_Path = self.Load_POC(allpoc.get())
                
                single_mode = POC(self.CMD_ARGS.url,self.getproxy())
                single_verify = single_mode._verify()
                if single_verify[0] == True:
                    print("URL: {url}  || POC: {script} \nServer return information: \n{text} \n【Vuln】\n".format(url = self.CMD_ARGS.url,script = self.CMD_ARGS.script,text = single_verify[1]))
                else:
                    print("URL: {url}  || POC: {script} \nServer return information: \n{text} \n【UnVuln】\n".format(url = self.CMD_ARGS.url,script = self.CMD_ARGS.script,text = single_verify[1]))
            
            # enum mode
            elif self.getmode() == 2:
                loglogo("poc parser,waiting....")
                if self.CMD_ARGS.script == "all":
                    self.get_all_poc()
                elif "," in self.CMD_ARGS.script:
                    for i in self.CMD_ARGS.script.split(","):
                        self.get_some_poc(i)
                else:
                    self.get_some_poc(self.CMD_ARGS.script)
                start_time = time.time()
                while not allpoc.empty():
                    POC,POC_Path = self.Load_POC(allpoc.get())

                    with open(self.CMD_ARGS.file,"r") as f:
                        target_list = [i.strip() for i in f.readlines() if "." in i]
                    for i in target_list:
                        if i.strip() == "":
                            target_list.remove(i)
                    for i in target_list:
                        qu.put(i) 
                    run_threads(num_threads = self.CMD_ARGS.thread,thread_function = run,args=(POC,qu,self.getproxy(),self.CMD_ARGS.output,str(allpoc.qsize())))
                    # run(POC,qu,self.CMD_ARGS.proxy)
                    self.Unload_POC(POC_Path)
                if self.CMD_ARGS.output != False:
                    
                    # print(vulnoutput)
                    loglogo("扫描结束，结果汇报")
                    if len(vulnoutput) >= 1:
                        txt_output = now + ".txt" if self.CMD_ARGS.output == True else self.CMD_ARGS.output+".txt"
                        txt_output = root_path+"/output/"+txt_output
                        Txt_output(txt_output,vulnoutput,target_list)
                        
                        md_output = now + ".md" if self.CMD_ARGS.output == True else self.CMD_ARGS.output + ".md"
                        md_output = root_path+"/output/"+md_output
                        Mkdn_output(md_output,vulnoutput)
                        
            
                    else:
                        logverifyerror("目标文件中的url未匹配POC检测逻辑，疑似无漏洞")
                
                end_time = time.time()
                loglogo("This scan takes :  %d Second"%(end_time-start_time))


            