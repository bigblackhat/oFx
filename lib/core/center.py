#coding:utf-8

import sys
import queue
import os
import time


from lib.core.data import root_path,lock
from lib.core.common import get_local_version,get_latest_revision
from lib.core.log import logvuln,logwarning,logunvuln,logverifyerror,logcritical  
from lib.core.data import qu,allpoc,now,vulnoutput,unvulnoutput,unreachoutput,scan_path,poc_path
from lib.core.threads import run_threads
from lib.core.common import run,GetCommand
from lib.core.log import loglogo
from lib.core.htmloutput import output_html
from lib.fofa import get_ukey,fofa_login,ukey_save,fofa_search
from lib.core.output import Mkdn_output,Txt_output



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
        print("当前的本地版本是 {localv}".format(localv = LocalVer))
        print("获取github仓库信息，请稍等.......")
        LatestVer = get_latest_revision()
        if LatestVer == None:
            print("当前网络状况不佳，无法获取最新版本信息")
            exit()
        elif LatestVer and LocalVer != LatestVer:
            print("最新版本是 {latestv}".format(latestv = LatestVer))
            exit()
        else:
            print("目前使用的ofx是最新版本")
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

            fofa_save_path = scan_path + input("请输入文件名保存结果（不要添加文件后缀）： ") + ".txt"
            FofaDork = input("请输入搜索语句：")
            loglogo("Fofa搜索语句是：{fofadork}，开始对接 Fofa Api".format(fofadork = FofaDork))
            FofaResultNum = fofa_search(FofaLogin[1],FofaLogin[2],FofaDork,fofa_save_path)
            if type(FofaResultNum) == int:
                log_msg = "搜索完成，结果保存到 {path}，去重后，一共 {FofaResultNum}条".format(path = fofa_save_path,FofaResultNum = FofaResultNum)
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
        logvuln("POC - %s 加载完毕"%(POC._info["name"]))
        return POC,poc_path

    def Unload_POC(self,poc_path):
        sys.path.remove(poc_path)
        del sys.modules["poc"]

    def get_some_poc(self,poc_path):
        poc_path = poc_path[:-7] if poc_path.endswith("poc.py") else poc_path
        poc_path = root_path+"/"+poc_path
        if os.path.exists(poc_path):
            loglogo("POC - %s 有效"%(poc_path))
            self.addpoc(poc_path)
        else:
            logvuln("POC - %s 不存在，请确认路径并重新指定"%(poc_path))
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
                vuln_path = vuln_path.split(root_path)[1][1:]
                self.addpoc(vuln_path)

                

    def command_parser(self):
        self.CMD_ARGS = GetCommand()
        if self.CMD_ARGS.version == True:
            self.show_version()

        if self.CMD_ARGS.proxy != False:
            self.setproxy()

        if self.CMD_ARGS.fofa_search:
            self.fromfofa()

        if self.CMD_ARGS.add_poc:
            app_name = input("请输入受漏洞影响的应用名")
            vuln_name = input("请输入漏洞名")

            app_list = os.listdir(poc_path)
            if app_name in app_list:
                pass 
            else:
                os.mkdir(poc_path+app_name+"/")
            app_dir = poc_path+app_name+"/"

            vuln_list = os.listdir(app_dir)
            if vuln_name in vuln_list:
                err_msg = "该POC名已存在，请重新确认"
                exit(err_msg)

            else:
                os.mkdir(app_dir+vuln_name+"/")
            vuln_dir = app_dir+vuln_name+"/"

            with open(vuln_dir+"poc.py","w") as f:
                f.write("#coding:utf-8")
            
            reference_dir = vuln_dir+"reference/"
            os.mkdir(reference_dir)
            with open(reference_dir+"reference.md","w") as f:
                f.write("``为了帮助笔者快速理解并完成POC贡献提交的测试工作，请在该文件中写入参考文献链接，以及漏洞基本概念和漏洞检测逻辑文字描述，如何判断漏洞存在与否``")
            with open(reference_dir+"test_num_1w.txt","w") as f:
                pass
            with open(reference_dir+"success_30.txt","w") as f:
                pass

            success_msg = """
___________生成POC目录结构如下____________
    |__ {APP_NAME}/
        |__ {VULN_NAME}/
            |__ poc.py
            |__ reference/
                |__ reference.md
                |__ other file
                |__ test_num_1w.txt
                |__ success_30.txt
_________________________________________
POC路径为{VULN_PATH}
            """.format(APP_NAME = app_name,VULN_NAME = vuln_name,VULN_PATH = vuln_dir)
            exit(success_msg)


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

                if self.CMD_ARGS.script == "all":
                    err_msg = "single 模式不支持全量POC，如果有需求，请将单个url保存到一个文件中，再用-f去检测"
                    exit(err_msg)
                elif "," in self.CMD_ARGS.script:
                    err_msg = "single 模式不支持多POC，如果有需求，请将单个url保存到一个文件中，再用-f去检测"
                    exit(err_msg)

                self.get_some_poc(self.CMD_ARGS.script)
                POC,POC_Path = self.Load_POC(allpoc.get())
                
                single_mode = POC(self.CMD_ARGS.url,self.getproxy())
                single_verify = single_mode._attack()
                if single_verify[0] == True:
                    print("URL: {url}  || POC: {script} \n服务器返回信息: \n{text} \n【漏洞存在】\n".format(url = self.CMD_ARGS.url,script = self.CMD_ARGS.script,text = single_verify[1]))
                else:
                    print("URL: {url}  || POC: {script} \n服务器返回信息: \n{text} \n【漏洞不存在】\n".format(url = self.CMD_ARGS.url,script = self.CMD_ARGS.script,text = single_verify[1]))
            
            # enum mode
            elif self.getmode() == 2:
                loglogo("POC 解析中,请稍后....")
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
                
                end_time = time.time()
                total_time = int(end_time-start_time)

                if self.CMD_ARGS.output != False:
                    
                    # print(vulnoutput)
                    loglogo("扫描结束，结果汇报")
                    if len(vulnoutput) >= 1:
                        txt_output = now + ".txt" if self.CMD_ARGS.output == True else self.CMD_ARGS.output+".txt"
                        txt_output = root_path+"/output/"+txt_output
                        Txt_output(txt_output,vulnoutput,target_list)
                        
                        md_output = now + ".md" if self.CMD_ARGS.output == True else self.CMD_ARGS.output + ".md"
                        md_output = root_path+"/output/"+md_output
                        Mkdn_output(md_output,vulnoutput,target_list = target_list,total_time = total_time)
                        
            
                    else:
                        logverifyerror("目标文件中的url未匹配POC检测逻辑，疑似无漏洞")
                
                # end_time = time.time()
                loglogo("本次扫描消耗了: %d 秒"%(total_time))


            