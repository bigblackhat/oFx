#coding:utf-8
from lib.core.log import loglogo

def Txt_output(filename,output_dict,target_list):
    with open(filename,"w") as f:
        for vuln_name in output_dict:
            loglogo("漏洞名：%s"%(vuln_name))
            f.write(vuln_name+"\n")
            loglogo("Total url %d 条， %d loophole"%(len(target_list),len(output_dict[vuln_name])))
            for vuln_url in output_dict[vuln_name]:
                f.write(vuln_url.split("||")[0].strip()+"\n")
            f.write("\n\n")
    loglogo("The report has been output to：%s"%(filename))

doc = ""

def Mkdn_output(filename,output_dict):
    global doc
    for poc_name in output_dict:
        doc += "# {}\n".format(poc_name)
        doc += "|url|title|\n"
        doc += "|-|-|\n"
        for vuln_url in output_dict[poc_name]:
            doc += "|{}|{}|\n".format(vuln_url.split("||")[0],vuln_url.split("||")[1])
        
    with open(filename,"w") as f:
        f.write(doc)
    loglogo("The report has been output to：%s"%(filename))