#coding:utf-8

import logging 
from lib.data import now,root_path

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(levelname)s: %(message)s")


# 使用FileHandler输出到文件
fh = logging.FileHandler("%s.log" % (root_path + "/log/" + now))
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)

# 使用StreamHandler输出到屏幕
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)

# 添加两个Handler
logger.addHandler(ch)
logger.addHandler(fh)

def loglogo(message):
    print("\033[33m")
    logger.info(message)

def logvuln(message):
    print("\033[32m") # 黑底绿字
    logger.info(message)

def logunvuln(message):
    print("\033[34m") # 黑底蓝字
    logger.info(message)

def logverifyerror(message):
    print("\033[36m") # 黑底青字
    logger.info(message)

def logwarning(message):
    print("\033[35m")
    logger.warning(message)

def logcritical(message):
    print("\033[31m")
    logger.critical(message)
