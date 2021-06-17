#coding:utf-8
#安全人的事能叫抄么，这是致敬经典
#此处向sqlmap致敬


import logging 
from lib.core.data import now,root_path
from lib.core.enums import CUSTOM_LOGGING

logging.addLevelName(CUSTOM_LOGGING.LOGO, "(∩ᵒ̴̶̷̤⌔ᵒ̴̶̷̤∩)")
logging.addLevelName(CUSTOM_LOGGING.VULN, "~o(〃'▽'〃)o")
logging.addLevelName(CUSTOM_LOGGING.UNVULN, "ε(┬┬﹏┬┬)3")
logging.addLevelName(CUSTOM_LOGGING.NETEERROR, "(*• . •*)?")

logger = logging.getLogger("oFx_l0g")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(levelname)s: %(message)s")


# 使用FileHandler输出到文件
FILE_HANDLE = logging.FileHandler("%s.log" % (root_path + "/log/" + now))
FILE_HANDLE.setLevel(logging.DEBUG)
FILE_HANDLE.setFormatter(formatter)

# 使用StreamHandler输出到屏幕
STREAM_HANDLE = None
try:
    from lib.thirdparty.ansistrm.ansistrm import ColorizingStreamHandler
    disableColor = False

    if disableColor:
        LOGGER_HANDLER = logging.StreamHandler()
    else:
        LOGGER_HANDLER = ColorizingStreamHandler()
        LOGGER_HANDLER.level_map[logging.getLevelName("(∩ᵒ̴̶̷̤⌔ᵒ̴̶̷̤∩)")] = (None, "yellow", False)
        LOGGER_HANDLER.level_map[logging.getLevelName("~o(〃'▽'〃)o")] = (None, "green", False)
        LOGGER_HANDLER.level_map[logging.getLevelName("ε(┬┬﹏┬┬)3")] = (None, "blue", False)
        LOGGER_HANDLER.level_map[logging.getLevelName("(*• . •*)?")] = (None, "cyan", False)
except:
    STREAM_HANDLE = logging.StreamHandler()


STREAM_HANDLE.setLevel(logging.DEBUG)
STREAM_HANDLE.setFormatter(formatter)

# 添加两个Handler
logger.addHandler(FILE_HANDLE)
logger.addHandler(STREAM_HANDLE)

def loglogo(message):
    print("\033[33m")
    logger.log(CUSTOM_LOGGING.LOGO,message)

def logvuln(message):
    print("\033[32m") # 黑底绿字
    logger.log(CUSTOM_LOGGING.VULN,message)

def logunvuln(message):
    print("\033[34m") # 黑底蓝字
    logger.log(CUSTOM_LOGGING.UNVULN,message)

def logverifyerror(message):
    print("\033[36m") # 黑底青字
    logger.log(CUSTOM_LOGGING.NETEERROR,message)

def logwarning(message):
    # print("\033[35m")
    logger.warning(message)

def logcritical(message):
    # print("\033[31m")
    logger.critical(message)
