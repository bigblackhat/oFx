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


import lib.core
from lib.core.data import root_path

from lib.core.common import get_local_version
from lib.core.center import oFxCenter
sys.path.append(root_path)



logo = """
\033[33m        _  ______      
\033[33m    ___ |  ___|_  __
\033[31m    / _ \| |_  \ \/ /\033[0m
\033[35m    | (_) |  _|  >  <__ _Author : jijue\033[0m
\033[32m    \___/|_| __/_/\_\__ __ __Version : {version}\033[0m

\033[32m    #*#*#  https://github.com/bigblackhat/oFx  #*#*#

\033[33m       _-___________________________________-_
                
\033[0m""".format(version=get_local_version(root_path+"/info.ini"))


##########


def main():

    print(logo)

    ofxcenter = oFxCenter()
    
    
    
if __name__ == "__main__":
    main()