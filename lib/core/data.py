#coding:utf-8

import time
import os
import queue
import threading

now=str(int(time.time()))

root_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

MAX_NUMBER_OF_THREADS = 50

qu = queue.Queue()

vulnoutput=list()
unvulnoutput=[]
unreachoutput=[]

lock=threading.Lock()