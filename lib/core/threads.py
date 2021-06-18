#coding:utf-8

import time
import threading
import traceback

from lib.core.log import logwarning,loglogo
from lib.core.data import MAX_NUMBER_OF_THREADS

def exception_handled_function(thread_function, args=(), silent=False):
    try:
        thread_function(*args)
    except KeyboardInterrupt:
        raise
    except Exception as ex:
        logwarning("thread {0}: {1}".format(threading.currentThread().getName(), str(ex)))
        logwarning(traceback.format_exc())

def run_threads(num_threads, thread_function, args: tuple = (), forward_exception=True, start_msg=True):
    threads = []

    try:
        if num_threads > 1:
            if start_msg:
                info_msg = "starting {0} threads".format(num_threads)
                loglogo(info_msg)

            if num_threads > MAX_NUMBER_OF_THREADS:
                warn_msg = "starting {0} threads, more than MAX_NUMBER_OF_THREADS:{1}".format(num_threads, MAX_NUMBER_OF_THREADS)
                logwarning(warn_msg)
                num_threads = MAX_NUMBER_OF_THREADS

        else:
            thread_function(*args)
            return 

        # Start the threads
        for num_threads in range(num_threads):
            thread = threading.Thread(target=exception_handled_function, name=str(num_threads),
                                      args=(thread_function, args))
            try:
                thread.start()
            except Exception as ex:
                err_msg = "error occurred while starting new thread ('{0}')".format(str(ex))
                logwarning(err_msg)
                break

            threads.append(thread)
        alive = True
        while alive:
            alive = False
            for thread in threads:
                if thread.is_alive():
                    alive = True
                    time.sleep(0.1)
    except (KeyboardInterrupt) as ex:
        loglogo("user aborted (Ctrl+C was pressed multiple times")
        if forward_exception:
            pass
        # exit()

    except Exception as ex:
        logwarning("thread {0}: {1}".format(threading.currentThread().getName(), str(ex)))
        logwarning(traceback.format_exc())

    finally:
        return