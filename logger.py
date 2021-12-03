import time

DEBUG = 1
NO_DEBUG = 0

class Logger():

    mode=None

    def __init__(self, debug=DEBUG):
        self.mode = debug
    
    def timestamp(self):
        return time.strftime("%Y-%m-%d %H:%M:%S")

    def log(self, *argv, **kwargs):
        print(self.timestamp(), *argv, **kwargs)

    def debug(self, *argv, **kwargs):
        if self.mode == DEBUG:
            self.log("[DEBUG]", *argv, **kwargs)

    def info(self, *argv, **kwargs):
        self.log("[INFO]", *argv, **kwargs)

    def attack(self, *argv, **kwargs):
        self.log("[ATAK]", *argv, **kwargs)

    def scan(self, *argv, **kwargs):
        self.log("[SCAN]", *argv, **kwargs)

    def error(self, *argv, **kwargs):
        self.log("[ERROR]", *argv, **kwargs)
        
    def title(self, *argv, **kwargs):
        print("\n===========[", *(argv+("]==========\n",)), **kwargs)

    def find(self, *argv, **kwargs):
        self.log('\033[91m'+"[FIND]", *(argv+("\033[0m",)), **kwargs)


# """timestamp
# log
# debug
# info
# attack
# scan
# error
# title
# find"""

logger = Logger()

timestamp = logger.timestamp
log = logger.log
debug = logger.debug
info = logger.info
attack = logger.attack
scan = logger.scan
error = logger.error
title = logger.title
find = logger.find