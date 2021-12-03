from bs4 import BeautifulSoup as bp
import requests
from urllib.parse import urlparse #이거 @들어간거 해석을 잘 못해요;;
import logger
import threading
import time

GET = "GET "
POST = "POST"
ORIGIN = None
run_cookies = None
DROP_DICT = {True:"○", False:"●"}
SPACE = "http:_testtool"
#날짜 관련된 것들은 최근 날짜로 자동으로 갱신하게 time 쓸까 생각중
SPACE_BY_TYPES = {"checkbox":SPACE, "color":"#ffffff", "date":"1990-01-01", "datetime-local":"1990-01-01T01:01", "email":"abc@example.com", "file":"white.jpg", "hidden":SPACE, "month":"1990-01", "number":"1", "password":SPACE, "radio":SPACE, "search":SPACE, "tel":"000-0000-0000", "text":SPACE, "time":"01:01", "url":"http://example.com", "week":"1990-W01"}
# TYPES = ["date", "datetime-local", "email", "file", "hidden", "month", "password", "radio", "search", "tel", "text", "time", "url", "week"]
BLACKLIST_TYPES = ["button", "reset", "submit", "image"]
ATTRIBUTE_BY_TAG_NAME = {"a":"href", "link":"href", "iframe":"src", "form":"action"}
HTTP_MODE = "http"
SCAN_DIR = "./scan"
FAST_SCAN = True
VERBOSE = False

class NotValidURL(Exception): pass
class Developing(Exception): pass
class ConnectionError(Exception): pass
class Return(Exception): pass


class UrlObj():

    url = None
    method = None
    data = None

    def __init__(self, url, method, data={}, params={}):
        self.url = url
        self.method = method.upper()
        self.data = data
        self.params = params

        self.set_params()
        self.url_repair()

    def set_params(self):
        #url에 존재하는 GET데이터들을 params로 이동
        parsed = urlparse(self.url)
        querys = parsed.query.split("&")
        if querys == ['']: return
        for i in querys:
            try: key, value = i[:i.index("=")], i[i.index("=")+1:]
            except ValueError: continue
            self.params[key] = value

    def url_repair(self):
        #url에 scheme이랑 origin 붙이기, https는 http로
        parsed = urlparse(self.url)
        if parsed.scheme in ['http', 'https']:
            self.url = f"{parsed.scheme}://{ORIGIN}{parsed.path}"
        else:
            self.url = f"{HTTP_MODE}://{ORIGIN}{parsed.path}"


    def go(self):
        global run_cookies
        #get, post에 따라 requests 날리기
        if self.method == POST: do = post
        else: do = get

        try: res = do(self.url, params=self.params, data=self.data, cookies=run_cookies)
        except requests.exceptions.ConnectionError:
            raise ConnectionError(self.url, self.params, self.data)
        
        for i in res.headers.get("Set-Cookie", "").split(";"):
            if '=' not in i: continue
            k, v = i.split("=")
            run_cookies[k] = v
        return res


class Spider():

    urlobj_list = []
    thread_num = 0

    def __init__(self):
        pass

    def run(self, url, cookies, fast_scan=True, v=False):
        #초기화 및 loop 시작 지점
        global ORIGIN, run_cookies, HTTP_MODE, FAST_SCAN, VERBOSE

        logger.title("SCAN")

        VERBOSE = v
        logger.info("VERBOSE:", VERBOSE)
        FAST_SCAN = fast_scan
        logger.info("FAST_SCAN:", FAST_SCAN)
        HTTP_MODE = urlparse(url).scheme
        logger.info("HTTP_MODE:", HTTP_MODE)
        ORIGIN = urlparse(url).netloc
        logger.info("ORIGIN:", ORIGIN)
        run_cookies = cookies
        logger.info("run_cookies:", run_cookies)
        # try: os.remove(f"./{SCAN_DIR}/{ORIGIN}.txt")
        # except: pass
        with open(f"./{SCAN_DIR}/{ORIGIN.replace(':', '..')}.txt", "w") as f: f.write("")
        self.loop(UrlObj(url, GET, {}))
        # self.loop(UrlObj("/robots.txt", GET, {}))
        # self.loop(UrlObj("/.htaccess", GET, {}))
        while self.thread_num != 0:
            time.sleep(0.5)
            # logger.debug("THREAD_NUM:", self.thread_num)
        logger.debug(len(self.urlobj_list))
        return self.urlobj_list.copy()

    def loop(self, urlobj):
        if FAST_SCAN:
            # logger.debug("LOOP!")
            t = threading.Thread(target=self.loop_thread, args=(urlobj,))
            t.daemon = True
            t.start()
        else:
            self.loop_thread(urlobj)

    def loop_thread(self, urlobj):
        #메인 루프
        self.thread_num += 1
        try:
            if not self.is_okay_to_loop(urlobj): raise Return
            self.urlobj_list.append(urlobj)
            res = urlobj.go()
            drop = res.status_code != 200
            if VERBOSE: logger.scan(DROP_DICT[drop], res.status_code, urlobj.method, urlobj.url, urlobj.params, urlobj.data)
            else: logger.scan(DROP_DICT[drop], res.status_code, urlobj.method, urlobj.url)
            if drop: raise Return
            self.save(urlobj)
            
            soup = bp(res.text, "html.parser")

            for tag_name in ["a", "link", "iframe"]:
                for tag in soup.find_all(tag_name):
                    # print(tag)
                    url = tag.get(ATTRIBUTE_BY_TAG_NAME[tag_name], None)
                    if url == None: continue
                    obj = UrlObj(url, GET, {})

                    # if not self.is_okay_to_loop(obj): continue

                    # self.urlobj_list.append(obj)
                    self.loop(obj)

            for tag_name in ["form"]:
                for tag in soup.find_all(tag_name):
                    # logger.debug(tag)
                    url = tag.get('action', urlobj.url)
                    dicts = {}
                    for attr in ['input', 'textarea']:
                        for inp in tag.find_all(attr):
                            if not inp.get('name', None): continue
                            if inp.get('value', None) and inp['value'] != "": dicts[inp['name']] = inp['value']
                            else: 
                                if inp.get('type', 'text') in BLACKLIST_TYPES: continue
                                dicts[inp['name']] = SPACE_BY_TYPES[inp.get('type', 'text')]

                    

                    params = {}
                    data = {}
                    method = tag.get('method', GET).upper()
                    # if method == GET: params = dicts
                    # else: data = dicts

                    if method == POST: data = dicts
                    else:
                        params = dicts
                        method = GET

                    # logger.debug("check:", urlobj.url)

                    if not url:
                        url = urlobj.url
                    if url[0] == "?":
                        url = urlobj.url + url
                    obj = UrlObj(url, method, params=params, data=data)

                    self.loop(obj)

        except Return: pass
        except Exception as e: logger.error(e)
        except: logger.error("Unknown Error!!!")
        self.thread_num -= 1

    def is_in_urlobj_list(self, obj):
        #해당 URL이 urlobj_list 안에 있으면 안됨
        #(11.15)조건수정: 주소뿐만 아니라 값의 종류와 개수도 달라야 함
        for urlobj in self.urlobj_list:
            # print(urlobj.url, obj.url)
            if urlobj.url == obj.url and urlobj.method == obj.method:
                flag = 1
                # for i in obj.params:
                #     if urlobj.params.get(i, None) == None:
                #         flag=0
                #         break
                # for i in urlobj.params:
                #     if obj.params.get(i, None) == None:
                #         flag=0
                #         break
                # for i in obj.data:
                #     if urlobj.data.get(i, None) == None:
                #         flag=0
                #         break
                # for i in urlobj.data:
                #     if obj.data.get(i, None) == None:
                #         flag=0
                #         break
                # if flag:
                #     return True
                uop = list(urlobj.params); uop.sort()
                op = list(obj.params); op.sort()
                uod = list(urlobj.data); uod.sort()
                od = list(obj.data); od.sort()
                if uop == op and uod == od:
                    return True
        return False

    def is_okay_to_loop(self, obj):
        i1 = is_url(obj)
        i2 = not self.is_in_urlobj_list(obj)
        i3 = is_same_origin(obj)
        # print(i1, i2, i3)
        return i1 and i2 and i3

    def save(self, obj):
        with open(f"./{SCAN_DIR}/{ORIGIN.replace(':', '..')}.txt", "a") as f:
            f.write(str((obj.url, obj.method, obj.params, obj.data))+"\n")
        

def is_url(obj):
    #샵으로 시작하면 안됨
    return obj.url[0] != "#"

def is_same_origin(obj):
    #같은 origin인지 확인
    netloc = urlparse(obj.url).netloc
    return netloc == ORIGIN

def scan(url, cookies={}, fast_scan=True, v=False):
    # log = logger.Logger()
    # sp = Spider(log)
    sp = Spider()
    sp.run(url, cookies, fast_scan=fast_scan, v=v)

def post(url, params, data, cookies={}):
    # logger.attack(url, params, data, cookies)
    return requests.post(url, params=params, data=data, cookies=cookies, timeout=10)

def get(url, params, data, cookies={}):
    # logger.attack(url, params, data, cookies)
    return requests.get(url, params=params, data=data, cookies=cookies, timeout=10)