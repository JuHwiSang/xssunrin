import threading
from urllib.parse import urlparse, quote
import requests
import logger
import re
from bs4 import BeautifulSoup as bp
import time
import json

from reflected import get_status, is_payload

GET = "GET "
POST = "POST"
COOKIE = "COOKIE"

ATTACK_DIR = "./attack"
SCAN_DIR = "./scan"
ORIGIN = None
DEEP = 1
PAYLOADS = ['<script>alert("{}")</script>', '<img src="X" onerror="alert(\'{}\')">']
ATTRIBUTE_BY_TAG_NAME = {"a":"href", "link":"href", "iframe":"src", "form":"action"}
SPACE = "http:_testtool"
SPACE_BY_TYPES = {"checkbox":SPACE, "color":"#ffffff", "date":"1990-01-01", "datetime-local":"1990-01-01T01:01", "email":"abc@example.com", "file":"white.jpg", "hidden":SPACE, "month":"1990-01", "number":"1", "password":SPACE, "radio":SPACE, "search":SPACE, "tel":"000-0000-0000", "text":SPACE, "time":"01:01", "url":"http://example.com", "week":"1990-W01"}
BLACKLIST_TYPES = ["button", "reset", "submit", "image"]
HTTP_MODE = None
DROP_DICT = {True:"○", False:"●"}
FAST_ATTACK = None
VERBOSE = False
thread_num = 0
went_list = []
already_exploited_list = []

def attack(url, cookies, selenium, fast_attack=True, v=False, ss=False):
    global ORIGIN, HTTP_MODE, went_list, attacks, FAST_ATTACK, VERBOSE

    logger.title("STORED XSS")
    
    with open(f"./result/stored/{ORIGIN}.txt", 'w') as f: f.write("")
    VERBOSE = v
    FAST_ATTACK = fast_attack
    went_list = []
    HTTP_MODE = urlparse(url).scheme
    ORIGIN = url_repair(url)
    urls = read_urls()
    attacks = read_attacks()

    # for url in urls:
    #     if url[1] == "GET": go = requests.get
    #     else: go = requests.post
    #     res = go(url[0], params=url[2], data=url[3], cookies=cookies)
    #     if is_alert(res.text):
    #         print_find(url, attack)
    #     for location in get_location(res.text):
    #         if location['method'] == GET: go = requests.get
    #         else: go = requests.post
    #         res = go(location['url'], params=location['params'], data=location['data'], cookies=cookies)
    #         if is_alert(res.text):
    #             print_find(url, attack)

    locations = []  
    for _url in urls:
        locations.append({'method':_url[1], 'url':_url[0], 'params':_url[2], 'data':_url[3]})

    if selenium:
        # logger.error("개발중: 쿠키 문제, redirect to requests attack")
        init_selenium_module()
        driver = get_driver(url, cookies, ss)
        attack_by_selenium(driver, locations, 0)
        driver.quit()
        return

    loop(locations, cookies, 0)
    while thread_num != 0: time.sleep(0.5)

def attack_by_selenium(driver, locations, cnt):
    global already_exploited_list
    # init_selenium_module()
    for location in locations:
        try:
            if not okay_to_go(location): continue
            if is_already_exploited(location): continue
            if location['method'] == GET: go = get
            else: go = post
            go(driver, location['url'], params=location['params'], data=location['data'])
            status_code = get_status(driver)
            if VERBOSE: logger.attack(DROP_DICT[status_code!=200], status_code, location['method'], location['url'], location['params'], location['data'], driver.get_cookies())
            else: logger.attack(DROP_DICT[status_code!=200], status_code, location['method'], location['url'])
            c = is_alert_selenium(driver)
            if c:
                print_find(c, location)
                already_exploited_list.append({'method':location['method'], 'url':location['url']})
            if cnt <= DEEP:
                attack_by_selenium(driver, get_location(driver.page_source, location['url']), cnt+1)
        except KeyboardInterrupt: raise KeyboardInterrupt
        except: pass

def is_alert_selenium(driver):
    # print("check!")
    try:
        while 1:
            alert = driver.switch_to_alert()
            if is_payload(alert.text): c = int(alert.text[len("test_XSS"):])
            alert.accept()
    except selenium.common.exceptions.NoAlertPresentException:
        pass
    return c

def post(driver, url, params, data):
    url_tmp = url+params_to_str(params)
    ret = f'<form method="POST" action="{url_tmp}" name="to_submit">'
    for k, v in data.items():
        ret += f'<input type="hidden" name="{quote(k)}" value="{quote(v)}">'
    ret += "</form><script>document.to_submit.submit();</script>"
    driver.execute_script(f"document.write('{ret}');")
    driver.implicitly_wait(5)

def get(driver, url, params, data):
    t = url+params_to_str(params)
    # logger.debug(t)
    driver.get(t)
    driver.implicitly_wait(5)

def params_to_str(params):
    ret = "?"
    for k ,v in params.items():
        ret += f"{quote(k)}={quote(v)}&"
    ret = ret[:-1]
    return ret

def get_status(driver):
    logs = driver.get_log("performance")
    for log in logs:
        if log['message']:
            d = json.loads(log['message'])
            try:
                content_type = 'text/html' in d['message']['params']['response']['headers']['content-type']
                response_received = d['message']['method'] == 'Network.responseReceived'
                if content_type and response_received:
                    return d['message']['params']['response']['status']
            except:
                pass

def get_driver(url, cookies, ss):
    webdriver_options = webdriver.ChromeOptions()
    if not ss:
        webdriver_options.add_argument('headless')
        webdriver_options.add_argument("disable-gpu")

    capabilities = DesiredCapabilities.CHROME.copy()
    capabilities['goog:loggingPrefs'] = {'performance': 'ALL'}

    driver = webdriver.Chrome(executable_path='./chrome/chromedriver.exe', options=webdriver_options, desired_capabilities=capabilities)
    driver.get(url)
    driver.implicitly_wait(5)
    for cookie in cookies:
        # driver.add_cookie({'name':cookie, 'value':cookies[cookie], 'domain':urlparse(url).netloc})
        driver.add_cookie({'name':cookie, 'value':cookies[cookie]})
        # print(urlparse(url).netloc)
        # driver.execute_script(f"document.cookie = '{cookie}:{cookies[cookie]}'")

    return driver

def init_selenium_module():
    global webdriver, DesiredCapabilities, By, selenium
    import selenium
    from selenium import webdriver
    from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
    from selenium.webdriver.common.by import By

def loop(locations, cookies, cnt):
    if FAST_ATTACK:
        t = threading.Thread(target=loop_thread, args=(locations, cookies, cnt))
        t.daemon = True
        t.start()
    else:
        loop_thread(locations, cookies, cnt)

def loop_thread(locations, cookies, cnt):
    global already_exploited_list, thread_num
    thread_num += 1
    try:
        for location in locations:
            if not okay_to_go(location): continue
            if is_already_exploited(location): continue
            if location['method'] == GET: go = requests.get
            else: go = requests.post
            # logger.debug(location)
            try: res = go(location['url'], params=location['params'], data=location['data'], cookies=cookies)
            except KeyboardInterrupt: raise KeyboardInterrupt
            except: continue
            re_cookies(res, cookies)
            c = is_alert(res.text)
            if VERBOSE: logger.attack(DROP_DICT[res.status_code!=200], res.status_code, location['method'], location['url'], location['params'], location['data'], cookies)
            else: logger.attack(DROP_DICT[res.status_code!=200], res.status_code, location['method'], location['url'])
            if c:
                print_find(c, location)
                already_exploited_list.append({'method':location['method'], 'url':location['url']})
            if cnt <= DEEP:
                loop(get_location(res.text, res.url), cookies.copy(), cnt+1)
    except:
        pass
    thread_num -= 1

def re_cookies(res, cookies):
    for i in res.headers.get("Set-Cookie", "").split(";"):
        if '=' not in i: continue
        k, v = i.split("=")
        cookies[k] = v


def okay_to_go(location):
    global went_list
    if (location['params'] == {} and location['data'] == {}) and location['url'] in went_list:
        return False
    went_list.append(location['url'])
    return True

def is_already_exploited(location):
    for i in already_exploited_list:
        if location['method'] == i['method'] and location['url'] == i['url']:
            return True
    return False

def set_params(url):
    #url에 존재하는 GET데이터들을 params로 이동
    ret = {}
    parsed = urlparse(url)
    return parse_query(parsed.query)

def url_repair_p(url):
    #url에 scheme이랑 origin 붙이기, https는 http로
    parsed = urlparse(url)
    if parsed.scheme in ['http', 'https']:
        url = f"{parsed.scheme}://{ORIGIN}{parsed.path}"
    else:
        url = f"{HTTP_MODE}://{ORIGIN}{parsed.path}"

    return url


def get_location(context, n_url):

    ret = []

    soup = bp(context, "html.parser")

    for tag_name in ["a", "link", "iframe"]:
        for tag in soup.find_all(tag_name):
            url = tag.get(ATTRIBUTE_BY_TAG_NAME[tag_name], None)
            if url == None: continue
            
            query = set_params(url)
            url = url_repair_p(url)

            ret.append({'method':GET, 'url':url, 'params':query, 'data':{}})

    for tag_name in ["form"]:
        for tag in soup.find_all(tag_name):
            # self.log.debug(tag)
            url = tag.get('action', n_url)
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
            # method = tag.get('method', GET).upper()
            # if method == GET: params = dicts
            # else: data = dicts
            if method == POST: data = dicts
            else:
                params = dicts
                method = GET

            if not url:
                url = n_url
            if url[0] == "?":
                url = n_url + url

            query = set_params(url)
            url = url_repair_p(url)

            ret.append({'method':method, 'url':url, 'params':params, 'data':data})

    return ret

def print_find(c, location):
    for i in attacks:
        if i['attack_cnt'] == c:
            break
    logger.find(i['method'], i['url'], ", attackable:", i['param_name'], (i[i['method']])[i['param_name']])
    logger.find("xss url:", location['method'], location['url'])
    # 결과값 저장 코드 추가
    with open(f"./result/stored/{ORIGIN}.txt", 'a') as f:
        f.write(str({'method':i['method'], 'url':i['url'], 'param_name':i['param_name'], 'payload':(i[i['method']])[i['param_name']]}))

def parse_query(text):
    if not text: return {}
    ret = {}
    for i in text.split("&"):
        k, v = i.split("=")
        ret[k] = v

    return ret

def is_alert(context):
    for p in PAYLOADS:
        p = p.replace("(", "\\(").replace(")", "\\)")
        i, b = p.split("{}")
        r = re.compile(f"{i}test_XSS[0-9]+{b}")
        f = r.findall(context)
        if f:
            f = f[0]
            # print(i, b, '\n', f)
            return int(f.split("test_XSS")[1].split(b.replace("\\)", ")").replace("\\(", "("))[0])

def read_urls():
    ret = []
    with open(f"./{SCAN_DIR}/{ORIGIN}.txt", "r") as f:
        for i in f.readlines():
            ret.append(eval(i))

    return ret

def read_attacks():
    ret = []
    with open(f"./{ATTACK_DIR}/{ORIGIN}.txt", "r") as f:
        for i in f.readlines():
            line = eval(i)
            ret.append({
                "attack_cnt":line[0],
                "param_name":line[1],
                "method":line[2][0],
                "url":line[2][1],
                GET:line[2][2],
                POST:line[2][3],
                COOKIE:line[2][4]
            })

    return ret

def url_repair(url):
    return urlparse(url).netloc.replace(":", "..")
