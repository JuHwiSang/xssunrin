import spider
import reflected, stored
import argparse
import os

def get_args():

    parser = argparse.ArgumentParser(description="Just simple attack tool")
    parser.add_argument("url", help="Scan URL, XSS Attacks")
    parser.add_argument("--cookies", help="Use cookies")
    parser.add_argument("--selenium", action="store_const", const=True, help="Use selenium (if not, use multi-threading requests)")
    parser.add_argument("--no-scan", action="store_const", const=True, help="Attack Without Scan")
    parser.add_argument("--no-attack", action="store_const", const=True, help="Scan Without Attack")
    parser.add_argument("--reflected", action="store_const", const=True, help="Scan + Reflected")
    parser.add_argument("--stored", action="store_const", const=True, help="Scan + Reflected + Stored")
    parser.add_argument("--no-fast", action="store_const", const=True, default=False, help="Disable multi-threading")
    parser.add_argument("--verbose", action="store_const", const=True, default=False, help="Verbose Output")
    parser.add_argument("--show", action="store_const", const=True, default=False, help="Show selenium browser")

    parser = parser.parse_args()

    print("url:", parser.url)
    print("cookies:", parser.cookies)
    print("selenium:", parser.selenium)

    return parser

def parse_cookie(cookies_str):
    if cookies_str == None: return {}
    ret = {}
    for i in cookies_str.split(";"):
        key, value = i.strip().split("=")
        ret[key] = value
    return ret

def main():
    if not os.path.isdir("./scan"): os.mkdir("./scan")
    if not os.path.isdir("./attack"): os.mkdir("./attack")
    if not os.path.isdir("./result"): os.mkdir("./result")
    if not os.path.isdir("./result/reflected"): os.mkdir("./result/reflected")
    if not os.path.isdir("./result/stored"): os.mkdir("./result/stored")

    parser = get_args()
    url = parser.url
    cookies = parse_cookie(parser.cookies)
    if not parser.no_scan: spider.scan(url, cookies=cookies.copy(), fast_scan=not parser.no_fast, v=parser.verbose)
    r, s = 0, 0
    if not parser.no_attack:
        if parser.reflected or parser.stored:
            if parser.reflected:
                if r == 0:
                    reflected.attack(url, cookies=cookies, selenium=parser.selenium, fast_attack=not parser.no_fast, v=parser.verbose, ss=parser.show)
                    r = 1
            elif parser.stored:
                if r == 0:
                    reflected.attack(url, cookies=cookies, selenium=parser.selenium, fast_attack=not parser.no_fast, v=parser.verbose, ss=parser.show)
                    r = 1
                if s == 0:
                    stored.attack(url, cookies=cookies, selenium=parser.selenium, fast_attack=not parser.no_fast, v=parser.verbose, ss=parser.show)
                    s = 1

        else:
            reflected.attack(url, cookies=cookies.copy(), selenium=parser.selenium, fast_attack=not parser.no_fast, v=parser.verbose, ss=parser.show)
            stored.attack(url, cookies=cookies.copy(), selenium=parser.selenium, fast_attack=not parser.no_fast, v=parser.verbose, ss=parser.show)

if __name__ == "__main__":
    main()
