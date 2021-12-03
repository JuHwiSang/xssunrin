# Xssunrin
Find the XSS vulnerability in the requested url.

Made by. team 1321

The program is under development. You probably don't understand the program. It is very inefficient.

Developed on Windows.

## target
- reflected xss
- stored xss

## initialization
<code>
pip install -r requirements.txt
</code>

## Running
<code>
python3 simple_attack.py URL [--OPTIONS]
</code>

### Options
- --selenium : Use selenium (if not, use multi-threading requests)
- --cookies : Use cookies
- --reflected : Scan + Reflected
- --stored : Scan + Reflected + Stored
- --no-scan : Attack Without Scan
- --no-attack : Scan Without Attack
- --no-fast : Disable multi-threading
- --verbose : Verbose Output
- --show : Show selenium browser
