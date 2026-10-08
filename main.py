import json, requests, re, os, time, random, ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from preferences import prefs
from logger import logger

IP_LIST = {}
accounts_list = {}
hasE = False

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Connection': 'keep-alive'
}

def validate_ip_port(ip, port):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_multicast or ip_obj.is_unspecified:
            return False
    except ValueError:
        return False
    ip_parts = ip.split('.')
    for part in ip_parts:
        if not 0 <= int(part) <= 255:
            return False
    if not 1 <= int(port) <= 65535:
        return False
    return True

def verify(proxy):
    target_url = 'https://bbs.binmt.cc/forum.php?mod=guide&view=hot'
    proxies = {
        'https': f'http://{proxy}',
        'http': f'http://{proxy}'
    }
    start_time = time.time()
    try:
        response = requests.get(target_url, headers=headers, proxies=proxies, timeout=(5, 8))
        return proxy, response.ok, int((time.time() - start_time) * 1000)
    except:
        return proxy, False, -1

def is_phone_number(username):
    pattern = r'^1[3-9]\d{9}$'
    return re.match(pattern, username) is not None

def format_phone_number(phone):
    if len(phone) == 11:
        return f"{phone[:3]}****{phone[-4:]}"
    return phone

def format_username(username):
    if is_phone_number(username):
        return format_phone_number(username)
    n = len(username)
    if n <= 2:
        return username
    hide_rules = {3:1,4:2,5:3,6:2,7:3,8:4,9:3,10:4}
    hide = hide_rules.get(n, 4)
    keep = n - hide
    left = keep // 2
    right = keep - left
    return username[:left] + '*' * hide + username[-right:]

def load():
    myset = set()
    successful_proxies = []
    try:
        with open("src/ips.txt", "r", encoding="utf-8") as f:
            for line in f:
                ip = line.strip()
                if ":" not in ip or not ip: continue
                newIp, newPort = ip.split(':', 1)
                if not validate_ip_port(newIp, newPort): continue
                myset.add(ip)
    except Exception as e:
        pass
    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = [executor.submit(verify, proxy) for proxy in myset]
        for future in as_completed(futures):
            proxy, is_valid, requestTime = future.result()
            if is_valid:
                successful_proxies.append((proxy, requestTime))
    successful_proxies.sort(key=lambda x: x[1])
    logger.info("可用ip代理:")
    for index, (proxy, req_time) in enumerate(successful_proxies, 1):
        logger.info(f"{index}: {proxy} - {req_time}ms")
        IP_LIST[proxy] = True

def diagnostic(stage, response):
    # Never log raw HTML, credentials, cookies, formhash, or redirect URLs.
    logger.info("%s: HTTP %s, type=%s, bytes=%s, redirected=%s",
                stage, response.status_code,
                response.headers.get("Content-Type", "unknown").split(";")[0],
                len(response.content), bool(response.history))


def checkIn(user, pwd, ip=None):
    global hasE
    with requests.Session() as req:
        req.trust_env = False
        req.headers.update(headers)
        logger.info("%s 使用 GitHub Actions 直连签到", format_username(user))
        try:
            url = 'https://bbs.binmt.cc/member.php?mod=logging&action=login&infloat=yes&handlekey=login&inajax=1&ajaxtarget=fwin_content_login'
            resp = req.get(url, timeout=(12, 30))
            diagnostic("获取登录表单", resp)
            if not resp.ok:
                return False
            resp.encoding = resp.apparent_encoding
            login_token = loginhash(resp.text)
            form_token = formhash(resp.text)
            logger.info("登录表单解析: loginhash=%s, formhash=%s",
                        bool(login_token), bool(form_token))
            if not login_token or not form_token:
                logger.warning("登录表单缺少必要字段，可能是页面结构变化或访问限制")
                return False

            url = f'https://bbs.binmt.cc/member.php?mod=logging&action=login&loginsubmit=yes&handlekey=login&loginhash={login_token}&inajax=1'
            data = {
                'formhash': form_token,
                'referer': 'https://bbs.binmt.cc/k_misign-sign.html',
                'fastloginfield': 'username',
                'username': user,
                'password': pwd,
                'questionid': '0',
                'answer': '',
                'agreebbrule': ''
            }
            resp = req.post(url, data=data, timeout=(12, 30))
            diagnostic("提交登录", resp)
            if not resp.ok:
                return False
            resp.encoding = resp.apparent_encoding
            if '失败' in resp.text:
                logger.error("%s 登录响应包含失败提示（未判定为密码错误）", format_username(user))
                hasE = True
                return False

            resp = req.get('https://bbs.binmt.cc/k_misign-sign.html', timeout=(12, 30))
            diagnostic("读取签到页", resp)
            if not resp.ok:
                return False
            resp.encoding = resp.apparent_encoding
            sign_token = formhash(resp.text)
            logger.info("签到页解析: formhash=%s", bool(sign_token))
            if not sign_token:
                logger.warning("签到页缺少 formhash，可能未登录或页面结构变化")
                return False

            url = f'https://bbs.binmt.cc/plugin.php?id=k_misign:sign&operation=qiandao&format=text&formhash={sign_token}'
            resp = req.get(url, timeout=(12, 30))
            diagnostic("执行签到", resp)
            if not resp.ok:
                return False
            resp.encoding = resp.apparent_encoding
            result = CDATA(resp.text) or resp.text
            if '已签' in result or '签到成功' in result:
                accounts_list.pop(user, None)
                prefs.put(user, prefs.getTime())
                logger.info("%s 今日签到已确认", format_username(user))
                return True
            logger.warning("签到响应未包含已知成功标志，响应长度=%s", len(resp.content))
            return False
        except requests.RequestException as exc:
            logger.warning("直连请求失败: %s: %s", type(exc).__name__, str(exc).split("url:")[0][:180])
            return False
        except Exception as exc:
            logger.exception("签到程序异常: %s", type(exc).__name__)
            return False

def loginhash(data):
    pattern = r'loginhash.*?=(.*?)[\'"]>'
    match = re.search(pattern, data, re.IGNORECASE | re.UNICODE)
    if match and match.group(1):
        return match.group(1).strip()
    return ''

def formhash(data):
    pattern = r'formhash[\'"].*?value=[\'"](.*?)[\'"].*?/>'
    match = re.search(pattern, data, re.IGNORECASE | re.UNICODE)
    if match and match.group(1):
        return match.group(1).strip()
    return ''

def CDATA(data):
    pattern = r'CDATA.*?(.*?)]>'
    match = re.search(pattern, data, re.IGNORECASE | re.UNICODE)
    if match and match.group(1):
        return match.group(1).strip('[]')
    return ''

def start():
    ACCOUNTS = os.environ.get("ACCOUNTS", "")
    if not ACCOUNTS:
        logger.warning('github ACCOUNTS变量未设置')
        exit(1)
    for duo in ACCOUNTS.split("\n"):
        if ':' not in duo:
            continue
        username, password = duo.split(':', 1)
        username = username.strip()
        password = password.strip()
        YiQianDao = prefs.get(username, "") == prefs.getTime()
        if username and password and not YiQianDao:
            accounts_list[username] = password
        elif YiQianDao:
            logger.info(f"{format_username(username)} 今日已签, 跳过签到")
    if not accounts_list:
        logger.info("没有待签到账号")
        return True
    # Direct-only: no untrusted public proxy pool.
    keys = list(accounts_list.keys())
    for i, username in enumerate(keys):
        if not checkIn(username, accounts_list[username]):
            logger.error("%s 本次签到失败", format_username(username))
        if i < len(keys) - 1:
            time.sleep(3)
    if accounts_list:
        logger.error("签到未完成，失败账号数：%d", len(accounts_list))
        return False
    return True

success = start()
prefs.save()
if hasE or not success:
    raise SystemExit(1)