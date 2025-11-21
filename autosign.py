import os
import re
import asyncio
import uuid
import aiohttp
import logging
import sys
from urllib.parse import urlparse, parse_qs
from dotenv import load_dotenv
from colorama import init, Fore, Style

init(autoreset=True)
load_dotenv()


class ColoredFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: Fore.CYAN + Style.DIM,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelno, Fore.WHITE)
        
        log_fmt = (
            f"{Fore.LIGHTBLACK_EX}%(asctime)s{Style.RESET_ALL} "
            f"{color}[%(levelname)s]{Style.RESET_ALL} "
            f"%(message)s"
        )
        
        formatter = logging.Formatter(log_fmt, datefmt="%H:%M:%S")
        return formatter.format(record)

def setup_logger():
    logger = logging.getLogger("ZJU_Auto")
    logger.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColoredFormatter())
    logger.addHandler(handler)
    return logger

logger = setup_logger()

def rsa_encrypt(password: str, exponent: str, modulus: str) -> str:
    password_bytes = password.encode('ascii')
    pwd_int = int.from_bytes(password_bytes, 'big')
    e_int = int(exponent, 16)
    n_int = int(modulus, 16)
    encrypted_int = pow(pwd_int, e_int, n_int)
    return hex(encrypted_int)[2:].rjust(128, '0')

PUBKEY_URL = "https://zjuam.zju.edu.cn/cas/v2/getPubKey"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Sec-Ch-Ua" : '"Chromium";v="142", "Microsoft Edge";v="142", "Not_A Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
}

class ZJUAM:
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.session = aiohttp.ClientSession(headers={"User-Agent": HEADERS["User-Agent"]})
        self.first_login = False

    async def close(self):
        await self.session.close()

    async def _login(self, login_url: str):
        logger.info(f"ZJUAM: Attempting login as {Fore.CYAN}{self.username}{Style.RESET_ALL}...")

        async with self.session.get(login_url) as r:
            html = await r.text()

        execution = re.search(r'name="execution" value="([^"]+)"', html)
        if not execution:
            raise Exception("Cannot find execution string in login page")
        execution = execution.group(1)

        async with self.session.get(PUBKEY_URL) as r:
            pub = await r.json()
        
        encrypted_pwd = rsa_encrypt(self.password, pub["exponent"], pub["modulus"])

        data = {
            "username": self.username,
            "password": encrypted_pwd,
            "execution": execution,
            "_eventId": "submit",
            "authcode": ""
        }

        async with self.session.post(login_url, data=data, headers=HEADERS, allow_redirects=False) as r:
            if r.status == 302:
                self.first_login = True
                logger.info("ZJUAM: Login success.")
                return r.headers.get("Location")

            if r.status == 200:
                text = await r.text()
                msg = re.search(r'<span id="msg">([^<]+)</span>', text)
                raise Exception(f"Login failed: {msg.group(1) if msg else 'Unknown reason'}")

            raise Exception("Unexpected status: " + str(r.status))

    async def login(self):
        return await self._login("https://zjuam.zju.edu.cn/cas/login")

    async def fetch(self, url: str, method="GET", headers=HEADERS, **kwargs):
        if not self.first_login:
            await self.login()
        return await self.session.request(method, url, headers=headers, **kwargs)

    async def login_service(self, service_url: str):
        full_login = "https://zjuam.zju.edu.cn/cas/login?service=" + service_url
        if self.first_login:
            async with await self.fetch(full_login, method="GET", allow_redirects=False) as r:
                if r.status == 302:
                    return r.headers.get("Location")
                return await self._login(full_login)
        else:
            return await self._login(full_login)


class COURSES:
    def __init__(self, am: ZJUAM):
        self.am = am
        self.session = aiohttp.ClientSession(headers={"User-Agent": HEADERS["User-Agent"]})
        self.first = True

    async def close(self):
        await self.session.close()

    async def login(self):
        logger.info("Courses: Login sequence started.")
        url = "https://courses.zju.edu.cn/user/index"
        
        current_url = url
        while True:
            async with self.session.get(current_url, allow_redirects=False) as r:
                location = r.headers.get("Location")
                if not location:
                    break
                
                host = urlparse(location).hostname

                if host == "zjuam.zju.edu.cn":
                    service = parse_qs(urlparse(location).query).get("service", [""])[0]
                    final_url = await self.am.login_service(service)
                    current_url = final_url
                else:
                    current_url = location

        logger.info("Courses: Login finished.")

    async def fetch(self, url: str, method="GET", headers=HEADERS, **kwargs):
        if self.first:
            await self.login()
            self.first = False
        return await self.session.request(method, url, headers=headers, **kwargs)

RaderInfo = {
    "ZJGD1": (120.089136, 30.302331),
    "ZJGX1": (120.085042, 30.30173),
    "ZJGB1": (120.077135, 30.305142),
    "YQ4":   (120.122176, 30.261555),
    "YQ1":   (120.123853, 30.262544),
    "YQ7":   (120.120344, 30.263907),
    "ZJ1":   (120.126008, 30.192908),
    "HJC1":  (120.195939, 30.272068),
    "HJC2":  (120.198193, 30.270419),
    "ZJ2":   (120.124267, 30.19139),
    "YQSS":  (120.124001, 30.265735),
    "ZJG4":  (120.073427, 30.299757)
}

CONFIG = {
    "raderAt": os.getenv("RADAR_AT", "ZJGD1"),
    "coldDownTime": int(os.getenv("COLD_DOWN_TIME", "2")),
}

if CONFIG["raderAt"] not in RaderInfo:
    logger.error(f"Config Error: Unknown radar location '{CONFIG['raderAt']}'. Please check RADAR_AT environment variable.")
    sys.exit(1)

async def answer_radar(courses: COURSES, xy, rid):
    async def _req(x, y):
        payload = {
            "deviceId": str(uuid.uuid4()),
            "latitude": y,
            "longitude": x,
            "speed": None,
            "accuracy": 68,
            "altitude": None,
            "altitudeAccuracy": None,
            "heading": None,
        }
        try:
            async with await courses.fetch(
                f"https://courses.zju.edu.cn/api/rollcall/{rid}/answer?api_version=1.1.2",
                method="PUT",
                json=payload
            ) as r:
                return await r.json()
        except Exception:
            return None

    logger.info(f"Radar: Trying default point {Fore.BLUE}{CONFIG['raderAt']}{Style.RESET_ALL}...")
    res = await _req(xy[0], xy[1])
    if res and res.get("status_name") == "on_call_fine":
        logger.info(f"Radar: {Fore.GREEN}Success at configured point!{Style.RESET_ALL}")
        return True

    logger.info("Radar: Trying all known locations...")
    for key, (x, y) in RaderInfo.items():
        res = await _req(x, y)
        if res and res.get("status_name") == "on_call_fine":
            logger.info(f"Radar: {Fore.GREEN}Success at {key}!{Style.RESET_ALL}")
            return True

    logger.warning("Radar: All locations failed.")
    return False

async def answer_number(courses: COURSES, rid, code):
    payload = {
        "deviceId": str(uuid.uuid4()),
        "numberCode": code
    }

    async with await courses.fetch(
        f"https://courses.zju.edu.cn/api/rollcall/{rid}/answer_number_rollcall",
        method="PUT",
        json=payload
    ) as r:
        if r.status != 200:
            return False
        data = await r.json()
        return data.get("status") == "on_call"

async def brute_force_number(courses: COURSES, rid):
    logger.info(f"Bruteforce: Cracking rollcall #{rid}...")
    
    sem = asyncio.Semaphore(50)
    found_event = asyncio.Event()
    result_code = None

    async def _worker(code):
        nonlocal result_code
        if found_event.is_set(): return
        
        async with sem:
            if found_event.is_set(): return
            success = await answer_number(courses, rid, code)
            if success:
                result_code = code
                found_event.set()
                logger.info(f"Bruteforce: {Fore.GREEN}SUCCESS! Code = {code}{Style.RESET_ALL}")

    tasks = []
    for i in range(10000):
        if found_event.is_set(): break
        code = f"{i:04d}"
        tasks.append(asyncio.create_task(_worker(code)))

    await asyncio.gather(*tasks)

    if result_code:
        return result_code
    
    logger.warning("Bruteforce: Failed to find code.")
    return None

async def main():
    user = os.getenv("ZJU_USERNAME")
    pwd = os.getenv("ZJU_PASSWORD")

    if not user or not pwd:
        logger.error("请设置环境变量 ZJU_USERNAME 与 ZJU_PASSWORD")
        return

    am = ZJUAM(user, pwd)
    courses = COURSES(am)

    try:
        req_num = 0
        while True:
            try:
                async with await courses.fetch("https://courses.zju.edu.cn/api/radar/rollcalls") as r:
                    data = await r.json()

                rollcalls = data.get("rollcalls", [])
                if not rollcalls:
                    # DEBUG 级别，平时不显示，防止刷屏
                    logger.debug(f"Auto Sign-in #{req_num}: No rollcalls.")
                    req_num += 1
                    await asyncio.sleep(CONFIG["coldDownTime"])
                    continue

                for rc in rollcalls:
                    rid = rc["rollcall_id"]
                    title = rc.get("title")
                    course = rc.get("course_title")
                    status_name = rc.get("status_name")
                    status = rc.get("status")
                    created_by = rc.get("created_by_name")
                    
                    # 发现新点名，使用亮色显示重要信息
                    logger.info(f"{Fore.MAGENTA}FOUND:{Style.RESET_ALL} {title} @ {course} by {created_by}")
                    logger.info(f"Meta: rid={rid}, status={status_name}, Radar={rc.get('is_radar')}, Number={rc.get('is_number')}")

                    if status_name in ("on_call_fine", "on_call") or status in ("on_call_fine", "on_call"):
                        logger.warning(f"Skip: Rollcall #{rid} already signed in.")
                        await asyncio.sleep(CONFIG["coldDownTime"])
                        continue
                    
                    if rc.get("is_radar"):
                        logger.info(f"Action: Starting Radar Sign-in for rid={rid}")
                        await answer_radar(courses, RaderInfo[CONFIG["raderAt"]], rid)

                    if rc.get("is_number"):
                        logger.info(f"Action: Starting Number Crack for rid={rid}")
                        await brute_force_number(courses, rid)

                    await asyncio.sleep(CONFIG["coldDownTime"])

            except Exception:
                logger.exception("An error occurred in the monitoring loop")
                await asyncio.sleep(5)

    finally:
        await am.close()
        await courses.close()

if __name__ == "__main__":
    asyncio.run(main())