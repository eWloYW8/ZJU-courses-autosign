import os
import re
import asyncio
import uuid
import aiohttp
from urllib.parse import urlparse, parse_qs
from dotenv import load_dotenv

load_dotenv()

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
        print("[ZJUAM] Attempting login …")

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
                print("[ZJUAM] Login success.")
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
        print("[COURSES] login begins")
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

        print("[COURSES] Login finished.")

    async def fetch(self, url: str, method="GET", headers=HEADERS, **kwargs):
        if self.first:
            await self.login()
            self.first = False
        return await self.session.request(method, url, headers=headers, **kwargs)

CONFIG = {
    "raderAt": "ZJGD1",
    "coldDownTime": 2
}

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
        except:
            return None

    print("[Radar] Trying configured radar point:", xy)
    res = await _req(xy[0], xy[1])
    if res and res.get("status_name") == "on_call_fine":
        print("[Radar] Success at configured point!")
        return True

    print("[Radar] Trying all Rader points...")
    for key, (x, y) in RaderInfo.items():
        res = await _req(x, y)
        if res and res.get("status_name") == "on_call_fine":
            print("[Radar] Success at:", key)
            return True

    print("[Radar] All locations failed.")
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
    print(f"[Bruteforce] cracking rollcall #{rid}")
    
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
                print(f"[Bruteforce] SUCCESS! code = {code}")

    tasks = []
    for i in range(10000):
        if found_event.is_set(): break
        code = f"{i:04d}"
        tasks.append(asyncio.create_task(_worker(code)))

    await asyncio.gather(*tasks)

    if result_code:
        return result_code
    
    print("[Bruteforce] Failed: no code found.")
    return None

async def main():
    user = os.getenv("ZJU_USERNAME")
    pwd = os.getenv("ZJU_PASSWORD")

    if not user or not pwd:
        print("请设置环境变量 ZJU_USERNAME 与 ZJU_PASSWORD")
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
                    print(f"[Auto Sign-in #{req_num}] No rollcalls.")
                    req_num += 1
                    await asyncio.sleep(CONFIG["coldDownTime"])
                    continue

                for rc in rollcalls:
                    rid = rc["rollcall_id"]
                    title = rc.get("title")
                    course = rc.get("course_title")
                    status_name = rc.get("status_name")
                    status = rc.get("status")
                    created_by_name = rc.get("created_by_name")
                    department = rc.get("department_name")

                    print(f"\n[Found] {title} @ {course}  by  {created_by_name} ({department})")
                    print(f"[Rollcall Info] rid={rid}, status={status}, status_name={status_name}, "
                          f"is_radar={rc.get('is_radar')}, is_number={rc.get('is_number')}")

                    if status_name in ("on_call_fine", "on_call") or status in ("on_call_fine", "on_call"):
                        print(f"[Skip] Rollcall #{rid} 已签到（status_name={status_name}）")
                        await asyncio.sleep(CONFIG["coldDownTime"])
                        continue
                    
                    if rc.get("is_radar"):
                        xy = RaderInfo[CONFIG["raderAt"]]
                        print(f"[Radar] 开始尝试雷达点名: rid={rid}")
                        ok = await answer_radar(courses, xy, rid)
                        print(f"[Radar] 结果: {'成功' if ok else '失败'}")

                    if rc.get("is_number"):
                        print(f"[Number] 开始破解点名 code: rid={rid}")
                        code = await brute_force_number(courses, rid)
                        if code:
                            print(f"[Number] 点名成功！code = {code}")
                        else:
                            print("[Number] 未找到正确 code")

                    await asyncio.sleep(CONFIG["coldDownTime"])

            except Exception as e:
                print(f"[Error] {e}")
                await asyncio.sleep(5)

    finally:
        await am.close()
        await courses.close()

if __name__ == "__main__":
    asyncio.run(main())