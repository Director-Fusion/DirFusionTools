import requests
from bs4 import BeautifulSoup as bs4
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

cookies = {
    '$Cookie: 85698974155bb6892604ef972ddb2cdd': '61be3513c4407fbead5dd4747708fee3',
    'JSESSIONID': '_LMcJpie1z8oRM-3LuehAv9HopyZp6ZAxn__TsvroHRT2g4ZDSma\\u00211701208557',
}

headers = {
    'Connection': 'keep-alive',
    'Cache-Control': 'max-age=0',
    'sec-ch-ua': '";Not A Brand";v="99", "Chromium";v="88"',
    'sec-ch-ua-mobile': '?0',
    'Upgrade-Insecure-Requests': '1',
    'Origin': 'https://clslp.cat.com',
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-User': '?1',
    'Sec-Fetch-Dest': 'document',
    'Referer': 'https://clslp.cat.com/tbr/main/forgotPassword.html',
    'Accept-Language': 'en-US,en;q=0.9',
}

data = {
  'userName': 'test'
}

#response = requests.post('https://XXXXXXXXXXXX.com/forgotPassword.html', headers=headers, cookies=cookies, data=data, verify=False)
#print(bs4(response.content))
