from bs4 import BeautifulSoup
import requests

for i in range(1,5):
    cookies = {
    }

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://www.google.com/',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-User': '?1',
    }

    response = requests.get(f"https://www.zoominfo.com/pic/dearborn-mid--west-co/346540908?pageNum={i}", cookies=cookies, headers=headers).text
            
    soup = BeautifulSoup(response, 'html.parser')

    for name in soup.find_all("a", {"class": "title link"}):
        names_list = name.string
        print(names_list)
