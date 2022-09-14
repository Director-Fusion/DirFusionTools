#!/usr/bin/python

import httpx
import asyncio
import time
import sys

async def grab_data(client, url):
    resp = await client.get(url)
    results.append(resp.json()['data'][0]['attributes']['last_analysis_stats'])
    return

async def main():
    async with httpx.AsyncClient(headers=headers) as client:
        tasks = []
        with open(file, 'r') as f:
            for q in f:
                start = time.time() 
                url = f"https://www.virustotal.com/api/v3/search?query={q}"
                tasks.append(asyncio.create_task(grab_data(client, url)))
            await asyncio.gather(*tasks)
            print(f"Requests: {time.time() -  start} seconds.") 

if __name__ == '__main__':
    headers = {
    "accept": "application/json",
    "x-apikey": "3cc23f2031fac19f1fbc0500c03f9aebe30944a904a78cf3c8220d78a0989a1b"
    }
    file = sys.argv[1]
    results = []        
    asyncio.run(main())
    print(results)