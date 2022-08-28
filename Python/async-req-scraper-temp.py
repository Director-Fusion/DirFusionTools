#!/usr/bin/python

import httpx
import asyncio
import time

async def get_items(client, url):
    resp = await client.get(url)
    name = resp.json()['name']
    return print(name)

async def main():
    async with httpx.AsyncClient() as client:
        tasks = []
        for req_id in range(1,151):
            url = f"https://pokeapi.co/api/v2/pokemon/{req_id}"
            tasks.append(asyncio.create_task(get_items(client, url)))
        await asyncio.gather(*tasks)    
start = time.time()          
asyncio.run(main())
print(f"Requests: {time.time() -  start} seconds.")  