#!/usr/bin/python3

import time
from datetime import timedelta, datetime
from playwright.sync_api import sync_playwright
#from bs4 import BeautifulSoup as bs
from rich import print

zipcode = ""
emailaddress = ""
password = ""

def checkIn():
    with sync_playwright() as p:
        print("[bold cyan]***Creating new incognito session[/bold cyan]")
        browser = p.chromium.launch(headless=False, slow_mo=100)
        context = browser.new_context(user_agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36')
        print("[bold cyan]***Opening a new page[/bold cyan]")
        page = context.new_page()
        print("[bold cyan]***Going to sportclips[/bold cyan]")
        page.goto('https://sportclips.com/')
        print("[bold cyan]***Opened SportClips.com[/bold cyan]")
        print("[bold cyan]***Creating a new check in online[/bold cyan]")
        #page.is_visible('div#ctl01_ppHeader_lnkOnlineCheckin')
        page.click('#ctl01_ppHeader_lnkOnlineCheckin')
        page.is_visible('div#map')
        page.click('#locationInput')
        print("[bold cyan]***Entering Location[/bold cyan]")
        page.fill('input#locationInput', zipcode)
        page.keyboard.press('Enter')
        print("[bold cyan]***Selecting Location[/bold cyan]")
        page.click("#ui-id-2")
        page.is_visible('div#map')
        print("[bold cyan]***Selecting the Ellison Road Location[/bold cyan]")
        page.get_by_text("INSERT PREFERRED LOCATION HERE").click()
        page.click("#employeeSelector")
        
        # Selecting a Stylist
        dani = page.locator('"PREFERRED STYLIST 1"')
        jay = page.locator('"PREFERRED STYLIST 2"')

        print("[bold cyan]***Selecting a stylist...[/bold cyan]")
        try:
            print("[bold cyan]***Selecting Dani...[/bold cyan]")
            dani.click()
        except:
            print("[bold orange]***Selecting Jay...[/bold orange]")
            jay.click()
        
        # Fill out creds and submite check in
        print("[bold cyan]***Filling out login details[/bold cyan]")
        page.fill('#emailRegister', emailaddress)
        page.fill('#passwordRegister', password)
        page.locator('"Check In Now"').click()
        print("[bold green]***CHECKING IN[/bold green]")

def main():
    currentTime = datetime.now().strftime("%H:%M")
    future = datetime.now().replace(hour=9, minute=5).strftime("%H:%M") #"09:05:00"
    while True:
        if currentTime == "09:05:00":
            checkIn()
            break
        else:
            print("[bold red]Sleeping until 09:05[/bold red]")
            t1 = datetime.strptime(currentTime, "%H:%M")
            t2 = datetime.strptime(future, "%H:%M")
            duration = t2 - t1
            print("[bold red]Sleep duration is: [/bold red]", duration)
            time.sleep(duration.total_seconds())
            currentTime = "09:05:00"
    # checkIn()
main()
