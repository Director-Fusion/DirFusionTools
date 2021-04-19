#!/usr/bin/python3

## Developed by DirectorFusion 16 April 2021

from selenium import webdriver
from selenium.webdriver.common.keys import Keys

# Variables

PATH = "C:\Program Files\msedgedriver.exe"

driver = webdriver.Edge(PATH)

driver.get("https://www.gamestop.com/toys-collectibles/funko/pop/products/pop-games-diablo-tyrael-only-at-gamestop/11098607.html")

buy = driver.find_element_by_class_name("add-to-cart btn btn-primary ")

buy.click()


#time.sleep(2)

#driver.quit()
 