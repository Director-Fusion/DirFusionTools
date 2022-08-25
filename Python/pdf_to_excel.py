#!/usr/bin/python


import PyPDF2
import time
import re
import openpyxl
import ezgmail, os, sys
import logging

logging.basicConfig(level=logging.DEBUG, filename="pdf-to-excel.log", filemode="w", format="%(asctime)s - %(levelname)s - %(message)s")

def get_emails():
    
    logging.info("Searching Attachments")
    os.chdir(r'/Users/corykeller/Documents/AutoMate-The-Boring-Stuff')
    ezgmail.init()
    results = ezgmail.search('meetingminutes.pdf')
    attachment = results[0].messages[0].attachments
    attachment = str(attachment).replace('[', '').replace(']', '').strip("'")
    results[0].messages[0].downloadAllAttachments(downloadFolder='/tmp')
    ezgmail.markAsRead(results)
    time.sleep(2)
    distribute(attachment)

def distribute(attachment):
    
    logging.info("Inside Distribute")
    os.chdir('/tmp')
    getPDF(attachment)      
        
def getPDF(attachment):    
   
    pdfFileObj = attachment
    pdfReader = PyPDF2.PdfFileReader(pdfFileObj)
        
    for i in range(0, pdfReader.numPages):
        pgObj = pdfReader.getPage(i)
        pageData = pgObj.extractText()
        re_extraction(pageData)   
         
def re_extraction(pageData):
    
    logging.info('Inside RE-extract')
    contract_dict = r'Contractor: (.+?)\s*$'
    matches = re.finditer(contract_dict, pageData, re.MULTILINE)
    
    for matchNum, match in enumerate(matches, start=1):   
        for groupNum in range(0, len(match.groups())):
            groupNum = groupNum + 1
            groups = match.groups(groupNum)
            print(groups)
            exportExcel(groups)

def exportExcel(groups):
    
    logging.info("Exporting to Excel")
    wb = openpyxl.Workbook() # New Blank WorkBook
    wb.sheetnames # First sheet
    boe_sheet = wb.active
    boe_sheet.title = 'The Board of Education'
    
    for group in groups:
        boe_sheet.append(group)
        
    wb.save('boetest.xlsx')
    wb.close() 
    
get_emails()