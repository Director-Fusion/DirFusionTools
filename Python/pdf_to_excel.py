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
    os.chdir(r'PATH INFO HERE')
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
    logging.info("Inside GetPDF")
    attachment = str(attachment)
    pdfFileObj = open(attachment, 'rb')
    pdfReader = PyPDF2.PdfFileReader(pdfFileObj)
    
    for i in range(0, pdfReader.numPages):
        pgObj = pdfReader.getPage(i)
        pageData = pgObj.extractText()
        re_extraction(pageData)
    
    pdfFileObj.close()
       
def re_extraction(pageData):
    logging.info('Inside RE-extract')
    contract_dict = r'Contractor: (.+?)\s*$'
    matches = re.finditer(contract_dict, pageData, re.MULTILINE)
    
    for matchNum, match in enumerate(matches, start=1):
    
        print ("Match {matchNum} was found at {start}-{end}: {match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
    
        for groupNum in range(0, len(match.groups())):
            groupNum = groupNum + 1
        
            print ("Group {groupNum} found at {start}-{end}: {group}".format(groupNum = groupNum, start = match.start(groupNum), end = match.end(groupNum), group = match.group(groupNum)))
    
        exportExcel(match)

def exportExcel(match):
    logging.info("Exporting to Excel")
    wb = openpyxl.Workbook() # New Blank WorkBook
    wb.sheetnames # First sheet
    boe_sheet = wb.active
    boe_sheet.title = 'The Board of Education'
    boe_sheet['A1'] = match
    boe_sheet['B2'] = match
    boe_sheet['A2'] = str('Fuck you')
    wb.save('boetest.xlsx') # Save the Workbook
    wb.close()
    
get_emails()
