#!/usr/bin/python3

import requests
import json
import csv
import argparse
from googleapiclient.discovery import build
import pprint
import math

headers = {
    "Accept": "application/json"
}

pp = pprint.PrettyPrinter(indent=2)

def google_search(query, gapi_key, g_cse_id, filename, verbose, **kwargs):
    with open(query, 'r') as f:
        for qu  in f:
            service = build("customsearch", "v1", developerKey=gapi_key)
            resp = service.cse().list(q=qu, cx=g_cse_id, **kwargs).execute()
            total_results = resp['searchInformation']['totalResults']
            total_results = int(total_results)

            if total_results > 10:
                calls_to_make = math.ceil(total_results / 10)
            else:
                calls_to_make = 1

            startitem = 1
            og_calls = calls_to_make
            returnedData = []
            url = f"https://customsearch.googleapis.com/customsearch/v1?cx={g_cse_id}&q={qu}&start={startitem}&safe=off&key={gapi_key}"
            
            while calls_to_make > 0:
                #resp = service.cse().list(q=query, cx=g_cse_id, **kwargs).execute()
                resp = requests.get(url, headers=headers)
                data = resp.json()
                #pp.pprint(data)
                returnedData.append(data)
                calls_to_make = calls_to_make - 1
                startitem += 10
                leftover = total_results - startitem - 1
                if verbose:
                    beautifyOutput(data)
                if 0 < leftover < 10:
                    kwargs['num'] = leftover
            writeToCsv(returnedData, filename, og_calls, qu)
            
def beautifyOutput(data):
    for x in range(0, len(data)):
        pp.pprint(data['items'][x]['title'])
        pp.pprint(data['items'][x]['displayLink'])
        pp.pprint(data['items'][x]['formattedUrl'])
        pp.pprint(data['items'][x]['htmlSnippet'])
        
def writeToCsv(returnedData, filename, og_calls, qu):
    f = returnedData
    headers = ['Title', 'Display Link', 'Formatted URL', 'HTML Snippet', 'Query']
    data_file = open(f'{filename}.csv', 'w')
    writer = csv.writer(data_file)
    writer.writerow(headers)
    for x in range(0, og_calls):
        try:
            title = f[0]['items'][x]['title']
            display_link = f[0]['items'][x]['displayLink']
            formatted_url = f[0]['items'][x]['formattedUrl']
            html_snippet =f[0]['items'][x]['htmlSnippet']
            writer.writerow([title, display_link, formatted_url, html_snippet, qu])
        except:
            pp.pprint("We ran out of data to parse and write.") 
    data_file.close()
    
def main():
    gapi_key = ""
    g_cse_id = ""
    
    parser = argparse.ArgumentParser(
        prog='Dork API Search',
        description='Use free level API searches to perform google and bing dorking'
        )
    parser.add_argument(
        '-e',
        '--engine',
        metavar='ENGINE',
        required=False,
        help='Choose a search engine: BING, GOOGLE or BOTH'
    )
    # parser.add_argument(
    #     '-q',
    #     '--query',
    #     metavar='QUERY',
    #     required=True,
    #     help='Add a DORK here' 
    # )   
    parser.add_argument(
        '-w',
        '--write',
        metavar='WRITE',
        required=True,
        help='File Name for writing results to. Example: query-filename' 
    )
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        required=False,
        help='Enable STDOUT for logging and responses.' 
    )
    parser.add_argument(
        '-f',
        '--file',
        required=True,
        help='File containing queires by new line.' 
    )
    args = parser.parse_args()
    
    query = args.file
    filename = args.write
    verbose = args.verbose
    google_search(query, gapi_key, g_cse_id, filename, verbose)

if __name__ == '__main__':            
    main()
