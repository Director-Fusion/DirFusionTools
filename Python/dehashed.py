import requests
import argparse

email = ""
apikey = ""

headers = {
	"Accept": "application/json",
}

def csv_write(data, domain):
	# Keys from JSON to write to top of CSV row.
	headers = ['Id', 'Email', 'IP Address', 'Username', 'Password', 'Hashed Passwords', 'Name', 'VIN', 'Address', 'Phone', 'Database Name']
	# Specify entries in the data to step into the credentials portion.
	entries = data['entries']
	# Open file to be written.
	data_file = open(f'{domain}_creds.csv', 'w')
	# Variable for writing to the new document.
	writer = csv.writer(data_file)
	# Write headers to top row.
	writer.writerow(headers)
	# Iterate through JSON files and write rows.
	for x in entries:
		info = x.values()
		writer.writerow(info)
	# Not able to use context manager/IDFK how to use it with the real time data. So just did traditional file.close().
	data_file.close()

def main():
	# Create argument parser 
	parser = argparse.ArgumentParser('Get credentials by domain with dehashed.')
	parser.add_argument('--domain',
		type=str,
		metavar='DOMAIN',
		required=True,
		help='Enter a domain name "example.com"'
		)
	# Variable for parsing arguments
	args = parser.parse_args()
	domain = args.domain
	# URL - the F string for domain can be changed out later to do specific low flying recon with searching by specific emails. This should be done in GUI though as not to burn API queiries.
	url = f"https://api.dehashed.com/search?query=domain:{domain}"
	resp = requests.get(url, auth=(email, apikey), headers=headers)
	# Want to tell python we are parsing JSON.
	data = resp.json()
	csv_write(data, domain)

main()
