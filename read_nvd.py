import json
from os import listdir
from os.path import isfile, join
import gzip
import json

files = [f for f in listdir("../nvd/") if isfile(join("../nvd/", f))]
files.sort(reverse=True)
print(files)

for file in files[0:1]:
    with gzip.GzipFile("../nvd/"+file, 'r') as fin:
        cve_dict = json.loads(fin.read().decode('utf-8'))
        print(cve_dict.keys())

        #print("CVE_data_timestamp: " + str(cve_dict['CVE_data_timestamp']))
        #print("CVE_data_version: " + str(cve_dict['CVE_data_version']))
        #print("CVE_data_format: " + str(cve_dict['CVE_data_format']))
        #print("CVE_data_numberOfCVEs: " + str(cve_dict['CVE_data_numberOfCVEs']))
        #print("CVE_data_type: " + str(cve_dict['CVE_data_type']))

        print(json.dumps(cve_dict['CVE_Items'][0], sort_keys=True, indent=4, separators=(',', ': ')))
        
        print(cve_dict['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['vectorString'])
        print(cve_dict['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore'])
        print(cve_dict['CVE_Items'][0]['impact']['baseMetricV3']['exploitabilityScore'])
        print(cve_dict['CVE_Items'][0]['impact']['baseMetricV3']['impactScore'])

        for rec in cve_dict['CVE_Items']:
            #print(rec['impact'])
            if rec['impact']:
                print(rec['impact']['baseMetricV3']['cvssV3']['vectorString'],rec['impact']['baseMetricV3']['cvssV3']['baseScore'],rec['impact']['baseMetricV3']['exploitabilityScore'],rec['impact']['baseMetricV3']['impactScore'])

