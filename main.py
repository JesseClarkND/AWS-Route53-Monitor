#python3

import sys
from requests import get
from requests.exceptions import RequestException
from contextlib import closing
import boto3
from botocore.exceptions import ClientError
import botocore.exceptions
import simplejson as json
import os.path
from os import path
import smtplib, ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import datetime

#Based off the work here:
#https://www.cloudconformity.com/knowledge-base/aws/Route53/dangling-dns-records.html

#REMEMBER TO SET YOUR SMTP CREDS IN credentials-email.txt
PROFILE_NAMES = ["default"]
REGIONS = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
RECORD_TYPES = ['A', 'AAAA', 'CNAME']
ENABLE_DIFFERENCE_ALERT = True
WORK_FOLDER = "./"
VERBOSE = True
SENDER_EMAIL = "from@example.com"  # Enter your address
RECEIVER_EMAIL = ["to@example.com"]  # Enter receiver addresses, its an array, put in many values

#Find all the route53 hosted zones that are assoicated with the current environment session
def list_hosted_zones(session):
    route53 = session.client('route53')
    response = route53.list_hosted_zones()
    return response['HostedZones']

#Find the Recourse records
def list_resource_record_sets(session, hosted_zone_id):
    route53 = session.client('route53')
    response = route53.list_resource_record_sets(HostedZoneId=hosted_zone_id)
    return response['ResourceRecordSets']

#Attempt to find IP address assoicated with an EC2 instance
def describe_address(session, eip, region):
    try:
        ec2 = session.client('ec2', region_name=region)
        response = ec2.describe_addresses(PublicIps=[eip])
        return response['Addresses']
    except botocore.exceptions.ClientError as error:
        #print(error)
        if str(error).startswith('An error occurred (InvalidAddress.NotFound) when calling the DescribeAddresses operation: Address'):
            return []


def log(message):
    global VERBOSE
    now = datetime.datetime.now()
    message = now.strftime("%d/%m/%Y %H:%M:%S") + " " + message + "\n"
    
    #Here you can set up a log file it you are pleased to do so, else we will just dump to screen
    #logpath = now.strftime("C:/logs/route53-%d-%m-%Y")+'.txt'
    #mode = 'a+' if os.path.exists(logpath) else 'w+'
    #f = open(logpath,mode)
    #f.write(message)
    #f.close()
    if VERBOSE:
        print(message)

#Big ugly function to generate HTML report
def create_report(report_name, dangling_pointers, regions, types):
    global WORK_FOLDER
    f = open(WORK_FOLDER+report_name+'.html','w')

    message = "<html>\n"
    message += "<center><h2>Route 53 Dangling DNS Pointers</h2>\n"
    message += "Regions Checked: " + str(regions) +"<br/>"
    message += "Types Checked: " + str(types) +"<br/>"
    message += "</center>"
    message += "<table width='100%'>\n"

    message += "<tr>\n"
    message += "     <th>Profile</th>\n"
    message += "     <th>Hosted Zone</th>\n"
    message += "     <th>EIP</th>\n"
    message += "     <th>Resource Name</th>\n"
    message += "     <th>Type</th>\n"
    message += "</tr>\n"

    for pointer_key in dangling_pointers:
        for pointer in dangling_pointers[pointer_key].dangling_pointers:
            message += "<tr>\n"
            message += "<td style='text-align: center'>\n"
            message += pointer.profile_name
            message += "</td>\n"
            message += "<td style='text-align: center'>\n"
            message += "<a target='_blank' href='https://console.aws.amazon.com/route53/v2/hostedzones#ListRecordSets/"+pointer.environment_hosted_zone+"'>"+pointer.environment_hosted_zone+"</a>"
            message += "</td>\n"
            message += "<td style='text-align: center'>\n"
            message += pointer.eip
            message += "</td>\n"
            message += "<td style='text-align: center'>\n"
            message += "<a target-'_blank' href='https://"+pointer.resourse_name.strip('.')+"'>"+pointer.resourse_name+"</a>"
            message += "</td>\n"
            message += "<td style='text-align: center'>\n"
            message += pointer.type
            message += "</td>\n"
            message += "</tr>\n"

    message += "</table>\n"

    message += "</html>\n"

    f.write(message)
    f.close()

#Save our environment JSON to a file so we have something to compare to in the future
def create_json(environment_results):
    global WORK_FOLDER
    for environment_name in environment_results:
        f = open(WORK_FOLDER+environment_name+'.json','w')
        f.write(environment_results[environment_name].toJSON())
        f.close()

def simple_get(url):
    """
    Attempts to get the content at `url` by making an HTTP GET request.
    If the content-type of response is some kind of HTML/XML, return the
    text content, otherwise return None.
    """
    try:
        #print(url)
        headers = {'User-Agent': 'Mozilla/5.0 (platform; rv:geckoversion) Gecko/geckotrail Firefox/firefoxversion'}

        with closing(get(url, stream=True, headers=headers, allow_redirects=True, timeout=8)) as resp:
            #print(str(resp.content))
            return (resp.status_code == 200)

    except RequestException as e:
        #log_error('Error during requests to {0} : {1}'.format(url, str(e)))
        return ""

#Find differences between two lists, so we can note changes in our env
def list_diff(li1, li2):
    li_dif = []
    for i in li1:
        boolFound = False
        for x in li2:
            if x.eip == i.eip and x.resourse_name == i.resourse_name and x.environment_hosted_zone == i.environment_hosted_zone:
                boolFound = True
        if boolFound == False:
            li_dif.append(i)
    return li_dif 


class EnvironmentResults:
    def __init__(self):
        self.profile_name = ''
        self.regions_tested = []
        self.dangling_pointers = []

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, 
            sort_keys=True, indent=4)

class DanglingPointer:
    def __init__(self):
        self.profile_name = ''
        self.environment_hosted_zone = ''
        self.eip = ''
        self.type = ''
        self.resourse_name = ''
        #self.regions_tested = []

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, 
            sort_keys=True, indent=4)


def send_email(sender_email, receiver_emails, msg):
    global WORK_FOLDER
    global SENDER_EMAIL
    email_info = []    
    with open(WORK_FOLDER+'credentials-email.txt', 'r') as f:
        email_info = json.load(f)

    context = ssl.create_default_context()
    with smtplib.SMTP(email_info['server'], email_info['port']) as server:
        server.ehlo()  # Can be omitted
        server.starttls(context=context)
        server.ehlo()  # Can be omitted
        server.login(email_info['username'], email_info['password'])
        server.sendmail(SENDER_EMAIL, receiver_emails, msg.as_string())
        server.quit()

def send_difference_email():
    global WORK_FOLDER
    global SENDER_EMAIL
    global RECEIVER_EMAIL

    msg = MIMEMultipart('alternative')
    msg['Subject'] = "Route 53 Difference!"
    msg['From'] = SENDER_EMAIL
    msg['To'] = ", ".join(RECEIVER_EMAIL)

    email_body = ''
    with open(WORK_FOLDER+'report_difference.html', 'r') as f:
        email_body = f.read()
    # Create the body of the message (a plain-text and an HTML version).
    text = "Hi!\nYou should enable HTML emails"
    html = email_body

    # Record the MIME types of both parts - text/plain and text/html.
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')

    # Attach parts into message container.
    # According to RFC 2046, the last part of a multipart message, in this case
    # the HTML message, is best and preferred.
    msg.attach(part1)
    msg.attach(part2)

    with open('report_difference.html', "rb") as fil:
        part = MIMEApplication(
            fil.read(),
            Name='report_difference.html'
            )
        # After the file is closed
        part['Content-Disposition'] = 'attachment; filename="%s"' % 'report_difference.html'
        msg.attach(part)

    send_email(SENDER_EMAIL, RECEIVER_EMAIL, msg)

def main():
    log("Starting Route53 Checker")


    log(str(len(PROFILE_NAMES))+ " profiles loaded")

    found_dangling_pointers = {}
    environment_differences = {}

    for name in PROFILE_NAMES:
        temp_result = EnvironmentResults()
        temp_result.profile_name = name
        temp_result.regions_tested = REGIONS
        found_dangling_pointers[name] = temp_result

        temp_result2 = EnvironmentResults()
        temp_result2.profile_name = name
        temp_result2.regions_tested = REGIONS
        environment_differences[name] = temp_result2

    for profile_name in PROFILE_NAMES:
        log("Testing Env: "+ profile_name)

        session = boto3.Session(profile_name=profile_name)
        environment_hosted_zones = list_hosted_zones(session)

        for environment_hosted_zone in environment_hosted_zones:
            eip_list = list_resource_record_sets(session, environment_hosted_zone['Id'].split('/')[2])

            for eip in eip_list:
                #print(eip)
                if eip['Type'] in RECORD_TYPES: #The list_resource_record_sets record isn't supported, even tho its in the boto3 documentation :(
                    if 'ResourceRecords' in eip.keys():
                        if eip['Type'] == 'CNAME': 
                            for resource_record in eip['ResourceRecords']:
                                log(resource_record['Value'])
                                log('-------------------')
                                #print(resource_record['Value'])
                                #look for it
                                boolFound = simple_get(resource_record['Value'].strip('.'))
                                if boolFound==False:
                                    log("No record found!")
                                    d_pointer = DanglingPointer()
                                    d_pointer.profile_name = profile_name
                                    d_pointer.environment_hosted_zone = environment_hosted_zone['Id'].split('/')[2]
                                    d_pointer.type = eip['Type']
                                    d_pointer.eip = resource_record['Value']
                                    d_pointer.resourse_name = eip['Name']
                                    found_dangling_pointers[profile_name].dangling_pointers.append(d_pointer)
                        else:
                            for resource_record in eip['ResourceRecords']:
                                log(resource_record['Value'])
                                log('-------------------')
                                boolFound = False
                                for region in REGIONS:
                                    addresses = describe_address(session, resource_record['Value'], region)
                                    if len(addresses) != 0:
                                        boolFound = True
                                        break
                                    log(region + " : " + str(len(addresses)))
                                if boolFound==False:
                                    log("No record found!")
                                    d_pointer = DanglingPointer()
                                    d_pointer.profile_name = profile_name
                                    d_pointer.environment_hosted_zone = environment_hosted_zone['Id'].split('/')[2]
                                    d_pointer.type = eip['Type']
                                    d_pointer.eip = resource_record['Value']
                                    d_pointer.resourse_name = eip['Name']
                                    found_dangling_pointers[profile_name].dangling_pointers.append(d_pointer)

    boolSendEmail = False
    for profile_name in PROFILE_NAMES:
        if path.exists(WORK_FOLDER+profile_name+'.json'):
    #    print('here')
            with open(WORK_FOLDER+profile_name+'.json', 'r') as f:
                environment_difference = EnvironmentResults()
                environment_difference.regions_tested = REGIONS
                environment_difference.profile_name = profile_name
                old_environment_result = json.load(f)

                if 'dangling_pointers' in old_environment_result:
                    temp_pointers_json = old_environment_result['dangling_pointers']

                    old_environment_result['dangling_pointers'] = []
                    for i in temp_pointers_json:
                        dangler = DanglingPointer()
                        dangler.profile_name = i['profile_name']
                        dangler.environment_hosted_zone = i['environment_hosted_zone']
                        dangler.eip = i['eip']
                        dangler.type = i['type']
                        dangler.resourse_name = i['resourse_name']

                        old_environment_result['dangling_pointers'].append(dangler)

                    print("Length of found: " + str(len(found_dangling_pointers[profile_name].dangling_pointers)))
                    print("Length of old: " + str(len(old_environment_result['dangling_pointers'])))

                    environment_difference.dangling_pointers = list_diff(found_dangling_pointers[profile_name].dangling_pointers, old_environment_result['dangling_pointers'])
                    if len(environment_difference.dangling_pointers) > 0:
                        boolSendEmail = True

                environment_differences[profile_name] = environment_difference

    log("Creating report")
    create_report('report', found_dangling_pointers, REGIONS, RECORD_TYPES)

    log("Creating difference report")
    create_report('report_difference', environment_differences, REGIONS, RECORD_TYPES)

    
    if boolSendEmail and ENABLE_DIFFERENCE_ALERT:
        log("Sending email")
        send_difference_email()

    log("Creating json")
    create_json(found_dangling_pointers)
    log("Ending Route53 Checker")
    

if __name__ == "__main__":
    main()