# AWS-Route53-Monitor
 
### Set up
Set the PROFILE_NAMES array.
This is the names of AWS credentials that is in your .aws/credentials file
If you only have one environment you'd like to monitor, just leave it as the "default" value

.aws/credentials
```
[default]
aws_access_key_id = imakeyid
aws_secret_access_key = imthekey

[aws_evn_1]
aws_access_key_id = imakeyid
aws_secret_access_key = imthekey

[aws_evn_2]
aws_access_key_id = imakeyid
aws_secret_access_key = imthekey

[aws_evn_3]
aws_access_key_id = imakeyid
aws_secret_access_key = imthekey
```


Set the REGIONS array
Set the regions you'd like to monitor

Set the ENABLE_DIFFERENCE_ALERT bool
True/False on weather or not to send the difference_report.html to your email

Set WORK_FOLDER
Set the directory you'd like files and reports to be saved to

Set VERBOSE
True/False for if you want a mess on your screen

Set SENDER_EMAIL
Email address from who the report will be sent

Set RECEIVER_EMAIL
Array of email address who should receive the alerts

### Overview

Script uses boto3 to cycle through Route53 entries pointing towards Ip addresses,
It then attempts to match these Ip addresses to Ec2 instances and will denote any Route53 pointers that have no cooresponding Ec2 instance into a report, called report.html

A JSON object of environment's R53 is saved as a file named {{evn}}.json and is used to compare to the next time this script is run
If you enable the ENABLE_DIFFERENCE_ALERT flag you'll get an email highlighting the changes in R53


### Testing

If you want to test the "differnce email" run the script once, then remove some of the entries dangling_pointers array in {{evn}}.json and run the script again.

### To run
`python3 main.py`