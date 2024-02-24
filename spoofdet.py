import re
import sys
from termcolor import cprint, colored

#infomail.microsoft.com


def emailSpoofDetection(header, emailDomain):
    # Assign header and emailDomain to a variable 
    header = str(header);
    emailDomain = str(emailDomain);

    # Convert Gmail header object format to raw string 
    header = re.sub(r'\{\"name\"\:\"', '', header)
    header = re.sub(r'\"\,\"value\"\:\"', ': ', header)
    header = re.sub(r'\"\}\,', ', ', header)
    header = re.sub(r'^\[', '', header)
    header = re.sub(r'\"\}\]$', '', header)
    header = re.sub(r'\s+', ' ', header)

    # Remove new line characters, if any 
    header = re.sub(r'\n', ' ', header)
    header = re.sub(r'\t', ' ', header)

    match = []
    outcome = {}

    # Parse dkmin records in the header 
    dkimRegex = r'dkim\=(\S+)\sheader\.i\=\@(\S+)\s'
    dkim = {"result": [], "domain": []}
    match = re.findall(dkimRegex, header)
    for (r, d) in match:
        if r not in dkim["result"]:
            dkim["result"].append(r)
        if d not in dkim["domain"]:
            dkim["domain"].append(d)

    # Parse spf records in the header 
    spfRegex = r'spf\=(\S+).*?smtp\.mailfrom\=.*?\@(.*?)\;\s'
    spf = {"result": [], "domain": []}
    match = re.findall(spfRegex, header)
    for (r, d) in match:
        if r not in spf["result"]:
            spf["result"].append(r)
        if d not in spf["domain"]:
            spf["domain"].append(d)

    # Parse dmarc records in the header 
    dmarcRegex = r'dmarc\=(\S+)\s\(p\=\S+\s+sp\=\S+\s+dis\=\S+\)\s+header\.from\=(\S+)'
    dmarc = {"result": [], "domain": []}
    match = re.findall(dmarcRegex, header)
    for (r, d) in match:
        if r not in dmarc["result"]:
            dmarc["result"].append(r)
        if d not in dmarc["domain"]:
            dmarc["domain"].append(d)

    # Validate the result and domain name 
    if ("pass" in dkim["result"] and "pass" in spf["result"] and "pass" in dmarc["result"] and emailDomain in dkim["domain"]):
        outcome = {'validEmail': True}
    else:
        outcome = {'validEmail': False}
    return outcome

logo=colored(''' 

                        Welcome to Email Spoof Buster!

  ______                     ___ ______                               
 / _____)                   / __|____  \              _               
( (____  ____   ___   ___ _| |__ ____)  )_   _  ___ _| |_ _____  ____ 
 \____ \|  _ \ / _ \ / _ (_   __)  __  (| | | |/___|_   _) ___ |/ ___)
 _____) ) |_| | |_| | |_| || |  | |__)  ) |_| |___ | | |_| ____| |    
(______/|  __/ \___/ \___/ |_|  |______/|____/(___/   \__)_____)_|    
        |_|                      Made by hei$enberg                    

    


    ''', 'blue')

if (sys.argv[1]=='-h') or (sys.argv[1]=='--help') or (sys.argv[1]=='help'):
    print(logo)
    print('''

        Installation & Usage

            $ python3 spoofdet.py /path/to/txt file



        ''')
    sys.exit()

print(logo)

    
try:
    file_path=sys.argv[1]

    emailDomain = input(colored('enter the email domain: ', 'yellow'))
    with open(file_path, 'r') as header:
        analysis = emailSpoofDetection(header, emailDomain)
        if analysis:
            print(' ')
            cprint('everythings fine!', 'yellow')
        else:
            print(' ')
            cprint('email spoofing detected!', 'red')

except FileNotFoundError:
    print(' ')
    cprint("file not found...", 'red')
except IndexError:
    print(' ')
    cprint('wrong parameters...', 'red')
except KeyboardInterrupt:
    print(' ')
    cprint('exiting...', 'red')
