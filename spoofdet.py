from emailSpoofDetection import emailSpoofDetection
import sys
from termcolor import cprint, colored

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

            $ pip install emailSpoofDetection

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