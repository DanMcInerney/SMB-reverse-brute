SMB-reverse-brute
------
Performs a 2 password reverse bruteforce against any hosts with NULL SMB sessions that allow RID cycling for usernames. Takes a hostlist file or an Nmap XML output file as input.

* Takes input in form of Nmap XML or hostlist file
* Finds any open 445 ports
* Attempts a NULL SMB session (connecting over SMB without a password)
* On success will perform RID cycling to gather domain usernames
* Prevents account lockout by creating list of unique usernames and bruteforcing each one with two passwords:
** P@ssw0rd
** <Season><year> such as Summer2017


#### Installation
```
git clone https://github.com/DanMcInerney/SMB-reverse-brute
cd SMB-reverse-brute
git submodule init
git submodule update
pip install pipenv
pipenv --three install
pipenv shell
python SMB-reverse-brute.py -x/-l ...

```

#### Usage
Read from Nmap XML file

```python SMB-reverse-brute.py -x nmapfile.xml```


Read from a hostlist of newline separated IPs or CIDR addresses. Also use your own password list.

```python SMB-reverse-brute.py -l hostlist.txt -p passwords.txt```

