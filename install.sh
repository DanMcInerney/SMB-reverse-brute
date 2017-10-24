echo '[*] Initialing and updating submodules'
git submodule init
git submodule update
echo '[*] Install pip then pipenv'
apt-get install python-pip
pip install pipenv
echo '[*] Creating virtual environment'
pipenv --three
echo '[*] Installing requirements'
pipenv install
echo '[*] Done. Run `pipenv shell` then `python3 SMB-reverse-brute.py -x/-l <nmapoutput.xml/targetlist.txt>`'
