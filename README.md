# bash.zsh.stuff
Quick configs for getting bash / zsh up and running with some quality of life stuff

```bash
sudo dnf update -y && dnf upgrade -y
```
```bash
sudo dnf install vim
```
```bash
echo -e "alias ls='ls -1al'\nalias ifconfig='ip a'">> ~/.bash_profile && source ~/.bash_profile
```
```bash
sudo visudo -f /etc/sudoers.d/myusername
```
then add:
Defaults:myusername timstamp_timeout=720
which sets the timeout for 12 hours
