# fresh
Fresh: Harden a fresh Debian 11/12 server in one shot: create a key-only admin account, lock down SSH, Ansible, enable UFW + Fail2Ban unattended upgrades—with a single Bash script.
is a single-file Bash script that transforms a brand-new Debian 11/12 box into a reasonably hardened, key-only environment:

### What it does	Highlights
✅ Creates an admin account and adds it to sudo	🔐 Locks the password by default (or generates one on request)
✅ Installs OpenSSH, UFW, Fail2Ban, Vim, tmux, Ansible	🚫 Disables root SSH login & password auth
✅ Enables unattended security upgrades	🛡️ Applies a minimal sysctl baseline
✅ Dry-run (-n) & verbose (-v) modes	📈 Health-check verifies SSH is listening

## Important**
Before running the script, upload your public SSH key to the server (or place it on attached media).
Without a key the new admin user cannot log in.
**Heads-up**  
The script needs your **public SSH key** _already on the server_ (or on attached media) before you run it.  
typical workflow is:
```bash
scp ~/.ssh/id_ed25519.pub root@your-server:/root/admin.pub
ssh root@your-server
sudo ./secure_debian_server.sh -u janis -k /root/admin.pub -p 2222
 ```
---

## Requirements

* Debian 11 (bullseye) or Debian 12 (bookworm)
* Root access (`sudo su -` or direct root login for the very first run)
* An outbound network connection to Debian package mirrors

---

## Quick start

1. **Download the script**

```bash
wget -O secure_debian_server.sh \
https://raw.githubusercontent.com/<you>/secure-debian-server/main/secure_debian_server.sh
chmod +x secure_debian_server.sh
```
2. **Copy your public key to the server**
```bash
scp ~/.ssh/id_ed25519.pub root@server:/root/admin.pub
```
4. **Run It**
```bash
sudo ./debian_server.sh \
     -u admin \
     -k /root/admin.pub \
     -p 2222        # optional SSH port
```
 ### Usage
 ```bash
sudo ./debian_server.sh -u <user> -k </path/to/key.pub> [OPTIONS]
Options:
  -u USER   admin account to create / manage   (required)
  -k FILE   path to public SSH key             (required)
  -p PORT   SSH port (default 22)
  -s        lock the account password (default)
  -P        generate & store a random sudo password
  -n        dry-run – print actions, don’t execute
  -v        verbose – echo every command (set -x)
  -h        help
```
### What the script changes

1. **Updates & upgrades** the system.
2. **Installs** core packages (`openssh-server`, `ufw`, `fail2ban`, `unattended-upgrades`, ...).
3. **Creates** the admin user, adds to `sudo`, and locks or sets a strong password.
4. **Appends** your public key to `~/.ssh/authorized_keys`.
5. **Hardens SSH** via `/etc/ssh/sshd_config.d/00-secure.conf`.
6. **Configures UFW** (deny incoming, allow outgoing, limit SSH on chosen port).
7. **Enables Fail2Ban** & unattended security upgrades.
8. **Applies sysctl** tweaks (SYN cookies, martian logging, no IP forwarding).
9. **Runs a health check** to confirm SSH is listening and AppArmor is on.

---

### Dry run & logging

- Add `-n` to see every command without changing the system.
- All output (colour-stripped) is logged to `/var/log/fresh_debian_server.log`.

---

### License

MIT License – see `LICENSE` file.

