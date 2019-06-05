# Trex PAM module of last resort

### A PAM module that enables PAM to authenticate a user using a USB key.

## Configuration:
### PAM:
Create/edit a config file for PAM (usually under /etc/pam.d/)  
Say /etc/pam.d/sshd  
Add to it something like:  
auth	required	/path/to/last-resort.so  
### Module:
For every user that wants to enable the module, place 2 files under ~/  
.lastresort_conf
containing 2 parameters:  

fingerprint-of-trusted-public-key path-to-mountpoint  
The corresponding key must be trusted by your gpg trust db.  
(gpg --edit-key pub@key.com, set trust to ultimate)  
The mountpoint is where your automounter puts its sub directories  
(usbmount uses /media/usb0-7 by default)  

.lastresort_rollingstate
containing 2 parameters:  

machine-id current-secret  
machine-id can be any string with no whitespace, see security considerations.  
current-secret can be any string with no whitespace,  
it will be replaced by the module on any successful login via the module.  
See security considerations.  

## Usage:
Follow the instructions printed on the screen.  
You need to plug in a USB drive with a file named "lastresort.sig"  
Containing a signature by the configured key of the current ~/.lastresort_rollingstate  
A reminder of rollingstate will be printed, and if auth was granted,  
lastresort.sig will be overwritten with the next rollingstate to be signed for the next login.  

## Security considerations:
Very similar to the trex-pam.so module by the same authors.  
With the exceptions that:  
1: the random challenge only rotates upon success.  
So brute force attacks are more of an issue,  
hopefully offset by the requirement of physical presence.  
(Still, requires signing a guessed 10 char long,  
a-zA-Z0-9 nonce, given good randomness this puts us at one in over a billion.)  
2: physical access to plug in a USB drive is required.  

(at the very least, attacker must be able to mount volumes  
or overwrite files under $HOME or sign with the corresponding secret key.  
In all these cases, attacker has won before the module was even written)  
See the analysis in the documentation of trex-pam.so for further details.  
