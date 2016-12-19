# README #

### Crypto Honeypot ###

* Quick summary

The aim behind the Cryptolocker Honeypot toolkit is to have a folder on each network share that acts as a honeypot for unauthorised file changes from network users.

The honeypot folder will contain non-business documents that can be encrypted without harm. This folder has a checksum run across the files every 500 milliseconds waiting for a checksum change.

As the honeypot folder is created the files get hashed which get stored in a config file to compare against.

Once a change has been detected the server service will be forced to stop running preventing any further spread across the files server.

### How do I get set up? ###

* Verify you have a folder called 'files' in the same location as the .exe with generic documents.
* Run the Crypto Honeypot to open the console configuration utility. You can configure the honeypots & install the service to run in the background.
* Start the service under services.msc. Note email alert still to be setup. Keep an eye on the 'Server' service

### Who do I talk to? ###

* Email: matt@yesit.com.au

### To Do ###

* Email notifications
* Fix error when stopping service

### Future Plans ###

The honeypot will aim to have a client system installed on network PC's that monitors for a detection alert from a server with a possible User/PC causing the issue. If the User/PC matches the clients then an alert will be displayed to notify that user. That PC will also have its network shares disconnected further reducing threats.