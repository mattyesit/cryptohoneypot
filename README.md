# README #

This README would normally document whatever steps are necessary to get your application up and running.

### What is this repository for? ###

* Quick summary

The aim behind the Cryptolocker Honeypot toolkit is to have a folder on each network share that acts as a honeypot for unauthorised file changes from network users.

The honeypot folder will contain non-business documents that can be encrypted without harm. This folder has a checksum run across the files as well as timestamps for further accuracy.

Based on defined configuration rules, if the rules are triggered on that folder then the server service will be stopped to prevent users accessing the network shares.

The service will also report a 'Disconnect' alert that computers in the network wait for in order to disconnect any network share attached to that PC as a second level of prevention. This will be a separate project.

* Version
* [Learn Markdown](https://bitbucket.org/tutorials/markdowndemo)

### How do I get set up? ###

* Summary of set up
* Configuration
* Dependencies
* Database configuration
* How to run tests
* Deployment instructions

### Contribution guidelines ###

* Writing tests
* Code review
* Other guidelines

### Who do I talk to? ###

* Repo owner or admin
* Other community or team contact