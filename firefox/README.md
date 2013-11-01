Build and Run
=============

** Prerequisites **

See: https://addons.mozilla.org/en-US/developers/docs/sdk/latest/dev-guide/tutorials/installation.html

Before running the targets, activate the SDK
```sh
> cd ${SDK}
> source bin/activate
```

**Run**

This will run the add-on using a temporary browser profile.
```sh
> cd ${project}/firefox
> cfx run
```
Add -p ~/path-to-profile-dir to the run command if you want run using an exising profile.
The directory will be created if it does not exist.

**Build**

This will create a .xpi file in the add-on folder.
```sh
> cd ${project}/firefox
> cfx xpi
```