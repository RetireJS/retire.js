Development
=============

**Prerequisites**

Download and install the latest SDK from Mozilla.

See: https://addons.mozilla.org/en-US/developers/docs/sdk/latest/dev-guide/tutorials/installation.html

Before running a target, the SDK must be activated.

```sh
> cd ${SDK_DIR}
> source bin/activate
```

or with Bash

```sh
> cd ${SDK_DIR}
> bash bin/activate
```

All targets must be exectued from the same directory as this README file is in.

**Test**

Run tests using a temporary browser profile
```sh
> cfx test
```

**Run**

Run current code using a temporary browser profile
```sh
> cfx run
```
Add ` -p ~/path-to-profile-dir` to the run command if you want run using an exising profile.
The directory will be created if it does not exist.

**Build**

Export a .xpi file in the add-on folder
```sh
> cfx xpi
```

To test the reporting you can visit the demo page at http://erlend.oftedal.no/blog/retire/