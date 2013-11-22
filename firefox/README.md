Development
=============

## Prerequisites

Download and install the latest SDK from Mozilla.

See the  [documentation](https://addons.mozilla.org/en-US/developers/docs/sdk/latest/dev-guide/tutorials/installation.html) for more information.


## fx.sh

Before running a target add ${ADD-ON-SDK}/bin to the $PATH

All targets must be executed from the same directory as this README file is in.

**test**

Run tests using a temporary browser profile
```sh
> ./fx.sh test
```

**run**

Run current code using a temporary browser profile
```sh
> ./fx.sh run
```
Add ` -p ~/path-to-profile-dir` to the run target if you want run using an exising profile.
The directory will be created if it does not exist.

**build**

This will build the add-on and export it to a .xpi file
```sh
> ./fx.sh build
```

To test the reporting you can visit the demo page at http://erlend.oftedal.no/blog/retire/