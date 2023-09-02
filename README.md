This project is intended to support USB HID smart screens.
Only one such device is currently supported, but its actual
vendor or brand is currently unknown.

The main program of this project is `hidss-ctl` which can
be used to control any detected devices. It is intended to
be run as a `setuid` program so unprivileged users can use
their supported devices. Superuser privileges are dropped
once they are no longer required.

`hidss-ctl` supports the following features:
 - Device enumeration
 - Device selection
 - Widget, sensor, or datetime updates
 - Upload of theme or firmware updates
 - Report model

Currently the only thing known to be missing is a theme
generator or editor.

Supported Platforms:
 - Linux
 - Windows

Useful Links:
 - [Product Listing](https://aliexpress.com/item/1005005632018367.html)
 - [Proprietary Software](https://smartdisplay.lanzouo.com/b04jvavkb)
