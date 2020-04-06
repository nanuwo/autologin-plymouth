# autologin

It logs you in. Automatically.

## How to build

```
meson build
ninja -C build
```

## How to use

1. Create `/etc/pam.d/autologin`. You can use `/etc/pam.d/login` as source.
2. Install binary to /usr/local/bin/, systemd unit to /etc/systemd/system/
3. Change username and start command in systemd unit
3. Enable and start.

(Note, systemd is not required)