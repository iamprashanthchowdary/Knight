# Knight agent

Knight tails your nginx access logs and serves traffic analytics + failure
reports over a local JSON API (default `127.0.0.1:8090`), for the Knight
dashboard. It observes only — it never blocks or modifies traffic.

## Install

    sudo apt install ./knight_<version>_amd64.deb

This installs a `knight` systemd service running as the unprivileged `knight`
user (in the `adm` group so it can read `/var/log/nginx`).

## Configure

Edit `/etc/knight/config.json` (or use the dashboard's Configuration page),
then:

    sudo systemctl restart knight

Point a site at your nginx access log — a single file, a directory, or a glob:

    "sites": [ { "name": "mysite", "access_log": "/var/log/nginx/access.log" } ]

## Operate

    systemctl status knight        # is it running?
    journalctl -u knight -f        # live logs
    curl -s 127.0.0.1:8090/v1/overview   # sanity check the API

## Uninstall

    sudo apt remove knight         # keep /etc/knight/config.json
    sudo apt purge knight          # also remove config + the knight user
