# DnsCacher

A minimal and lightweight local DNS/mDNS caching server

Intended for use with musl linux systems, to provide local caching, faster resolution and extended DNS capabilities

Planned to support DNSSEC, DNS-OVER-TLS and other advanced DNS functions (once the code has been cleaned up)

This project was original created as a more elegant solution to the lack of mDNS support on musl.

## Usage

Provides the `dns_cacher` executable that will started a server on port 53 (or 1053 if not root).

Use `dns_cacher --help` to see currently available options. May be run as either a command or daemon.

Currently works well as a daemon, which will resolve and cache DNS & mDNS queries

Utilises `openresolv`/`resolvconf` if available to change DNS configuration at startup/shutdown.

Can be sent a `SIGHUP` to reload downstream servers on network change.

There are scripts that automate this in [misc](misc).

More in-depth command line options and runtime configuration is still very much a WIP.

## License

The gem is available as open source under the terms of the [GPL-3.0 License](https://opensource.org/licenses/gpl-3-0).
