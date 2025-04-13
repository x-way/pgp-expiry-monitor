# pgp-expiry-monitor - monitor PGP keys for expiry

The `pgp-expiry-monitor` tool provides an simple way to monitor PGP public keys for expiry.

## Installation
Either install the go package
```
# go install github.com/x-way/pgp-expiry-monitor@latest
```

## Usage
Run the go binary from your local path
```
# pgp-expiry-monitor -u http://example.com/my-pgp-public-key.txt -d 90
Key AAA123BB (4567abcd0123effe9876cccc0000babddefc4331) is not valid on 13.05.2025
```

## Parameters
```
Usage of pgp-expiry-monitor:
  -d int
    	Number of days into the future to check for expiry (default 30)
  -u string
    	URL where the public key file is located
```
