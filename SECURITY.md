# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub's
[private vulnerability reporting](https://github.com/3ft9/blugw/security/advisories/new)
rather than in a public issue. Include what you found, how to reproduce it and
the version or commit affected.

You should get a response within a week. Fixes are released as soon as they
are ready, and reporters are credited in the advisory unless they prefer not
to be.

## Supported versions

Only the latest release and the `main` branch receive security fixes.

## Scope

Of particular interest:

- Anything that lets a nearby Bluetooth device inject, replay or forge
  readings for an encrypted BTHome device.
- Leaks of AES keys or MQTT credentials, for example in logs or error messages.
- Crashes or unbounded resource use caused by malformed advertisements.
