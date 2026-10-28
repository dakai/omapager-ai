# Helper isolation

Bubblewrap is required for the hardened helper path. On Arch the package is
`bubblewrap`; remote raster decoding additionally requires `python-pillow`.
No automatic installation or live plugin replacement is performed by this branch.

All profiles: fresh namespaces, dropped capabilities, read-only /usr and project
source, private /tmp and HOME, minimal environment, private process view, no host
SSH/GPG/Documents/other projects/browser profiles. CPU/address-space/file-size and
45-second wall-time limits bound helper failure. The project source is mounted at
/opt/omapager, not its surrounding Projects folder. Linux user namespace policy
must permit Bubblewrap; missing/blocked Bubblewrap causes helper failure.

| Helper | Writable | Extra read-only | Network |
| --- | --- | --- | --- |
| store | Omapager state only | Runtime and own code | Isolated |
| icon | State/icons only | System/user icon and application dirs, configured icon overrides | Isolated unless --fetch |
| KDE | None | Only user bus socket, runtime and own code | Network namespace isolated; session D-Bus socket exposed |
| secret | None | Only user bus socket | Isolated |
| model | None | Only user bus socket, resolver and CA bundles | Shared, for the configured endpoint |

The KDE socket exposes the session bus; it is **not** destination-filtered.
The compatibility demo fixture is not exposed by the production launcher.

`secret` is the API key's only path: the keyring lives on the session bus, so
the profile gets that socket and nothing else — no network, no state directory,
no home. It is the narrowest profile here on purpose.

`model` is the one helper that is both networked and bus-connected, because it
must reach the provider and the keyring. It cannot read the notification store,
and the endpoint it contacts comes from the widget's settings, never from
notification text. Remote endpoints are https on 443 through the pinned
transport; a plain `http` endpoint is accepted only when the host is a literal
loopback address (`127.0.0.1` or `::1`), which is how a local model server
works and where the traffic cannot leave the machine. No hostname is resolved
to decide this.

The KDE profile requires an explicit `DBUS_SESSION_BUS_ADDRESS` using a single
`unix:path=` socket (percent-escaped paths and an optional 32-hex `guid` are
accepted). It preserves that address and the selected `XDG_RUNTIME_DIR` rather
than assuming `/run/user/<uid>/bus`. Missing, abstract, TCP and multi-address
forms fail closed; no host-bus fallback is attempted. The selected path must
be an existing absolute Unix socket.

Run `bin/omapager-run-helper status` for an actual lightweight namespace check.
`omapager probe` reports that check, required policy and absence of fallback.
Run `python3 tests/sandbox.py` on an ordinary Linux host to prove synthetic HOME
secrets cannot be read, network connections fail and scoped writes succeed.
Nested agent/container sandboxes may block namespace creation; that is a test
environment limitation, not permission to fall back unsandboxed. The test uses
a temporary home and never reads real notification history or private keys.

A sandbox failure leaves the live UI able to show notifications, but helper-backed
storage/icons/replies are unavailable. The error appears in helper stderr and
probe status; no secret payload is logged. A graphical health indicator is a
possible follow-up, not implemented here.
