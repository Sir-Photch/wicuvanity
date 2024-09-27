# wicuvanity

Generate wireguard vanity addresses with given prefix in the public key -- on your Nvidia GPU!

## Yield comparison

### [wireguard-vanity-address](https://github.com/warner/wireguard-vanity-address)

On an i9-14900KS:

```console
$ timeout 1m wireguard-vanity-address --in 20 foo > cpu.keys
$ wc -l cpu.keys
45803 cpu.keys
```

(Debug output is not subtracted here)

### wicuvanity

On a RTX 4090:

```console
$ timeout 1m wicuvanity --in 20 foo > gpu.keys
$ wc -l gpu.keys
173929 gpu.keys
```

## Build

Requires up-to-date meson and cuda toolkit, as well as [cxxopts](https://github.com/jarro2783/cxxopts).

```console
$ meson setup builddir --buildtype release
$ meson install -C builddir
```

## Details

- Implements curve25519 as described by Martin Kleppmann: https://martin.kleppmann.com/papers/curve25519.pdf
- Build is optimized for native GPU arch, thus, binary is not necessarily portable
