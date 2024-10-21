# MPEG-TS Crypto GStreamer Plugin

This `mpegtscrypto` GStreamer plugin supports MPEG-TS stream encryption and decryption using various algorithms, such as **CSA/CSA3** (via `libcsa`) and **AES/DES/TDES** (via `OpenSSL`). The plugin provides two elements, `mpegtsencrypt` and `mpegtsdecrypt`, which handle encryption and decryption of MPEG-TS streams.

## Features

- Supports multiple encryption algorithms: AES, DES, TDES, CSA/CSA3.
- Uses OpenSSL for AES/DES/TDES and `libcsa` for CSA.
- Handles both TS-188 and TS-192 formats.
- Configurable encryption key, algorithm, and initialization vector (IV) via GStreamer properties.

## Prerequisites

### Required Packages

Make sure you have the following dependencies installed:

- **GStreamer 1.0** (Core and Base Plugins)
- **OpenSSL** (for AES/DES/TDES encryption/decryption)
- **libcsa** (for CSA/CSA3 encryption/decryption)

#### On Debian/Ubuntu

```
sudo apt update
sudo apt install gstreamer1.0 gstreamer1.0-plugins-base gstreamer1.0-tools \
                 libssl-dev libcsa-dev meson ninja-build cmake pkg-config
```

#### On Fedora

```
sudo dnf install gstreamer1 gstreamer1-plugins-base openssl-devel \
                 libcsa-devel meson ninja-build cmake pkg-config
```

If **libcsa** is not available in your distribution’s package manager, download and compile it from source.

## Building the Plugin

### Meson and Ninja Build Instructions

1. **Configure the project:**
   ```
   meson build
   ```

2. **Build the project:**
   ```
   ninja -C build
   ```

3. **Install the plugin system-wide:**
   ```
   sudo ninja -C build install
   ```
   Alternatively, install it locally:
   ```
   meson build --prefix=$HOME/.local
   ninja -C build install
   ```

4. **Set the `GST_PLUGIN_PATH` environment variable** (if installing locally):
   ```
   export GST_PLUGIN_PATH=$HOME/.local/lib/gstreamer-1.0:$GST_PLUGIN_PATH
   ```

### CMake Build Instructions

1. **Configure the project:**
   ```
   mkdir build
   cd build
   cmake ..
   ```

2. **Build the project:**
   ```
   make
   ```

3. **Install the plugin:**
   ```
   sudo make install
   ```
   For local installation:
   ```
   make install DESTDIR=$HOME/.local
   ```

4. **Set the `GST_PLUGIN_PATH` environment variable**:
   ```
   export GST_PLUGIN_PATH=$HOME/.local/lib/gstreamer-1.0:$GST_PLUGIN_PATH
   ```

## Verifying Installation

Check that the plugin has been registered with GStreamer:

```
gst-inspect-1.0 mpegtscrypto
```

You should see the plugin details and information about the `mpegtsencrypt` and `mpegtsdecrypt` elements.

Example output:

```
Factory Details:
  Rank                     none (0)
  Long-name                MPEG-TS Crypto Plugin
  Klass                    Codec/Parser
  Description              Plugin for encrypting/decrypting MPEG-TS streams
  Author                   ketulabs <deji.aribuki@gmail.com>

Plugin Details:
  Name                     mpegtscrypto
  Description              MPEG-TS Encryption/Decryption plugin
  Filename                 /usr/lib/gstreamer-1.0/libgstmpegtscrypto.so
  Version                  1.0
  License                  LGPL
  Source module            gstmpegtscrypto
  Binary package           GStreamer Custom
  Origin URL               https://github.com/deji-aribuki/gst-mpegtscrypto

  mpegtsdecrypt: MPEG-TS Crypto
  mpegtsencrypt: MPEG-TS Crypto

  2 features:
  +-- 2 elements
```

## Usage

Here’s how to use the plugin for encryption and decryption in GStreamer pipelines.

### Encryption Example

```
gst-launch-1.0 filesrc location=input.ts ! tsdemux ! mpegtsencrypt algo=aes-128-cbc key=00112233445566778899aabbccddeeff ! filesink location=encrypted.ts
```

- **`algo`**: Algorithm for encryption (e.g., `aes-128-cbc`, `des-cbc`).
- **`key`**: Encryption key in hexadecimal format (e.g., `00112233445566778899aabbccddeeff`).

### Decryption Example

```
gst-launch-1.0 filesrc location=encrypted.ts ! tsdemux ! mpegtsdecrypt algo=aes-128-cbc key=00112233445566778899aabbccddeeff ! filesink location=decrypted.ts
```

### CSA/CSA3 Example

#### Encryption
```
gst-launch-1.0 filesrc location=input.ts ! tsdemux ! mpegtsencrypt algo=csa key=0011223344556677 ! filesink location=encrypted.ts
```

#### Decryption
```
gst-launch-1.0 filesrc location=encrypted.ts ! tsdemux ! mpegtsdecrypt algo=csa key=0011223344556677 ! filesink location=decrypted.ts
```

## Debugging

You can enable detailed GStreamer debugging:

```
GST_DEBUG=mpegtscrypto:5 gst-launch-1.0 ...
```

This will output detailed logs for debugging the plugin.

## License

The `mpegtscrypto` plugin is released under the LGPL license.

## Supported features

### MPEG-TS encryption and decryption algorithms

aes-128-ecb
aes-128-cbc-rsb
aes-128-cbc-scte
aes-128-cbc-cs
aes-128-ctr
aes-128-ctr64
aes-256-ecb
aes-256-cbc-rsb
aes-256-cbc-scte
aes-256-cbc-cs
aes-256-ctr
aes-256-ctr64
des-ecb
des-cbc-rsb
des-cbc-scte
tdes-ecb
tdes-ecb-cs
tdes-cbc-rsb
tdes-cbc-scte
dvb-csa
dvb-csa3. 
