
# MOTAM beacons' PKI

MOTAM beacons' platform uses an ad hoc security platform based on PKI. Every platform beacon transmits environment information (traffic light state, stop sign presence, bicycle accident and more) and a small cryptographic certificate. 

This tailor-made cryptographic certificate (aka mini-cert) is used to validate the information that comes from a trusted MOTAM platform beacon. This information is captured and verified by the [MOTAM gateway](https://github.com/nicslabdev/MOTAM-Gateway) included in the vehicles.

This repository contains the Certificate Authority application developed in [Nordic Semiconductor nRF52840 dongle](https://www.nordicsemi.com/eng/Products/nRF52840-Dongle).

The mini-certs are generated within nRF52840 and private keys are kept inside the SoC (they are not exportable). Generated mini-certs are sent through serial port. We have developed a Python script that made easier the serial communication with the nRF52840.

## Requirements
Currently, this project uses:
- nRF5 SDK version 15.2.0
- nRF52840 PDK (PCA10056) or nRF52840 Dongle (PCA10059)

## Get started 
 
The project has a hex folder with the precompiled application.

In order to program the device (nRF52840 PDK or Dongle), just use the Programmer application of Nordic Semiconductor [nRF Connect Desktop](https://www.nordicsemi.com/eng/Products/Bluetooth-low-energy/nRF-Connect-for-Desktop).

In order to stablish serial connection with your PC, you can use PUTTY if you are a Windows user or GNU Screen if you are a UNIX user.

**PUTTY connection parameters:**

```
Baud rate: 115.200
8 data bits
1 stop bit
No parity
HW flow control: None
```

**GNU screen**

```
sudo screen /dev/ttyACM0 115200
```

Where  _/dev/ttyACM0_  is the nRF52840 device. You can know what is the path of your nRF52840 connecting it and executing  _dmesg_  on UNIX terminal.

In case you are working on nRF52840 Development Kit:

-   Use nRF USB connector (J3 connector) for  **beacon scanner function**.
-   Use MCU USB connector (J2 connector) in order to see logger messages.


## Compiling the application
If you modify the code and you need to recompile it, just put the MOTAM_apps folder into the \nRF5_SDK_15.2.0\ folder.

There are several ways for developing code in nRF52, we have done this with [GCC and Eclipse](https://devzone.nordicsemi.com/tutorials/b/getting-started/posts/development-with-gcc-and-eclipse).

# To do
- Validity time: change start-end time format to start-duration format in order to save space.
- Bug: Send commands like "show" doesn't work properly if there are some data on the buffer before writing on it.
- Accept parameters like beacon ID, start date and duration validity, etc (now everything is static-hard coded).
- Develop Python script.