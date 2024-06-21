# wolfSSL NXP Application Code Hub

<a href="https://www.nxp.com"> <img src="https://mcuxpresso.nxp.com/static/icon/nxp-logo-color.svg" width="125" style="margin-bottom: 40px;" /> </a> <a href="https://www.wolfssl.com"> <img src="Images/wolfssl_logo_300px.png" width="100" style="margin-bottom: 40px" align=right /> </a>

This Repo is currently a work in progress and some items are placeholders.

## How to Use
The projects in this repo are intended to be used with NXP's [MCUXpresso for VS-code plugin](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/general-purpose-mcus/lpc800-arm-cortex-m0-plus-/mcuxpresso-for-visual-studio-code:MCUXPRESSO-VSC?cid=wechat_iot_303216).

To use a demo project simply use the provided `setup.sh` or `setup.bat` on the given project you want to run. 

### 1. Setup

#### Example
MacOS and Linux:
```
cd \path\to\nxp-appcodehub
./setup.sh dm-wolfssl-tls-hello-server-with-zephyr
```
Expected Output:
```
nxp-appcodehub % ./setup.sh dm-wolfssl-tls-hello-server-with-zephyr 
Created .vscode directory in dm-wolfssl-tls-hello-server-with-zephyr.
cmake-kits.json created.
cmake-variants.json created.
launch.json created.
mcuxpresso-tools.json created.
settings.json created.
```

This creates the necassary base files that the plugin needs to import the project correctly.

The default board is the FRDM-MCXN947, if you wanted to use a different board like the `mimxrt1060_evkb`, then add a second argument to the command like so:
```
./setup.sh dm-wolfmqtt-button-publisher-client-with-zephyr mimxrt1060_evkb
```

You may need to double check the `proj.conf` settings of the project to disable and/or enable drivers specific for the board. 

### 2. Import the Project

Assuming you have the necassary software describe in the readme for the given 
project, you simple need to go to the MCUXpresso plugin menu and select `Import Project` as seen in the figure below.

[<img src="Images/Plugin-Menu.png" width="200"/>](Images/Plugin-Menu.png)

Once you select `Import Project` select the path for the desired project you want to run. This will then detect the type of Project it. You will need to setup any repositories and SDK's through the plugin options.

In the figure below the imported project is of the type `Zephyr` and this means it needs to point to the Zephyr SDK and Repository. These need can be install via the `Import Repository` and the `MCUXpresso Installer` options seen in the previous menu

[<img src="Images/Import-Menu.png" width="500"/>](Images/Import-Menu.png)

Once you select the `Repository` and `SDK` you want to use with the imported project hit the `Import` button.

## Setting Up wolfSSL, wolfMQTT, and wolfSSH

Currently with the way the projects are setup you will need to add wolfSSL, wolfSSH, wolfMQTT, ect to the `west.yml` file inside the Zephyr Repo thats specified during the importation of the project.

```
manifest:
  remotes:
    # <your other remotes>
    - name: wolfssl
      url-base: https://github.com/wolfssl
    - name: wolfssh
      url-base: https://github.com/wolfssl
    - name: wolfmqtt
      url-base: https://github.com/wolfssl

  projects:
    # <your other projects>
    - name: wolfssl
      path: modules/crypto/wolfssl
      revision: master
      remote: wolfssl
    - name: wolfssh
      path: modules/lib/wolfssh
      revision: master
      remote: wolfssh
    - name: wolfmqtt
      path: modules/lib/wolfmqtt
      revision: master
      remote: wolfmqtt

```

For more Zephyr Specific examples look at the following README's:
- [wolfSSL](https://github.com/wolfSSL/wolfssl/tree/master/zephyr)
- [wolfSSH](https://github.com/wolfSSL/wolfshh/tree/master/zephyr)
- [wolfMQTT](https://github.com/wolfSSL/wolfmqtt/tree/master/zephyr)

