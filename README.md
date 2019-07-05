# SMPTE ST 2022 Lua Dissector for Wireshark

## Getting Started

To use this dissector first you must ensure Lua is supported in the version of Wireshark being used. Lua has shipped with the Windows version of Wireshark since 0.99.4 but availability on other platforms vary.

To see if Lua is supported in your version go to _Help>About Wireshark_. Lua should be mentioned in the "Complied by..." paragraph.

![About Wireshark](https://github.com/kscbroadcast/SMPTE-ST-2022-Wireshark-Dissector/blob/master/images/About-Wireshark.PNG)

Once Lua support has been confimred the the _SMPTE-2022.lua_ file must be placed in the Plugins folder. Wireshark looks for plugins in both a **Personal Lua Plugins** folder and a **Global Lua Plugins** folder.

On Windows Systems the folder locations are:  

- **Personal Lua Plugins** : _%APPDATA%\Wireshark\plugins_  
- **Global Lua Plugin** : _%PROGRAMFILES%\Wireshark\plugins_

On Linux systems the folder locations are:

- **Personal Lua Plugins** : _~/.local/lib/wireshark/plugins_  
- **Global Lua Plugin** : varies depending on the distro of Linux. Check

The location of the folders can be found by going to _Help>About Wireshark_ and selecting the _Folders_ tab.

Wireshark loads plugins at startup. Lua Plugins can be reloaded by going to _Analyze>Reload Lua Plugins_ or by hitting **Ctrl+Shift+L**

More information about using LUA with Wireshark can be seen here:  
<https://wiki.wireshark.org/Lua>

## Using the SMPTE ST 2022 Dissector

Once the _SMPTE-2022.lua_ file has been placed in the plugins folder start Wireshark or reload Lua Plugins by hitting **Ctrl+Shift+L**. Either make a capture of a ST 2022 data stream or load a _.pcap_ file.

The first thing that needs to be done is set tell Wireshark to decode the UDP port of your stream as RTP.

This is achieved by going to _Analyze>Decode As_ or by selecting a packet and right clicking and slecting **Decode As**

![Select Decode As](https://github.com/kscbroadcast/SMPTE-ST-2022-Wireshark-Dissector/blob/master/images/Select-Decode-As.PNG)

In the **Decode As** dialogue select RTP from the drop down list in the **Current** column.

![Decode As Dialogue](https://github.com/kscbroadcast/SMPTE-ST-2022-Wireshark-Dissector/blob/master/images/Decode-As-Dialogue.PNG)

Once Wireshark has processed the change then the protocols should be seen in the **Protocol** column

![Decoded ST2022-1](https://github.com/kscbroadcast/SMPTE-ST-2022-Wireshark-Dissector/blob/master/images/2022-1-Capture.PNG)

In the above image the ST2022-1 protocol is displayed in the **Packet List Pane** and the ST2022-1 Header and ST2022-1 Payload are shown as subtrees in the **Packet Details Pane**

## SMPTE ST 2022-5

![Decoded ST2022-5](https://github.com/kscbroadcast/SMPTE-ST-2022-Wireshark-Dissector/blob/master/images/2022-5-Capture.PNG)

In the above image the ST2022-5 protocol is displayed in the **Packet List Pane** and the ST2022-5 Header and ST2022-5 Payload are shown as subtrees in the **Packet Details Pane**

## SMPTE ST 2022-6

![Decoded ST2022-6](https://github.com/kscbroadcast/SMPTE-ST-2022-Wireshark-Dissector/blob/master/images/2022-6-Capture.PNG)

In the above image the ST2022-6 protocol is displayed in the **Packet List Pane** and the ST2022-6 Header and ST2022-6 Payload are shown as subtrees in the **Packet Details Pane**

## Feedback and Comments

If you have any feedback or comments please email support@kscbroadcast.com
