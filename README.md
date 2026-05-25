# AZUL

AZUL is the main server software for the CrossTalk service; a chat service planning to support as many messaging protocols as possible, both retro and modern. 

## Protocol support

### MSNP (used by MSN/Windows Live Messenger) 

Currently, MSNP2 through MSNP18 are fully implemented, with an MSNP19 - MSNP21 implementation in development. It has been tested and works with every version of MSN/Windows Live Messenger released on Windows, with a few caveats:

- If you want to log in to MSN Messenger < 4.7.2009, an MD5-encoded password hash must be stored

- Circles/Groups for Windows Live Messenger 2009 are fully implemented, however, managing members is expected to be done from the CrossTalk website. You can use `script/managecircle.py` to perform a few actions on a Circle and its users (run `python script/managecircle.py -h` to see instructions)

- Windows Live Messenger 2011/2012 supports authentication, viewing your contacts list, presence updates, and MsgrConfig, and instant messaging. Most other functionality is either unimplemented or untested. Peer-to-peer functionality (display picture syncing, file transfers, activites/games etc) currently does not interop between 2011/2012 and older versions; it only works with other 2011/2012 users.

### YMSG (used by Yahoo! Messenger)

As of now, YMSG9 through YMSG15 are implemented, with some caveats:

- If you want to log in, an MD5crypt-encoded password hash must be stored

- Conferences are currently not working

- Yahoo! Messenger 7.0 does not log in for currently unknown reasons. 5.0, 5.5, 5.6, 6.0, 7.5, 8.0, and 8.1 were all tested to work, however

- Yahoo! Messneger for Vista also does not work for currently unknown reasons

### IRC

IRC is going to be completely reworked with the introduction of chatrooms, but as it stands, it's fairly basic. It offers the ability to create, join, invite people to, leave, and list other people in temporary chats, and to set your nickname, view the MOTD, and set an away message. It also requires `USER`-based login with your account credentials, however, IRC-only guest logins are planned.

### OSCAR (used by AOL Instant Messenger and ICQ 2000 - 8)

OSCAR is basic, but functional. Right now, messaging and buddy list management is implemented. The FLAP and BUCP authentication methods are implemented. AIM 1.0 - 5.9 are supported, but 4.x and 5.x are where most testing is done, so older versions may be hit or miss. AIM 6.x - 7.x, TOC/TOC2, WebAPI, and ICQ are not supported yet, but support for them is planned and will come in the future. Not sure about AIM 8 because of NINA getting exploded.

## Developers

TODO
