# Azul

Azul is the main server software for the CrossTalk service; a chat service planning to support as many messaging protocols as possible, both retro and modern. This service acts as the backbone for all chat-related services that are a part of the undergr0und.

## Protocol support

### MSNP (used by MSN/Windows Live Messenger) 

Currently, MSNP2 through MSNP18 are fully implemented, with an MSNP19 - MSNP21 implementation in development. It has been tested and works with every version of MSN/Windows Live Messenger released on Windows, with a few caveats:

- If you want to log in to MSN Messenger < 4.7.2009, an MD5-encoded password hash must be stored

- Circles/Groups for Windows Live Messenger 2009 are fully implemented, however, managing members is expected to be done from the CrossTalk website. You can use `script/managecircle.py` to perform a few actions on a Circle and its users (run `python script/managecircle.py -h` to see instructions)

- Windows Live Messenger 2011/2012 supports authentication, viewing your contacts list, presence updates, and MsgrConfig. Most other functionality is either unimplemented or untested

### YMSG (used by Yahoo! Messenger)

As of now, only YMSG9 through YMSG15 are implemented, with some caveats:

- If you want to log in to Yahoo! Messenger < 7.0, an MD5crypt-encoded password hash must be stored

- Conferences are currently not working

- Yahoo! Messenger 7.0 does not log in for currently unknown reasons. 5.0, 5.5, 5.6, 6.0, 7.5, 8.0, and 8.1 were all tested to work, however

- Yahoo! Messneger for Vista is untested, but should work

### IRC

IRC support is going to be completely reworked with the introduction of chatrooms, but as it stands, it's fairly basic. It offers the ability to create, join, invite people to, leave, and list other people in temporary chats, and to set your nickname, view the MOTD, and set an away message. It also requires `USER`-based login with your account credentials, however, IRC-only guest logins are planned.

### OSCAR (used by AOL Instant Messenger and ICQ 2000 - 8)

OSCAR support is basic. Right now, only `FEEDBAG`, `BUDDY`, et cetera are partially implemented, and it supports showing your buddy list as well as presence updates. Messaging currently isn't supported yet. Only the FLAP authentication method and BUCP with the older hashing method (used by AIM 3.5 & 4.x) is implemented. It has been tested to work with AIM 4.3 and 4.8; older versions may be hit or miss. AIM 5.x - 7.x, TOC/TOC2, WebAPI, and ICQ are not supported yet, but support for them is planned and will come in the future.

## Developers

TODO
