# AZUL

AZUL is the main server software for the CrossTalk service; a chat service planning to support as many messaging protocols as possible, both retro and modern. Based on the legacy Escargot codebase.

## Protocol support

### MSNP (used by MSN/Windows Live Messenger) 

Currently, MSNP2 through MSNP18 are fully implemented, with an MSNP19 - MSNP21 implementation in development. It has been tested and works with every version of MSN/Windows Live Messenger released on Windows, with a few caveats:

- If you want to log in to MSN Messenger < 4.7.2009, an MD5-encoded password hash must be stored

- Circles/Groups for Windows Live Messenger 2009 are fully implemented, however, managing members is expected to be done from the CrossTalk website. You can usethe admin panel to perform a few actions on a Circle and its users 

- Most peer-to-peer functionality (display picture syncing, file transfers, activites/games etc) currently does not interop properly between 2011/2012 and older versions; it only works with other 2011/2012 users. This will be fixed in a future update.

### YMSG (used by Yahoo! Messenger)

As of now, YMSG9 through YMSG15 are implemented, with some caveats:

- If you want to log in, an MD5crypt-encoded password hash must be stored

- Conferences are currently not working

- Yahoo! Messenger 7.0 does not log in for currently unknown reasons. 5.0, 5.5, 5.6, 6.0, 7.5, 8.0, and 8.1 were all tested to work, however

- Yahoo! Messneger for Vista also does not work for currently unknown reasons

### IRC

IRC is going to be completely reworked in the future with the introduction of chatrooms, but as it stands, it's fairly basic. It offers the ability to create, join, invite people to, leave, and list other people in temporary chats, and to set your nickname, view the MOTD, and set an away message. It also requires `USER`-based login with your account credentials, however, IRC-only guest logins are planned.

### OSCAR (used by AOL Instant Messenger and ICQ 2000 - 8)

- If you want to log in, an MD5-encoded password hash must be stored
- AIM: client-side and server-side (feedbag) buddy lists with permit/deny, profiles and away messages, buddy icons (BART), chat rooms (made by users, exchange 4), warnings, typing notifications, offline IMs (stored when the sender asks, handed over at sign-on), the member directory, and rendezvous (file transfers, direct IM) between OSCAR clients. Buddies can be added by screen name or by ICQ number.
- ICQ 2000b and later sign on with their UIN (or, like AIM, with the username), and get ICQ statuses (away, N/A, occupied, DND, free for chat, invisible), the white pages (`ICQ__DB_QUERY` info and searches, which only show members listed in the directory), offline messages and authorization requests. 
- An all-digit screen name is tried as a UIN first, then as a username, so neither kind of account gets in the way of the other.

### ICQ (the pre-OSCAR Mirabilis protocol, ICQ 1.x - 2000a)

The original UDP protocol, versions 1 - 5, on UDP port `ICQ_LEGACY_PORT` (4000 by default; `ENABLE_FRONT_ICQ = False` turns it off): V5 is ICQ 98b - 2000a, V4 ICQ 98a, V3 ICQ Groupware, V2 ICQ 1.111 and CenterICQ, V1 ICQ 1.02. Point the client at the server with "For admin use" in its registration wizard, then choose to sign on as an existing user. Signing on takes the UIN and the account's password (the client's own limit on password length applies).

Contact list presence, statuses, messages and URLs (to and from every other protocol), offline messages, the white pages (`META_USER` for V5, the older info and search packets before it), profile changes and authorization requests work. New accounts can't be made from the client; they come from the website. Direct connections (file transfers, chat) are only possible with `ICQ_DIRECT_CONNECTIONS = True`, which hands V5 clients each other's IP address.

## Developers

TODO
