# Stiger — Privacy Policy

_Last updated: 29 September 2026_

Stiger is an iOS app and iMessage extension that hides text or location
secrets inside sticker images using on-device steganography and
encryption. This document describes what data Stiger does and does not
collect.

## TL;DR

- Stiger has **no servers**, **no accounts**, **no analytics**,
  **no advertising**, **no third-party tracking SDKs**.
- Everything you create — secrets, custom stickers, passwords —
  stays on your device.
- Two kinds of outbound network requests exist, both described below:
  Telegram sticker pack import, when you use it, and Apple Maps
  imagery, whenever Stiger shows a map.

## Data we collect

**None.** Stiger does not transmit any personal data to its developer
or to any third party for our own use.

## Data stored on your device

| What | Where | Encrypted at rest |
|---|---|---|
| Custom sticker images you import | App Group container | No (iOS file protection only) |
| Drafts of unsent secrets, kept for up to 72 hours | App Group container | Text: yes, with a key kept in this device's Keychain. Sticker image: iOS file protection only |
| Your password and a saved partner password (if you set them) | iOS Keychain, this device only | Yes (Keychain) |
| App settings (encryption on/off, biometrics on/off, etc.) | App Group `UserDefaults` | No |
| Sticker tap frequency (for "top used" section) | App Group `UserDefaults` | No |
| The padded size used for each sticker you send | App Group `UserDefaults` | No |

Deleting the app removes everything in the App Group container. iOS
keeps Keychain items after an app is deleted; Stiger erases its saved
passwords the next time it is installed on this device. Until then they
stay in this device's Keychain, where no other app can read them.

## Outbound network requests

Stiger talks to the network only in these cases:

1. **Telegram sticker pack import** (Pro feature). When you paste a
   `t.me/addstickers/<name>` link, the app calls the public Telegram
   Bot API at `api.telegram.org` to fetch publicly available sticker
   pack contents. No personal data is sent. The pack name and a
   developer-issued bot token are the only request payload.
2. **Apple Maps.** Maps in Stiger are drawn by Apple's MapKit, which loads
   map imagery from Apple's servers for the area on screen. That happens
   when you pick a location to send (including any place you search for),
   and automatically when you reveal a secret that carries a location (an
   attached location, or a map link with coordinates in it): Stiger shows a
   small map preview, and loading it tells Apple which area is being viewed,
   from your IP address. Stiger sends Apple nothing else. These requests are
   covered by Apple's own privacy policy. To keep a place away from Apple
   entirely, send it as plain text.

Stiger never uploads your secrets, stickers, photos, location, or any
other user-generated content to any server.

## Location

Stiger requests location access only when you tap the location button
inside the iMessage extension. The coordinates are embedded as the
hidden secret inside the sticker you are about to send; Stiger itself
sends them nowhere else. The map you pick them on is loaded from Apple
Maps (see "Outbound network requests" above). If you deny the permission,
every other Stiger feature continues to work.

## Camera

Stiger requests camera access only when you choose to add a sticker
from a photo you take in the moment, or to scan a partner's QR code
when you pair a shared password. Captured images are processed on
device.

## Face ID / Touch ID

Stiger uses biometric authentication only to gate its settings and
saved passwords and, if you turn it on, writing and reading secrets in
the iMessage extension. Authentication happens entirely
through Apple's `LocalAuthentication` framework; Stiger never sees
your biometric data.

## Purchases

In-app purchases (Stiger Pro monthly, yearly and lifetime, sticker
packs, and Donate) are processed by Apple via StoreKit. Stiger sees only
which of its products your Apple Account owns, as StoreKit reports it on
the device.
We do not receive your name, email, payment details, or App Store
account.

## Children

Stiger is not directed at children under 13 and does not knowingly
collect data from them. Age rating: 4+.

## Changes to this policy

Updates will be published at this URL with a new "Last updated" date.

## Contact and data controller

Privacy questions, deletion requests, or anything else:

**Individual Entrepreneur Pavel Khudiakov** (Tbilisi, Georgia)
Email: hello@onegoodman.studio

The full registered address is on file with the Apple App Store and is
disclosed to regulators on request.
