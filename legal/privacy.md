# Stiger — Privacy Policy

_Last updated: 28 April 2026_

Stiger is an iOS app and iMessage extension that hides text or location
secrets inside sticker images using on-device steganography and
encryption. This document describes what data Stiger does and does not
collect.

## TL;DR

- Stiger has **no servers**, **no accounts**, **no analytics**,
  **no advertising**, **no third-party tracking SDKs**.
- Everything you create — secrets, custom stickers, passwords —
  stays on your device.
- Two outbound network calls exist, both initiated by you and
  described below.

## Data we collect

**None.** Stiger does not transmit any personal data to its developer
or to any third party for our own use.

## Data stored on your device

| What | Where | Encrypted at rest |
|---|---|---|
| Custom sticker images you import | App Group container | No (iOS file protection only) |
| Saved partner password (if you enable it) | iOS Keychain | Yes (Keychain) |
| App settings (encryption on/off, biometrics on/off, etc.) | App Group `UserDefaults` | No |
| Sticker tap frequency (for "top used" section) | App Group `UserDefaults` | No |

Removing the app removes all of the above.

## Outbound network requests

Stiger talks to the network only in these two cases:

1. **Telegram sticker pack import** (Pro feature). When you paste a
   `t.me/addstickers/<name>` link, the app calls the public Telegram
   Bot API at `api.telegram.org` to fetch publicly available sticker
   pack contents. No personal data is sent. The pack name and a
   developer-issued bot token are the only request payload.
2. **Sticker pack catalog refresh.** The app fetches a static JSON
   catalog of available built-in sticker packs from a developer-hosted
   URL. The request contains no personal data.

Stiger never uploads your secrets, stickers, photos, location, or any
other user-generated content to any server.

## Location

Stiger requests location access only when you tap the location button
inside the iMessage extension. The coordinates are embedded as the
hidden secret inside the sticker you are about to send and never leave
your device through any other channel. If you deny the permission,
every other Stiger feature continues to work.

## Camera

Stiger requests camera access only when you choose to add a sticker
from a photo you take in the moment, or to scan a partner's QR code
to import a shared encryption key. Captured images are processed on
device.

## Face ID / Touch ID

Stiger uses biometric authentication only to gate access to settings
and saved passwords on your device. Authentication happens entirely
through Apple's `LocalAuthentication` framework; Stiger never sees
your biometric data.

## Purchases

In-app purchases (Stiger Pro monthly, yearly, lifetime, and Donate)
are processed by Apple via StoreKit. Stiger sees only an anonymous
entitlement flag indicating whether you have an active subscription.
We do not receive your name, email, payment details, or App Store
account.

## Children

Stiger is not directed at children under 13 and does not knowingly
collect data from them. Age rating: 12+.

## Changes to this policy

Updates will be published at this URL with a new "Last updated" date.

## Contact and data controller

Privacy questions, deletion requests, or anything else:

**Individual Entrepreneur Pavel Khudiakov** (Tbilisi, Georgia)
Email: khudiakov.develop@gmail.com

The full registered address is on file with the Apple App Store and is
disclosed to regulators on request.
