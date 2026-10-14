# Stiger — Support

## What is Stiger?

Stiger is an iOS app and iMessage extension that lets you hide a
secret message — text or a location — inside an ordinary sticker. The
recipient sees a normal sticker until they reveal it in Stiger. A free
secret is hidden but not encrypted: anyone with Stiger can read it.
With Stiger Pro you can lock it with a password that you and the
recipient share; to read a locked secret, the recipient needs Stiger
Pro and that password too.

## Quick start

1. Install Stiger from the App Store.
2. Open Messages → tap the apps drawer → choose Stiger.
3. Tap a sticker, type your secret (or attach a location), tap
   **Send**, then send the sticker as usual.
4. (Optional, Pro) Turn on encryption in Stiger's settings and set a
   password you and your partner already know. Your partner needs Pro
   as well to read it.
5. To read it, the recipient opens Stiger in Messages, touches and
   holds the sticker in the conversation, and drags it into the
   Stiger panel.

For a deeper walkthrough of the cryptography, the wire format, and
independent reference decoders in Python and TypeScript, see
<https://github.com/axlerk/stiger-protocol>.

## Frequently asked questions

**Q: Does Stiger have my secrets?**
No. Everything is computed on your device. Stiger has no servers and
no accounts.

**Q: What encryption does it use?**
AES-256-GCM with a key derived from your password via PBKDF2-SHA256
(600 000 iterations). Open mode (the free tier) hides text but does
not encrypt it; encryption requires Stiger Pro.

**Q: Can someone tell a sticker has a secret in it?**
Open mode (free) is meant for fun, not adversarial use: anyone with
Stiger — or a short script following the public spec — can read it.
Stealth mode (Pro, with a password) carries no fixed marker for a
scanner to look for, and without the password its content and length
stay hidden. It does not hide that the image was modified: statistical
steganalysis tools can flag it as a likely carrier. The threat model
in the repository above spells out what is and is not protected.

**Q: I lost my password.**
We cannot recover it. Stiger keeps it only in this device's Keychain —
never on a server — and it leaves the device only if you share it with
a partner through QR pairing. Without it the secret is unrecoverable.

**Q: I'm in Russia and the App Store won't let me pay.**
All Pro features are unlocked automatically when your iPhone's primary
language is Russian — the first language in Settings → General →
Language & Region. Setting Russian only for Stiger (Settings → Stiger →
Language) does not unlock them.

## Contact

**hello@onegoodman.studio** — bugs, feature requests, security
issues. For security issues, please prefix the subject line with
`[SECURITY]`.

---

_Operated by Individual Entrepreneur Pavel Khudiakov (Tbilisi, Georgia)._
