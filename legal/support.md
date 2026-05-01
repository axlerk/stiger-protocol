# Stiger — Support

## What is Stiger?

Stiger is an iOS app and iMessage extension that lets you hide a
secret message — text or your current location — inside an ordinary
sticker. The recipient sees a normal sticker; you and they share a
password to reveal what is hidden inside.

## Quick start

1. Install Stiger from the App Store.
2. Open Messages → tap the apps drawer → choose Stiger.
3. Pick a sticker, tap **Add secret**, type your text.
4. (Optional) Turn on encryption in the main Stiger app and set a
   password you and your partner already know.
5. Tap send. The recipient long-presses the sticker → **Reveal**
   to see the hidden message.

For a deeper walkthrough of the cryptography, the wire format, and an
independent Python reference decoder, see
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
The free "open" mode is steganographic but easy to detect with a
custom tool — it is meant for fun, not adversarial use. Stealth mode
(Pro) is designed to be statistically indistinguishable from a normal
sticker.

**Q: I lost my password.**
We cannot recover it. The password never leaves your device, and
without it the secret is unrecoverable.

**Q: I'm in Russia and the App Store won't let me pay.**
All Pro features are unlocked automatically when the app's UI language
is Russian. This works whether Russian is your system language or you
set it just for Stiger in iOS Settings → Stiger → Language.

## Contact

**hello@onegoodman.studio** — bugs, feature requests, security
issues. For security issues, please prefix the subject line with
`[SECURITY]`.

---

_Operated by Individual Entrepreneur Pavel Khudiakov (Tbilisi, Georgia)._
