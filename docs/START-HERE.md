# Start here

What notyas is, what you need, and the seven steps from a bare board to a signed
transaction. Nothing here assumes you have flashed a board or used a hardware wallet
before. Each step links to the page that does that step properly.

---

## What is this?

notyas is a small device that holds your Bitcoin keys and signs transactions with them. It
never joins a network. The keys are made on it, stay on it, and the only thing that ever
leaves is a signature.

It is **not** a wallet app. It does not hold coins: coins live on the Bitcoin network, and
keys are what let you move them. It does not go online, and there is no cable you can send a
transaction down. Transactions arrive on a microSD card and leave the same way.

**This is preview firmware.** No security audit has been done on this code. There is no
Secure Boot, no flash encryption and no secure element, and nobody has yet taken a
transaction from card to signature on a touch panel. Use testnet, and a seed you are
prepared to throw away. The full statement is
[Status and safety](../README.md#status-and-safety---read-this-first).

### Words you will meet

- **Air-gapped**: the device has no working network connection of any kind. Nothing goes in
  or out except the card you carry.
- **Coordinator**: the wallet software on your phone or computer. It watches the
  blockchain, shows your balance, and builds the transactions notyas signs. BlueWallet,
  Sparrow, Electrum and Bitcoin Core are the four this project writes about.
- **PSBT**: partially signed Bitcoin transaction. It is the file that travels between the
  two. Your coordinator writes one, notyas signs it, your coordinator broadcasts it.
- **Derivation path**: an address is one leaf on a tree of keys. The path, written like
  `m/84'/0'/0'/0/0`, says which leaf.
- **xpub**: extended public key. One key that produces every address in your wallet. It is
  public. It shows what you own; it cannot spend anything.
- **Fingerprint**: an eight-character label for your wallet, so software can tell whose key
  it is looking at.
- **Descriptor**: the xpub, plus the fingerprint, plus the derivation path, on one line with
  a checksum. It says whose key this is and exactly how to use it. This is what you hand
  your coordinator; hazard 1 below is what happens if you hand over a bare xpub instead.

---

## What do I need?

**A board.** Two have been tested on real hardware. The firmware is compiled for one board
or the other, so get one of these:

| Board | Panel |
|---|---|
| Waveshare ESP32-P4-WiFi6-Touch-LCD-4B | 720x720 touch, 4 inch |
| Elecrow CrowPanel Advanced 5inch ESP32-P4 | 800x480 touch, 5 inch |

Both are ordinary development panels sold by their makers, roughly USD 40 to 70 each before
shipping. This project sells no hardware and does not track prices, so the maker's page is
the authority on what one costs today. Eight other boards have code here that has never run
on hardware, and no firmware is published for them ([docs/BOARDS.md](BOARDS.md)).

The two are not equal on security. The Elecrow lets its radio chip start at every power-up
and run for a few hundred milliseconds before notyas can shut it down, so that board is
briefly visible over Wi-Fi and Bluetooth. The Waveshare holds its radio down from the instant
power arrives.

**A USB-C cable that carries data**, and a computer running Windows, macOS or Linux to
flash the board from. Many cables sold with phones carry power only, and that is the most
common reason a board never appears on the computer.

**A microSD card**, formatted FAT32. This is how transactions reach the device. On a
Waveshare 4B in its factory case the card slot sits behind the backing plate and cannot be
reached, so that board runs with the plate off.

**A coordinator.** BlueWallet runs on a phone. Sparrow, Electrum and Bitcoin Core run on a
computer. All four work; what differs is what comes back, and hazard 2 below depends on
which one you pick.

---

## The shape of it

**1. Get the files.** Download the release for your board from
https://github.com/intnsity/notyas/releases, with `SHA256SUMS.txt` and `SHA256SUMS.txt.asc`.
Take 0.2.3 or later: earlier tags have nothing on their pages to download.
[docs/FLASHING.md](FLASHING.md) section 1 lists every file and what it is for.

**2. Check the files.** Two questions, both answered before anything is written to a board:
are these the bytes that were published, and who published them. A hash check answers the
first, a signature check the second. [docs/FLASHING.md](FLASHING.md) section 3 walks both,
including the trap in the second: `gpg --verify` prints "Good signature" for any key carrying
the right name, so the check is the fingerprint and never the name.
[docs/VERIFYING.md](VERIFYING.md) is the thorough version, which rebuilds the firmware from
source and compares it byte for byte against what you downloaded.

**3. Put it on the board.** One command writes the whole image over USB. There is also a
Windows program in `flashtool/` that checks and flashes in one sitting.
[docs/FLASHING.md](FLASHING.md) covers both, and its section 6 covers what to do when the
board never appears on the computer.

**4. Provision the board, then set a PIN.** A freshly flashed board derives keys and shows
addresses, but it cannot store anything. Storing needs one key burned into the chip, once
per device, from your computer, and that burn cannot be undone. Read
[docs/PROVISIONING.md](PROVISIONING.md) before running any of it. The PIN is not a separate
menu: the device asks for it, twice, at the moment you save your first wallet in step 5.

**5. Make or restore a wallet.** Roll physical dice on the panel, or type a recovery phrase
you already have. Either way the device shows you the words, makes you check them back word
by word, and only then asks the one question that writes anything: save this wallet to the
device, or use it once and keep nothing. [docs/TOUR.md](TOUR.md#making-a-wallet) shows every
screen of it.

**6. Give your coordinator the descriptor.** Open the wallet, tap Export, and take the
descriptor from the top of the BIP-84 tab, as text or as a QR code you photograph. Build a
watch-only wallet from it. Then tap Receive and compare the address the device shows against
the address your coordinator shows for the same index: they must match character for
character. [docs/TOUR.md](TOUR.md#exporting-to-a-coordinator) shows the screen.

**7. Sign.** Build the spend in your coordinator, export the PSBT, and copy it onto the
card. On the device: Sign a transaction, pick the file, and read every review page - the
hold gesture that signs does not appear until you have. The signed file goes back to the
card, or onto the screen as a QR code if it is small enough. Your coordinator finalizes and
broadcasts it; nothing in this project does that.
[docs/TOUR.md](TOUR.md#reviewing-and-signing-a-transaction) shows the review pages.

---

## Two things that will bite you

### 1. Hand over the descriptor, not the bare xpub

The Export screen shows the descriptor first and the bare xpub below it. Use the first one.

A bare extended key carries no fingerprint and no derivation path. The coordinator that
reads it has to invent both: whose key this is, and which branch it came from. BlueWallet's
documented default for a bare xpub is the legacy branch, `m/44'/0'/0'`.

This has already cost somebody real trouble. A user handed over a bare xpub, received coins
on a legacy address he had not chosen, and then could not spend them from the device, which
refused his own transaction with words about cosigner keys he did not have. The coins were
never lost, and the device signs that script type today. The report is
[docs/archive/RELEASE-0.2.2.md](archive/RELEASE-0.2.2.md) section 0.

The descriptor closes both guesses, and it keeps mattering after setup: a coordinator that
only ever saw a bare key writes an all-zero fingerprint into every transaction it builds, so
nobody downstream can tell which signer made which signature.

### 2. A spend with two or more inputs can be refused

This is deliberate. It is not a broken device.

An **input** is one coin you are spending. If your transaction spends two or more coins, the
device requires the file to prove what each of those coins is worth, by carrying the full
previous transaction each one came from. A file that merely states an amount is refused,
with the code R-02.

The reason is that a signature only vouches for its own coin's amount. With two coins in the
file, a dishonest coordinator can prove one amount, merely claim the other, and collect a
signature over the coin it proved. Then it sends the same transaction back with the roles
swapped and collects a second. Each round shows an ordinary fee. The two signatures combine
into one transaction that pays an enormous one, and the device keeps no history, so it
cannot notice the second round.

**What this means in practice.** BlueWallet never attaches previous transactions, so a
BlueWallet spend of a single coin signs, and a BlueWallet consolidation, or Send Max from a
wallet holding more than one coin, is refused. Sparrow, Electrum and Bitcoin Core attach
them.

**The remedy**, which is also what the refusal screen says: use coin control to select a
single coin, or rebuild the transaction in software that attaches full previous transactions
- Sparrow, Electrum or Bitcoin Core - and load it again.

The full argument is [docs/archive/RELEASE-0.2.1.md](archive/RELEASE-0.2.1.md) section 0.
[docs/REFUSALS.md](REFUSALS.md) is the table of every refusal code with what to do about
each.

---

## What this device will not do for you

- **It does not back up your seed.** Write the recovery words down when the device shows
  them. That is the only copy that will ever exist.
- **There is no recovery service.** Nobody can restore your wallet for you. There is no
  account, no support key and no back door.
- **Fifteen wrong PINs erase everything on it, and nothing can turn that off.** No setting,
  no build, no menu. The count can also creep up on its own: a power cut at the wrong
  instant costs an attempt even when the PIN was right. Set a PIN you will not mistype
  fifteen times.
- **Your recovery words recover the seed and nothing else.** Multisig registrations, wallet
  labels and settings live only on the device, and a wipe destroys them permanently.
- **It will not sign every script type.** P2SH multisig and P2SH-P2WSH multisig are refused
  and there is no remedy in this release ([docs/REFUSALS.md](REFUSALS.md), code R-26).
- **It locks itself after 120 seconds**, with no warning and no countdown, including in the
  middle of a long transaction review.

---

## Where to go next

- [docs/TOUR.md](TOUR.md) - see it: every function, with the screens beside it.
- [docs/FLASHING.md](FLASHING.md) - install it, assuming you have never flashed a chip.
- [docs/VERIFYING.md](VERIFYING.md) - check it properly: rebuild the firmware yourself and
  compare it against what was published.
- [docs/KNOWN-ISSUES.md](KNOWN-ISSUES.md) - what is broken. A defect list, not a wish list.
- [docs/REFUSALS.md](REFUSALS.md) - look up a refusal code you saw on the panel.
- [README.md](../README.md) - the front door: the security model, what is deliberately
  missing, and how to build from source.
