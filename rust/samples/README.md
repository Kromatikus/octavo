# Samples

Made from the **PUBLIC demo seed** (`sneak1024-seed.txt`, SHA-256 8d1f7c16…8e24), never a real key:

    octavo hear -k sneak1024-seed.txt --sid demo_seed_earworm.sid --sid-wav demo_seed_earworm_sid.wav
    D4 G5 A4 C4- C4 D4 A5 D5- A5 D4 C4 E4- C4 C5 G4- D4-

- `demo_seed_earworm.sid`: PSID v2, play with `sidplayfp demo_seed_earworm.sid`.
- `demo_seed_earworm_sid.wav`: two passes rendered by the built-in SID-style synth.

Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
