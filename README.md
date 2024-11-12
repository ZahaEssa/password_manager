# Secure Password Manager

A secure password manager using JavaScript, cryptographic primitives, and the SubtleCrypto API. This project protects passwords in an encrypted, in-memory key-value store (KVS) and defends against attacks like swap and rollback attacks, using AES-GCM, HMAC, and PBKDF2.

## Project Features

- **Password Encryption**: Uses AES-GCM to encrypt passwords securely.
- **Domain Privacy**: Encrypts domain names with HMAC to avoid plaintext exposure.
- **Key Derivation**: Derives a master key using PBKDF2 and a user-provided password.
- **Integrity Protection**: Protects against tampering with SHA-256 checksums.
- **Defenses Against Attacks**: Mitigates swap and rollback attacks through cryptographic methods.

## Installation

1. **Install Node.js**: [Download Node.js](https://nodejs.org/en/).
2. **Setup**: Clone the repository.

## Usage

- **Initialize**: `Keychain.init(password)` creates a new password manager.
- **Load**: `Keychain.load(password, serializedData, trustedDataCheck)` loads an existing keychain.
- **Store/Update**: `set(domain, password)` to add or update a password.
- **Retrieve**: `get(domain)` to fetch a stored password.
- **Remove**: `remove(domain)` to delete a password.
- **Export**: `dump()` serializes the keychain with a SHA-256 hash.

## Key Components

- **Key Derivation**: PBKDF2 strengthens the master key.
- **AES-GCM Encryption**: Encrypts each password individually.
- **HMAC and Domain Privacy**: Protects domain names by hashing them with HMAC.
- **SHA-256 for Integrity**: Generates a hash to check against tampering.

## Security Highlights

1. **Password Length Obfuscation**: Pads passwords to a fixed length before encryption.
2. **Swap Attack Prevention**: Links HMAC keys to encrypted data.
3. **Rollback Attack Mitigation**: SHA-256 checksum checks for tampering.
4. **Efficient Lookup**: Uses deterministic HMAC for consistent lookups.

## Testing

npm install -g mocha

npm test



# Short-answer Questions

1. **How do we prevent the adversary from learning password lengths?**  
  We added padding to each stored password to make them all the same length before encrypting. This way, even if someone could see the encrypted data, they wouldn’t be able to guess the actual length of any password.

2. **How do we prevent swap attacks?**  
   We used HMAC to generate unique keys for each domain name in our key-value store (KVS). Each domain’s HMAC is linked to its encrypted password, so if anyone tries to swap entries, the system detects the mismatch, and an error is triggered. This prevents unauthorized swapping.

3. **Is trusted storage necessary for defending against rollback attacks?**  
   Using trusted storage to keep the SHA-256 hash safe is helpful for defending against rollback attacks, but it’s not totally required. If trusted storage isn’t available, we could still store the hash with the encrypted data and run regular checks for tampering. But this would be less secure, as someone could change both the data and its hash. Trusted storage is better for extra safety.

4. **How would lookups work with a randomized MAC instead of HMAC, and is there a performance penalty?**  
  With a randomized MAC, each lookup would be harder because each MAC would be different every time. This would mean storing multiple versions of the MAC or adding a search process, which would slow things down. So, yes, using a randomized MAC would likely add a performance penalty.

5. **How do we reduce leakage of the record count?**  
   To hide the exact number of records, we could organize records in groups, or “bins,” of a fixed size. By keeping each bin’s count consistent, we’d only show the approximate number of records, making it harder to guess the real count.

6. **How could we add multi-user support without compromising other data?**  
   To allow multi-user access for shared entries, we’d create separate encryption keys for each shared password. These keys would only be accessible to the users who need them (like Alice and Bob for shared entries). Each user’s other data would be encrypted with their own keys, so only the shared entry would be accessible to both, keeping everything else secure and separate.







