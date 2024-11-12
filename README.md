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

testnpm test



# Short-answer Questions
1. How do we prevent the adversary from learning password lengths?
   We ensured each stored password is padded to a fixed maximum length before encryption. This approach means that even if the encrypted passwords are observed, an adversary 
   cannot infer the actual length of each password, as they all appear to be the same length after padding.

2. How do we prevent swap attacks?
   To defend against swap attacks, we implemented HMAC for each domain name to create unique, tamper-proof keys in the key-value store (KVS). Since each domain’s HMAC is 
   linked to the encrypted data, any attempt to swap entries would be detected, as the HMAC verification would fail for mismatched entries. This ensures that if an adversary 
   tries to swap entries, it triggers an error on retrieval, thereby preventing unauthorized swapping.

3. Is trusted storage necessary for defending against rollback attacks?
   While having a trusted storage location for the SHA-256 hash makes rollback attacks easier to detect, it is not strictly necessary. If trusted storage is unavailable, we 
   could store the hash alongside the encrypted data and use periodic checks to verify integrity. However, this approach could be less secure as an adversary with access to 
   the entire data could modify both the data and its hash. Trusted storage remains preferable for stronger defense.

4. How would lookups work with a randomized MAC instead of HMAC, and is there a performance penalty?
   If a randomized MAC was used, each lookup would require storing multiple versions of the MAC (since it would differ with each generation) or implementing a complex 
   search. This would likely involve re-computing the MAC with the randomized component each time for lookup, adding computational overhead and increasing retrieval time. 
   Therefore, a randomized MAC could result in a performance penalty due to additional computation.

5. How do we reduce leakage of the record count?
   To obscure the exact number of records, we could use a data structure that groups records in fixed-size "bins." The number of records in each bin could be kept 
   consistent, so only the logarithmic size (in terms of bins) is leaked. This approach would allow for efficient lookup while only revealing a range (like log₂(k)), making 
   it harder for an adversary to know the exact count.

6. How could we add multi-user support without compromising other data?
   For multi-user access, we would create distinct encryption keys for each shared password entry, stored separately and accessible only to authorized users (e.g., Alice and 
   Bob for the shared entry). Each user’s other data would be encrypted with keys specific to them. Thus, only the shared entry is accessible with shared keys, while their 
   other data remains secure. This approach maintains data separation and security across users.







