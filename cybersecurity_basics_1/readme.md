# Security Operations & Compliance Project

This section documents key deliverables around security governance, encryption, incident response planning, and legal/ethical compliance as part of the SOC virtual lab project.

---

# Cybersecurity Basics 1 Project Submission

## Criteria Breakdown & Deliverables

### 1. Create an Incident Response Plan

- [x] **Detection**
  - [x] Describe at least 1 method used to detect a security incident  
    _(e.g., SIEM alerts, IDS logs, unusual network behavior)_

- [x] **Containment**
  - [x] Outline 1 containment strategy  
    _(e.g., isolating infected systems, disabling compromised accounts)_

- [x] **Eradication & Recovery**
  - [x]  List steps to:
    - [x] Eradicate the threat  
    - [x] Recover system functionality

- [x] **Attack Type**
  - [x] Identify and explain **1 type** of cyberattack:
    - Malware, Phishing, Ransomware, or Denial of Service (DoS)

---

#### Detection

  - Method Used:
    - Detected through SIEM alert (Wazuh) flagging multiple failed login attempts on the FTP service from the same IP within a short time frame.

  - Supporting Logs:
    - Located in Wazuh's dashboard under:
    Security Events > FTP Service > Authentication Failures
    

Example log snippet:

```
Jul 25 16:32:11 ftpserver vsftpd[2256]: FAIL LOGIN: Client "192.168.1.45"
```

#### Containment

  - Strategy:

      - Immediately blocked IP address of the attacker using the host firewall (iptables or Windows Defender Firewall).

      - Disabled external FTP access until internal review complete.

      - Alerted internal team and marked the system under investigation.

#### Eradication & Recovery

  - Eradication Steps:

      - Reviewed authentication logs and identified affected accounts.

      - Reset passwords for all FTP users.

      - Removed unauthorized or suspicious user accounts.

      - Uninstalled unused services and closed unnecessary ports.

  - Recovery Steps:

      -  Restored the FTP server from last known clean backup (if tampering detected).

      - Applied system and FTP server patches.

      - Re-enabled FTP service with updated access controls and monitoring.

      - Confirmed system stability and no signs of persistence/backdoors.

#### Attack Type

  - Brute Force Attack:
    
    The attacker used automated tools (e.g., Hydra) to guess user credentials by repeatedly attempting to log in. This is a Denial of Service (DoS)-style attack on authentication systems and could lead to unauthorized access.


### 2. Develop a Comprehensive Security Policy

- [x] **Rules/Guidelines**
  - [x] Define at least **3 security rules or guidelines**
    - _(e.g., password policies, access control, patch management)_

- [x] **Incident Response Plan**
  - [x] Include a step-by-step response plan for a security breach

- [x] **CIA Triad**
  - [x]  Explain how the policy helps maintain:
    - [x] **Confidentiality**
    - [x] **Integrity**
    - [x] **Availability**

---

#### Rules / Guidelines

  - Password Policy:
    - All user passwords must meet complexity requirements (min 12 characters, upper/lowercase, number, symbol).

  - Account Lockout Policy:
    - Accounts lock after 5 failed login attempts within 15 minutes.

  - Patch Management:
    - Systems and software must be updated monthly and after any critical security bulletin.

#### Incident Response Plan (Step-by-Step)

  - Detect suspicious login patterns (via SIEM or logs).

  - Alert the SOC team for triage.

  - Contain by blocking IP and isolating system.

  - Eradicate by removing malicious access vectors.

  - Recover services and monitor.

  - Document findings and update playbooks.

#### CIA Triad Alignment

  - Confidentiality: Enforcing strong access control and encryption of FTP data in transit.

  - Integrity: Logging and verifying authentication attempts, detecting tampering.

  - Availability: Blocking brute-force attempts prevents service disruption and maintains uptime.

### 3. Apply Encryption Techniques

- [x] **Symmetric Encryption**
  - [x] Show an example of:
    - [x] Encrypted text (e.g., AES)
    - [x] Decrypted plain text using the same method

- [x] **Hashing**
  - [x] Hash a sample string using a standard algorithm:
    - [x] MD5 **or** SHA-1 / SHA-256

---

#### Symmetric Encryption

- What It Is:

  - Symmetric encryption uses a single secret key to both encrypt and decrypt data.

  - The sender and receiver must both know the secret key in advance.

  - Example algorithms: AES (Advanced Encryption Standard), DES, Blowfish.

#### Encryption and Decryption Code Example

``` python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Generate a 128-bit AES encryption key (16 bytes).
# AES also supports 192-bit and 256-bit keys (24 and 32 bytes respectively).
key = get_random_bytes(16)

# Initialize the AES cipher in EAX mode, which provides both confidentiality and integrity.
cipher = AES.new(key, AES.MODE_EAX)

# Define the plaintext to be encrypted (must be in bytes).
plaintext = b"Hello world!"

# Encrypt the plaintext and generate an authentication tag.
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

# Output encrypted values for reference.
print("Original Unencrypted Message: ", plaintext)
print("Encrypted message (ciphertext):", ciphertext)
print("Authentication tag:", tag)
print("Nonce:", cipher.nonce)

# --- Decryption Phase ---

# Reinitialize the cipher using the same key and nonce used during encryption.
cipher_dec = AES.new(key, AES.MODE_EAX, nonce=cipher.nonce)

# Decrypt the ciphertext and verify its integrity using the authentication tag.
decrypted = cipher_dec.decrypt_and_verify(ciphertext, tag)

# Output the decrypted plaintext.
print("Decrypted message (plaintext):", decrypted.decode())
```

Using Python we can create a simple script which will encrypt a plain text variable in bytes, using the imported module `pip install pycryptodome`. From here we can encrypt our plain text which is `Hello World`.

Within the script we generate a 16 byte AES Encryption Key which intializes a cipher to secure our plain text through encryption for safe data traversing. 

Using the `authentication tag` also known as `MAC-  "Message Authentication Code"`, and our unique generated `nonce` we can verify the data was not alterted mid data stream. Also the unique nonce is used to decrypt the encrypted text. 

#### AES Script Output

``` python
Original Unencrypted Message:  b'Hello world!'
Encrypted message (ciphertext): b'\x89\x9d\xc4\xc1*\x04\xcc\xe9\xc6\xad\x8b\xed'
Authentication tag: b'\x95\xf7hO\x97?$o\xc4\xcb\xff\x02\xb5>#a'
Nonce: b'\x10sK\xfe\x1f\xc9\xf6\xc96<\xbds\xbd\xa4\x17s'
Decrypted message (plaintext): Hello world!
```

#### Hashing


#### Hashing Code Example

``` python

import hashlib  # Standard Python library for hashing functions

# Define the input data to be hashed.
# This can be any string – e.g., a password, file contents, or message.
input_data = "FTPadmin123"

# Convert the input string to bytes.
# Hashing functions require byte input, not plain strings.
encoded_data = input_data.encode()

# Create a SHA-256 hash object and update it with the byte-encoded input.
# The hashing algorithm processes the data internally.
hash_object = hashlib.sha256(encoded_data)

# Retrieve the final hash value as a hexadecimal string.
# The hexdigest() method returns the result in readable format (64 characters for SHA-256).
hashed_output = hash_object.hexdigest()

# Output the resulting hash.
# This value is deterministic: the same input will always produce the same hash.
print("Original input:", input_data)
print("SHA-256 hash:  ", hashed_output)

```

using `import hashlib` we can use python to create a simple script for creating unuqie hashes, in this case we used a SHA-256 Hash. This cannot be reversed, and is used best for password storage, digital signitures, and file integrity checks. The length will always be a 64 character hexadecimal string (256 bits = 32 bytes) 

#### Script Output

``` python

Original input: FTPadmin123
SHA-256 hash:   e7d92064a873b4405d4666b3979b36a2e36921ab899e432d7e4009f10fd93023

```

### 4. Demonstrate Legal and Ethical Compliance

- [x] **Legal Compliance**
  - [x] Identify **at least 2 relevant laws/regulations**, such as:
    - HIPAA, GDPR, CCPA, FISMA, etc.
  - [x] Explain how your incident response plan addresses these laws

- [x] **Ethical Considerations**
  - [x] Discuss at least **1 ethical concern**, such as:
    - Data privacy, responsible disclosure, user consent, etc.

- [x] **Alignment with Compliance**
  - [x]  Explain how your plan supports:
    - Legal obligations
    - Ethical responsibilities

---

### Relevant Laws / Regulations

#### Legal Compliance

- Law 1: GDPR (General Data Protection Regulation) – EU

  - Scope: Applies to organizations handling personal data of EU citizens, even if the organization is outside the EU.

  - Key Requirements Relevant to Incident Response:

      - Article 33 – Notification of a personal data breach to the supervisory authority
        Organizations must report a data breach to their supervisory authority within 72 hours if it poses a risk to individual rights and freedoms.

      - Article 34 – Communication of a personal data breach to the data subject
        If the breach is likely to result in high risk to individuals (e.g., compromised credentials), affected users must be notified without undue delay.

  - Incident Response Incorporation:

      - You preserve logs of unauthorized access attempts and investigate whether any personal data (usernames, credentials) were accessed.

      - If user accounts were compromised, you notify impacted users and the Data Protection Authority (DPA).

      - You document the attack, actions taken, and lessons learned to demonstrate accountability (Article 5).

- Law 2: CCPA (California Consumer Privacy Act) – USA

  - Scope: Applies to businesses that collect personal data of California residents.

  - Key Requirements Relevant to Incident Response:

      - Disclosure Requirements: Users have the right to know what personal data is collected and if it was exposed in a breach.

      - Data Security Mandate: Businesses must implement "reasonable security procedures" to protect data.

  - Incident Response Incorporation:

      - Incident response includes access reviews, account audits, and password resets after brute-force attempts.

      - In the event of confirmed account compromise, you provide disclosure to users as required by CCPA.

      - You implement technical safeguards (e.g., encryption, account lockouts) to be considered compliant with CCPA's "reasonable security" clause.


#### Ethical Considerations

- 1. Data Privacy

  - Even during a security incident, analysts must protect the privacy and dignity of users.

  - Ethical handling includes:

      - Reviewing only logs relevant to the attack.

      - Avoiding viewing or sharing sensitive information unless necessary.

      - Avoiding storage of passwords in plaintext.

      - Anonymizing logs for reports unless identification is necessary for remediation.

- 2. Responsible Disclosure

  - If the breach involves third-party systems or software (e.g., vulnerabilities in FTP software), you should:

      - Disclose responsibly to the software vendor.

      - Avoid public disclosure until the issue is patched.

      - Provide enough technical detail to help them address the issue without revealing exploit instructions.

- 3. User Consent and Transparency

  - If monitoring tools (like Wazuh) collect user behavior data, transparency is key:

      - Inform users (employees) of security monitoring in your organization's security policy or onboarding materials.

      - Limit intrusion and surveillance to only what is necessary for security.


#### Alignment with Compliance

| Area                         | How the Plan Supports It                                                                                                  |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **Legal Obligations**        | Tracks IPs, failed logins, and user accounts; maintains a timeline of events; ensures breach reporting and documentation. |
| **Ethical Responsibilities** | Avoids unnecessary data exposure, anonymizes logs in reports, and follows responsible disclosure practices.               |
| **Security by Design**       | Promotes strong authentication, encryption of data in transit, and continuous monitoring as proactive measures.           |
