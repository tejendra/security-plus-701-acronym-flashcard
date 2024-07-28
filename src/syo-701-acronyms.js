const list = [
  {
    "acronym": "AAA",
    "fullform": "Authentication, Authorization, and Accounting",
    "definition": "is a security framework that manages user access to computer resources, enforces policies, and audits usage. It's a crucial part of network security and is used in a variety of scenarios, including accessing a private corporate network remotely, using a wireless hotspot, and enforcing network segmentation."
  },
  {
    "acronym": "ACL",
    "fullform": "Access Control List",
    "definition": "are used for controlling permissions to a computer system or computer network. They are used to filter traffic in and out of a specific device. Those devices can be network devices that act as network gateways or endpoint devices that users access directly."
  },
  {
    "acronym": "AES (AES-256)",
    "fullform": "Advanced Encryption Standard (256-bit)",
    "definition": "is a symmetric block cipher that can encrypt (encipher) and decrypt (decipher) information. AES 256-bit encryption is the strongest and most robust encryption standard that is commercially available today. There is also AES 128-bit encryption which is easier to crack then AES 256-bit encryption but it has never been cracked."
  },
  {
    "acronym": "AH",
    "fullform": "Authenication Header",
    "definition": "provides data origin authentication, data integrity, and replay protection. However, AH does not provide data confidentiality, which means that all of your data is sent in the clear. The authentication header (AH) is an Internet Protocol security (IPsec) suite component."
  },
  {
    "acronym": "AI",
    "fullform": "Artificial Intelligence",
    "definition": "is the science of making machines that can think like humans."
  },
  {
    "acronym": "AIS",
    "fullform": "Automated Indicator Sharing",
    "definition": "is a service the Cybersecurity and Infrastructure Security Agency (CISA) provides to enable real-time exchange of machine-readable cyber threat indicators and defensive measures between public and private-sector organizations."
  },
  {
    "acronym": "ALE",
    "fullform": "Annualized Loss Expectancy",
    "definition": "is a quantitative metric that estimates the yearly cost of a risk over a specific period of time. It's calculated by multiplying the annual rate of occurrence (ARO) by the single loss expectancy (SLE): ALE = ARO x SLE."
  },
  {
    "acronym": "AP",
    "fullform": "Access Point",
    "definition": "is a term used for a network device that bridges wired and wireless networks."
  },
  {
    "acronym": "API",
    "fullform": "Application Programming Interface",
    "definition": "is a software intermediary that allows two applications to communicate with each other."
  },
  {
    "acronym": "APT",
    "fullform": "Advanced Persistent Thread",
    "definition": "is a stealthy cyberattack that involves an adversary gaining unauthorized access to a computer network and remaining undetected for an extended period of time. APTs are often carried out by well-funded nation-state cybercriminal groups or organized crime gangs, but can also be non-state-sponsored groups."
  },
  {
    "acronym": "ARO",
    "fullform": "Annualized Rate of Occurrence",
    "definition": "is the number of times per year that an incident is likely to occur. Knowing the adversaries' intent, capability, and motivation will help determine the ARO. f a serious fire is likely to happen once every 25 years, then the ARO is 1/25, or 0.04. ARO = Incidents / Years."
  },
  {
    "acronym": "ARP",
    "fullform": "Address Resolution Protocol",
    "definition": "is used to map IP addresses to MAC addresses. ARP inspection is used to protect a network from ARP attacks. An ARP attack, also known as ARP spoofing or ARP poisoning, is a cyberattack that allows hackers to intercept communication between devices on a local area network (LAN). The goal is to trick one device into sending messages to the attacker instead of the intended recipient, giving the attacker access to sensitive data like passwords and credit card information."
  },
  {
    "acronym": "ASLR",
    "fullform": "Address Space Layout Randomization",
    "definition": "a computer security technique that makes it harder for hackers to exploit memory corruption vulnerabilities in systems. ASLR does this by randomly placing system executables, libraries, and memory stacks in the system's memory. It is a memory protection measure for OS that secures buffer overflow attacks by haphazardly choosing where framework executable records are put away in memory. This makes it difficult for hackers to predict the location of important data or executables, and therefore harder for them to take control of the system or exploit data. If an attacker attempts to exploit an incorrect address space location, the target application will crash, stopping the attack and alerting the system."
  },
  {
    "acronym": "ATT&CK",
    "fullform": "Adversarial Tactics, Techniques and Common Knowledge",
    "definition": "is a framework that helps organizations understand cyber adversaries' tactics and techniques, and how to detect or stop them. It's a globally accessible knowledge base that's based on real-world observations and documentation, and it's used by the private sector, governments, and the cybersecurity community."
  },
  {
    "acronym": "AUP",
    "fullform": "Acceptable Use Policy",
    "definition": "governs employee computer and internet use in the workplace. It's similar to a code of conduct for the digital realm."
  },
  {
    "acronym": "AV",
    "fullform": "Antivirus",
    "definition": "software, also known as anti-malware, used to prevent, detect, and remove malware."
  },
  {
    "acronym": "BASH",
    "fullform": "Bourne Again Shell",
    "definition": ""
  },
  {
    "acronym": "BCP",
    "fullform": "Business Continuity Planning",
    "definition": "is a disaster recovery strategy that helps companies plan for recovering their entire business processes. This includes resources like workspaces, servers, applications, and network connections. The four P’s of business continuity are people, processes, premises, and providers: People - This covers your staff, customers and clients. Processes - This includes the technology and strategies your business uses to keep everything running. Premises - Covers the buildings and spaces from which your business operates. Providers - This includes parties that your business relies on for getting resources, like your suppliers and partners."
  },
  {
    "acronym": "BGP",
    "fullform": "Border Gateway Protocol",
    "definition": "is the protocol that enables the global routing system of the internet. It manages how packets get routed from network to network by exchanging routing and reachability information among edge routers."
  },
  {
    "acronym": "BIA",
    "fullform": "Business Impact Analysis",
    "definition": "predicts the consequences of a disruption to your business, and gathers information needed to develop recovery strategies."
  },
  {
    "acronym": "BIOS",
    "fullform": "Basic Input/Output System",
    "definition": "is the program a computer's microprocessor uses to start the computer system after it is powered on. It also manages data flow between the computer's operating system (OS) and attached devices, such as the hard disk, video adapter, keyboard, mouse and printer."
  },
  {
    "acronym": "BPA",
    "fullform": "Business Partners Agreement",
    "definition": "is a legal agreement between entities establishing the terms, conditions, and expectations of the relationship between the entities. Organizations that have longer term and broader relationships may create a Business Partners Agreement."
  },
  {
    "acronym": "BPDU",
    "fullform": "Bridge Protocol Data Unit",
    "definition": "are the messages that are transmitted across LAN networks to enable switches to participate in Spanning Tree Protocol (STP) by gathering information about each other. It contains information regarding switch ports such as port ID, port priority, port cost, and MAC addresses. BPDUs are a fundamental component of STP, which is a network protocol that prevents loops in Ethernet networks that can lead to broadcast storms and network instability."
  },
  {
    "acronym": "BYOD",
    "fullform": "Bring Your Own Device",
    "definition": "is a policy when an organization decides to allow or require employees to use personal devices for work-related activities. BYOD policies range from enabling remote tools on personal mobile phones to requiring employees to provide their own laptop or computer."
  },
  {
    "acronym": "CA",
    "fullform": "Certificate Authority",
    "definition": "is a trusted third party that issues digital certificates to verify the authenticity of online identities. These certificates are used to enable secure communication and transactions, and to validate the digital identity of websites, email addresses, companies, or individuals."
  },
  {
    "acronym": "CAPTCHA",
    "fullform": "Completely Automated Public Turing test to tell Computers and Humans Apart",
    "definition": ""
  },
  {
    "acronym": "CAR",
    "fullform": "Corrective Action Report",
    "definition": "is a document that details the activities taken to address and remedy a recognized problem or nonconformity within an organization. It is a methodical technique to determine the core cause of an issue and devise a strategy to prevent its recurrence in the future."
  },
  {
    "acronym": "CASB",
    "fullform": "Cloud Access Security Broker",
    "definition": "is an on-premises or cloud-based security policy enforcement point that is placed between cloud service consumers and cloud service providers. CASBs enforce an organization's security policies for cloud application access and usage. They can combine multiple security policies, such as authentication, encryption, malware detection, and more. CASBs can also help ensure compliance with industry data regulations, such as HIPAA, PCI, FFIEC, and FINRA."
  },
  {
    "acronym": "CBC",
    "fullform": "Cipher Block Chaining",
    "definition": "is a process used to encrypt and decrypt large plaintext inputs by creating a cryptographic chain wherein each ciphertext block is dependent on the last. In CBC mode, each block of plaintext is XORed with the previous ciphertext block before being encrypted."
  },
  {
    "acronym": "CCMP",
    "fullform": "Counter Mode/CBC-MAC Protocol",
    "definition": "is a encryption protocol based on the Advanced Encryption Standard (AES) encryption algorithm using the Counter Mode with CBC-MAC (CCM) mode of operation. It is an encryption protocol that forms part of the 802.11i standard for wireless local area networks (WLANs). The CCM mode combines Counter Mode (CTR) for confidentiality and Cipher Block Chaining Message Authentication Code (CBC-MAC) for authentication and integrity. CCMP offers enhanced security compared with similar technologies such as Temporal Key Integrity Protocol (TKIP)."
  },
  {
    "acronym": "CCTV",
    "fullform": "Closed-circuit Television",
    "definition": ""
  },
  {
    "acronym": "CERT",
    "fullform": "Computer Emergency Response Team",
    "definition": "is a group of information security experts who protect organizations from computer, network, or cybersecurity issues. Their mission is to contain computer security incidents, minimize their impact on the organization's operations and reputation. Also referred to as CIRT (Computer Incident Response Team) or CIRC (Computer Incident Response Center)"
  },
  {
    "acronym": "CFB",
    "fullform": "Cipher Feedback",
    "definition": "is an AES block cipher mode similar to Cipher Block Chaining (CBC). It uses an initialization vector and it uses the cipher from the previous block. The main difference is that with CFB, the ciphertext block from the previous block is encrypted first, and then XORed with the current block."
  },
  {
    "acronym": "CHAP",
    "fullform": "Challenge Handshake Authentication Protocol",
    "definition": "is a peer authentication protocol that verifies a client's identity using a challenge-response method. CHAP is based on a shared secret between the client and server, and it doesn't expose passwords. The protocol is used in other authentication protocols, such as RADIUS and Diameter. It is a challenge and response authentication method used in Point-to-Point Protocol (PPP) servers. The purpose is to verify the identity of a remote user accessing the network."
  },
  {
    "acronym": "CIA",
    "fullform": "Confidentiality, Integrity, Availability",
    "definition": "The CIA triad is a model in information security that guides organizations in establishing security policies and procedures. Confidentiality protects information from unauthorized access and disclosure, including personal privacy and proprietary information. Integrity ensures that information is accurate, complete, and trustworthy, and that it hasn't been modified or destroyed by an unauthorized user. Availability ensures that information is accessible and usable when needed, without affecting its confidentiality or integrity."
  },
  {
    "acronym": "CIO",
    "fullform": "Chief Information Officer",
    "definition": ""
  },
  {
    "acronym": "CIRT",
    "fullform": "Computer Incident Response Team",
    "definition": "The terms CIRT, CERT (Computer Emergency Response Team), and CIRC (Computer Incident Response Center) are often used interchangeably. All of them indicate cyber incident response teams working towards the same goal of responding to and investigating computer security incidents and mitigating their consequences."
  },
  {
    "acronym": "CMS",
    "fullform": "Content Management System",
    "definition": "are often used to manage websites and can help organizations keep their sites online and update the user-side portion of the site easily and consistently. Content in a CMS is usually stored in a database and displayed in a presentation layer based on templates."
  },
  {
    "acronym": "COOP",
    "fullform": "Continuity of Operation Planning",
    "definition": "A predetermined set of instructions or procedures that describe how an organization’s mission-essential functions will be sustained within 12 hours and for up to 30 days as a result of a disaster event before returning to normal operations."
  },
  {
    "acronym": "COPE",
    "fullform": "Corporate Owned, Personally Enabled",
    "definition": "business model in which an organization provides its employees with mobile devices that are owned by a company and provided to employees for both work and personal use. COPE devices allow employees to install applications on the devices, but organizations can also install their own applications. A COPE model can also be used to improve morale and build a strong corporate identity. COPE models have better data storage security features than BYOD models because the devices are uniform. This means it's quick to onboard new employees, new records and easier to deploy MDM solutions."
  },
  {
    "acronym": "CP",
    "fullform": "Contingency Planning",
    "definition": "is a proactive approach that helps organizations prepare for potential emergencies by creating strategies to mitigate risks in advance. It's an important part of ensuring the security and availability of an organization's information systems."
  },
  {
    "acronym": "CRC",
    "fullform": "Cyclical Redundancy Check",
    "definition": "is a mathematical technique that provides a way to detect errors in transmitted data by appending a special code, called a checksum, to the original information. This checksum is then recalculated at the receiving end to verify the integrity of the data."
  },
  {
    "acronym": "CRL",
    "fullform": "Certification Revocation List",
    "definition": "is a list of digital certificates that a certificate authority (CA) has revoked before their scheduled expiration date or have been marked as temporarily invalid (hold). The CRL does not include expired certificates. CRLs are made public so that anyone can verify if a certificate used to sign a message is valid. the CRL issuer (third party) may not be the same entity as the CA that issued the revoked certificate."
  },
  {
    "acronym": "CSO",
    "fullform": "Chief Security Officer",
    "definition": ""
  },
  {
    "acronym": "CSP",
    "fullform": "Cloud Service Provider",
    "definition": "is a company that offers components of cloud computing such as infrastructure as a service (IaaS), software as a service (SaaS) or platform as a service (PaaS)."
  },
  {
    "acronym": "CSR",
    "fullform": "Certificate Signing Request",
    "definition": "is one of the first steps towards getting your own SSL/TLS certificate. The CA will use the data from the CSR to build your SSL Certificate. The key pieces of information include the following: Common Name (CN), Organization (O), Organizational Unit (OU), City/Locality (L), State/County/Region (S), Country (C), and Email Address."
  },
  {
    "acronym": "CSRF",
    "fullform": "Cross-site Request Forgery",
    "definition": "is a cyber attack that tricks a user into performing actions on a website or web application using their credentials without their consent."
  },
  {
    "acronym": "CSU",
    "fullform": "Channel Service Unit",
    "definition": "is a hardware device that converts a digital data frame from the communications technology used on a local area network (LAN) into a frame appropriate to a wide-area network (WAN) and vice versa. If you have a Web business from your own home and have leased a digital line (perhaps a T-1 or fractional T-1 line) to a phone company or a gateway at an Internet service provider, you have a CSU/DSU at your end, and the phone company or gateway host has a CSU/DSU at its end, and the units at both ends must be set to the same communications standard."
  },
  {
    "acronym": "CTM / CTR",
    "fullform": "Counter Mode",
    "definition": "is a block cipher mode that acts like a stream cipher compared to CBC and CFB which are fixed-size blocks. This is another way to encrypt data."
  },
  {
    "acronym": "CTO",
    "fullform": "Chief Technology Officer",
    "definition": ""
  },
  {
    "acronym": "CVE",
    "fullform": "Common Vulnerability Enumeration",
    "definition": "is a standardized list of known cybersecurity vulnerabilities that's publicly available for sharing. The goal of CVE is to help organizations and security researchers communicate and share information about vulnerabilities, and their potential effects."
  },
  {
    "acronym": "CVSS",
    "fullform": "Common Vulnerability Scoring System",
    "definition": "attempts to assign severity scores to vulnerabilities, allowing responders to prioritize responses and resources according to threat. Scores are calculated based on a formula that depends on several metrics that approximate ease and impact of an exploit. Scores range from 0 to 10, with 10 being the most severe."
  },
  {
    "acronym": "CYOD",
    "fullform": "Choose Your Own Device",
    "definition": "business model in which an organization allows its employees to select a device from a list of company-approved options for work purposes."
  },
  {
    "acronym": "DAC",
    "fullform": "Discretionary Access Control",
    "definition": "is an access policy that allows the owner of an object to control who has access to it and what level of access they have."
  },
  {
    "acronym": "DBA",
    "fullform": "Database Administrator",
    "definition": "is responsible for maintaining, securing, and operating databases and also ensures that data is correctly stored and retrieved."
  },
  {
    "acronym": "DDoS",
    "fullform": "Distributed Denial of Service",
    "definition": "is a type of DoS attack that comes from many distributed sources, such as a botnet DDoS attack. It is designed to force a website, computer, or online service offline. This is accomplished by flooding the target with many requests, consuming its capacity and rendering it unable to respond to legitimate requests"
  },
  {
    "acronym": "DEP",
    "fullform": "Data Execution Prevention",
    "definition": "is a technology built into Windows that helps protect you from executable code launching from places it's not supposed to. It prevents code from being run from data pages such as the default heap, stacks, and memory pools."
  },
  {
    "acronym": "DES",
    "fullform": "Digital Encryption Standard",
    "definition": "is an outdated, symmetric-key algorithm."
  },
  {
    "acronym": "DHCP",
    "fullform": "Dynamic Host COnfiguration Protocol",
    "definition": "is a network management protocol that automatically assigns IP addresses and other communication parameters to devices connected to a network. It provides better fault tolerance than static IP allocation by allowing for redundancy and failover mechanisms."
  },
  {
    "acronym": "DHE",
    "fullform": "Diffie-Hellman Ephemeral",
    "definition": "The Diffie–Hellman key exchange method allows two parties that have no prior knowledge of each other to jointly establish a shared secret key over an insecure channel. When a key exchange uses Ephemeral Diffie-Hellman a temporary DH key is generated for every connection and thus the same key is never used twice. This enables Forward Secrecy (FS), which means that if the long-term private key of the server gets leaked, past communication is still secure."
  },
  {
    "acronym": "DKIM",
    "fullform": "DomainKeys Identified Mail",
    "definition": "is an email authentication method that uses a digital signature to let the receiver of an email know that the message was sent and authorized by the owner of a domain. DKIM can function independently, but it's often used with DMARC for a more comprehensive solution."
  },
  {
    "acronym": "DLL",
    "fullform": "Dynamic Link Library",
    "definition": "is a collection of small programs that larger programs can load when needed to complete specific tasks. DLL hijacking is a method of injecting malicious code into an application by exploiting the way some Windows applications search and load Dynamic Link Libraries (DLL)."
  },
  {
    "acronym": "DLP",
    "fullform": "Data Loss Prevention",
    "definition": "is a security strategy that helps organizations detect and prevent data breaches, exfiltration, or unwanted destruction of sensitive data. Organizations use DLP to protect and secure their data and comply with regulations."
  },
  {
    "acronym": "DMARC",
    "fullform": "Domain-based Message Authentication, Reporting, and Conformance",
    "definition": "is an email authentication protocol that helps protect email domains from unauthorized use, also known as email spoofing. Informs mail servers how to respond to emails that fail DKIM or SPF (Sender Policy Framework) checks. DMARC can instruct mail servers to mark failing emails as spam, deliver them anyway, or drop them. DMARC also provides reporting mechanisms."
  },
  {
    "acronym": "DNAT",
    "fullform": "Destination Network Address Translation",
    "definition": "is performed on incoming packets when the firewall translates a destination address to a different destination address; for example, it translates a public destination address to a private destination address. Destination NAT also offers the option to perform port forwarding or port translation."
  },
  {
    "acronym": "DNS",
    "fullform": "Domain Name System",
    "definition": "is a key part of the internet's infrastructure that translates domain names into IP addresses. DNS flood attack is when attackers send a massive amount of requests to DNS servers at once, which can take down the internet. Cache poisoning inserts malicious IP addresses into the DNS cache, which can redirect users to phishing websites."
  },
  {
    "acronym": "DoS",
    "fullform": "Denial of Service",
    "definition": "is a cyberattack that attempts to overload a network or website to make it inaccessible or degrade its performance."
  },
  {
    "acronym": "DPO",
    "fullform": "Data Privacy Officer",
    "definition": "is an independent company official who ensures that an organization complies with data protection laws and regulations."
  },
  {
    "acronym": "DRP",
    "fullform": "Disaster Recovery Plan",
    "definition": "is a formal document that outlines how an organization will respond to an unplanned incident and resume business operations. A DRP is an essential part of a business continuity plan (BCP)."
  },
  {
    "acronym": "DSA",
    "fullform": "Digital Signature Algorithm",
    "definition": "is a public-key cryptographic algorithm used to generate digital signatures, authenticate the sender of a digital message, and prevent message tampering."
  },
  {
    "acronym": "DSL",
    "fullform": "Digital Subscriber Line",
    "definition": "is a modem technology that uses existing telephone lines to transport high-bandwidth data, such as multimedia and video, to service subscribers. DSL provides dedicated, point-to-point, public network access."
  },
  {
    "acronym": "EAP",
    "fullform": "Entensible Authentication Protocol",
    "definition": "is an authentication framework, not a specific authentication mechanism. It is used to pass the authentication information between the supplicant (the Wi-Fi workstation) and the authentication server (Microsoft IAS or other). The EAP type actually handles and defines the authentication."
  },
  {
    "acronym": "ECB",
    "fullform": "Electronic Code Book",
    "definition": "a simple mode of operation for a block cipher, mostly used with symmetric key encryption, where each plaintext block has a corresponding ciphertext value. The plaintext is broken into blocks of a given size (128 bits in this case), and the encryption algorithm is run on each block of plaintext individually. The weakness of this encryption mode is that it's possible to see patterns in the ciphertext."
  },
  {
    "acronym": "ECC",
    "fullform": "Elliptic Curve Cryptography",
    "definition": "is a public-key cryptography algorithm that uses elliptic curve theory to generate keys and perform security functions. ECC provides greater cryptographic strength with shorter key lengths, making it ideal for devices with limited computing power."
  },
  {
    "acronym": "ECDHE",
    "fullform": "Elliptic Curve Diffie-Hellman Ephemeral",
    "definition": "is a key exchange algorithm that allows two parties to establish a shared secret over an insecure communication channel. It is a variant of the Diffie-Hellman key exchange that uses elliptic curve cryptography to provide stronger security with smaller key sizes. A distinct key for every exchange is used allowing for perfect forward secrecy."
  },
  {
    "acronym": "ECDSA",
    "fullform": "Elliptic Curve Digital Signature Algorithm",
    "definition": "is a public key cryptography encryption algorithm that uses elliptic curve cryptography (ECC) to generate keys, sign, authenticate, and verify messages. ECDSA is a variation of the Digital Signature Algorithm (DSA) that's more efficient because it requires smaller keys to provide the same level of security."
  },
  {
    "acronym": "EDR",
    "fullform": "Endpoint Detection and Response",
    "definition": "is a cybersecurity technology that monitors endpoints for threats and responds to them. EDR can help protect networks by: Containing threats, Preventing threats from spreading, and Rolling back damage caused by threats. An EDR solution isolates threats and automatically blocks any IOCs upon detecting any malicious activity."
  },
  {
    "acronym": "EFS",
    "fullform": "Encrypted File System",
    "definition": "is a user-based encryption control technique that enables users to control who can read the files on their system. The typical method of using EFS is to perform encryption at the folder level. This ensures that all files added to the encrypted folder are automatically encrypted."
  },
  {
    "acronym": "ERP",
    "fullform": "Enterprise Resource Planning",
    "definition": "is a category of business software that automates business processes and provides insights and internal controls, drawing on a central database that collects inputs from departments including accounting, manufacturing, supply chain management, sales, marketing and human resources (HR)."
  },
  {
    "acronym": "ESN",
    "fullform": "Electronic Serial Number",
    "definition": "created by FCC to uniquely identifies mobile devices."
  },
  {
    "acronym": "ESP",
    "fullform": "Encapsulated Security Payload",
    "definition": "is a security protocol that protects data sent across networks by providing confidentiality, integrity, and authenticity. ESP is part of the Internet Protocol Security (IPsec) protocol suite."
  }
];

export default list;