const list = [
  {
    "acronym": "AAA",
    "fullform": "Authentication, Authorization, and Accounting",
    "definition": "is a security framework that manages user access to computer resources, enforces policies, and audits usage. It's a crucial part of network security and is used in a variety of scenarios, including accessing a private corporate network remotely, using a wireless hotspot, and enforcing network segmentation.",
    "category": "Security"
  },
  {
    "acronym": "ACL",
    "fullform": "Access Control List",
    "definition": "are used for controlling permissions to a computer system or computer network. They are used to filter traffic in and out of a specific device. Those devices can be network devices that act as network gateways or endpoint devices that users access directly.",
    "category": "Security"
  },
  {
    "acronym": "AES (AES-256)",
    "fullform": "Advanced Encryption Standard (256-bit)",
    "definition": "is a symmetric block cipher that can encrypt (encipher) and decrypt (decipher) information. AES 256-bit encryption is the strongest and most robust encryption standard that is commercially available today. There is also AES 128-bit encryption which is easier to crack then AES 256-bit encryption but it has never been cracked.",
    "category": "Security"
  },
  {
    "acronym": "AH",
    "fullform": "Authenication Header",
    "definition": "provides data origin authentication, data integrity, and replay protection. However, AH does not provide data confidentiality, which means that all of your data is sent in the clear. The authentication header (AH) is an Internet Protocol security (IPsec) suite component.",
    "category": "Networking"
  },
  {
    "acronym": "AI",
    "fullform": "Artificial Intelligence",
    "definition": "is the science of making machines that can think like humans.",
    "category": "Computing"
  },
  {
    "acronym": "AIS",
    "fullform": "Automated Indicator Sharing",
    "definition": "is a service the Cybersecurity and Infrastructure Security Agency (CISA) provides to enable real-time exchange of machine-readable cyber threat indicators and defensive measures between public and private-sector organizations.",
    "category": "Security"
  },
  {
    "acronym": "ALE",
    "fullform": "Annualized Loss Expectancy",
    "definition": "is a quantitative metric that estimates the yearly cost of a risk over a specific period of time. It's calculated by multiplying the annual rate of occurrence (ARO) by the single loss expectancy (SLE): ALE = ARO x SLE.",
    "category": "Security"
  },
  {
    "acronym": "AP",
    "fullform": "Access Point",
    "definition": "is a term used for a network device that bridges wired and wireless networks.",
    "category": "Networking"
  },
  {
    "acronym": "API",
    "fullform": "Application Programming Interface",
    "definition": "is a software intermediary that allows two applications to communicate with each other.",
    "category": "Computing"
  },
  {
    "acronym": "APT",
    "fullform": "Advanced Persistent Thread",
    "definition": "is a stealthy cyberattack that involves an adversary gaining unauthorized access to a computer network and remaining undetected for an extended period of time. APTs are often carried out by well-funded nation-state cybercriminal groups or organized crime gangs, but can also be non-state-sponsored groups.",
    "category": "Security"
  },
  {
    "acronym": "ARO",
    "fullform": "Annualized Rate of Occurrence",
    "definition": "is the number of times per year that an incident is likely to occur. Knowing the adversaries' intent, capability, and motivation will help determine the ARO. f a serious fire is likely to happen once every 25 years, then the ARO is 1/25, or 0.04. ARO = Incidents / Years.",
    "category": "Security"
  },
  {
    "acronym": "ARP",
    "fullform": "Address Resolution Protocol",
    "definition": "is used to map IP addresses to MAC addresses. ARP inspection is used to protect a network from ARP attacks. An ARP attack, also known as ARP spoofing or ARP poisoning, is a cyberattack that allows hackers to intercept communication between devices on a local area network (LAN). The goal is to trick one device into sending messages to the attacker instead of the intended recipient, giving the attacker access to sensitive data like passwords and credit card information.",
    "category": "Networking"
  },
  {
    "acronym": "ASLR",
    "fullform": "Address Space Layout Randomization",
    "definition": "a computer security technique that makes it harder for hackers to exploit memory corruption vulnerabilities in systems. ASLR does this by randomly placing system executables, libraries, and memory stacks in the system's memory. It is a memory protection measure for OS that secures buffer overflow attacks by haphazardly choosing where framework executable records are put away in memory. This makes it difficult for hackers to predict the location of important data or executables, and therefore harder for them to take control of the system or exploit data. If an attacker attempts to exploit an incorrect address space location, the target application will crash, stopping the attack and alerting the system.",
    "category": "Security"
  },
  {
    "acronym": "ATT&CK",
    "fullform": "Adversarial Tactics, Techniques and Common Knowledge",
    "definition": "is a framework that helps organizations understand cyber adversaries' tactics and techniques, and how to detect or stop them. It's a globally accessible knowledge base that's based on real-world observations and documentation, and it's used by the private sector, governments, and the cybersecurity community.",
    "category": "Security"
  },
  {
    "acronym": "AUP",
    "fullform": "Acceptable Use Policy",
    "definition": "governs employee computer and internet use in the workplace. It's similar to a code of conduct for the digital realm.",
    "category": "Security"
  },
  {
    "acronym": "AV",
    "fullform": "Antivirus",
    "definition": "software, also known as anti-malware, used to prevent, detect, and remove malware.",
    "category": "Security"
  },
  {
    "acronym": "BASH",
    "fullform": "Bourne Again Shell",
    "definition": "",
    "category": "Computing"
  },
  {
    "acronym": "BCP",
    "fullform": "Business Continuity Planning",
    "definition": "is a disaster recovery strategy that helps companies plan for recovering their entire business processes. This includes resources like workspaces, servers, applications, and network connections. The four P’s of business continuity are people, processes, premises, and providers: People - This covers your staff, customers and clients. Processes - This includes the technology and strategies your business uses to keep everything running. Premises - Covers the buildings and spaces from which your business operates. Providers - This includes parties that your business relies on for getting resources, like your suppliers and partners.",
    "category": "Business"
  },
  {
    "acronym": "BGP",
    "fullform": "Border Gateway Protocol",
    "definition": "is the protocol that enables the global routing system of the internet. It manages how packets get routed from network to network by exchanging routing and reachability information among edge routers.",
    "category": "Networking"
  },
  {
    "acronym": "BIA",
    "fullform": "Business Impact Analysis",
    "definition": "predicts the consequences of a disruption to your business, and gathers information needed to develop recovery strategies.",
    "category": "Business"
  },
  {
    "acronym": "BIOS",
    "fullform": "Basic Input/Output System",
    "definition": "is the program a computer's microprocessor uses to start the computer system after it is powered on. It also manages data flow between the computer's operating system (OS) and attached devices, such as the hard disk, video adapter, keyboard, mouse and printer.",
    "category": "Computing"
  },
  {
    "acronym": "BPA",
    "fullform": "Business Partners Agreement",
    "definition": "is a legal agreement between entities establishing the terms, conditions, and expectations of the relationship between the entities. Organizations that have longer term and broader relationships may create a Business Partners Agreement.",
    "category": "Business"
  },
  {
    "acronym": "BPDU",
    "fullform": "Bridge Protocol Data Unit",
    "definition": "are the messages that are transmitted across LAN networks to enable switches to participate in Spanning Tree Protocol (STP) by gathering information about each other. It contains information regarding switch ports such as port ID, port priority, port cost, and MAC addresses. BPDUs are a fundamental component of STP, which is a network protocol that prevents loops in Ethernet networks that can lead to broadcast storms and network instability.",
    "category": "Networking"
  },
  {
    "acronym": "BYOD",
    "fullform": "Bring Your Own Device",
    "definition": "is a policy when an organization decides to allow or require employees to use personal devices for work-related activities. BYOD policies range from enabling remote tools on personal mobile phones to requiring employees to provide their own laptop or computer.",
    "category": "Business"
  },
  {
    "acronym": "CA",
    "fullform": "Certificate Authority",
    "definition": "is a trusted third party that issues digital certificates to verify the authenticity of online identities. These certificates are used to enable secure communication and transactions, and to validate the digital identity of websites, email addresses, companies, or individuals.",
    "category": "Security"
  },
  {
    "acronym": "CAPTCHA",
    "fullform": "Completely Automated Public Turing test to tell Computers and Humans Apart",
    "definition": "",
    "category": "Security"
  },
  {
    "acronym": "CAR",
    "fullform": "Corrective Action Report",
    "definition": "is a document that details the activities taken to address and remedy a recognized problem or nonconformity within an organization. It is a methodical technique to determine the core cause of an issue and devise a strategy to prevent its recurrence in the future.",
    "category": "Business"
  },
  {
    "acronym": "CASB",
    "fullform": "Cloud Access Security Broker",
    "definition": "is an on-premises or cloud-based security policy enforcement point that is placed between cloud service consumers and cloud service providers. CASBs enforce an organization's security policies for cloud application access and usage. They can combine multiple security policies, such as authentication, encryption, malware detection, and more. CASBs can also help ensure compliance with industry data regulations, such as HIPAA, PCI, FFIEC, and FINRA.",
    "category": "Security"
  },
  {
    "acronym": "CBC",
    "fullform": "Cipher Block Chaining",
    "definition": "is a process used to encrypt and decrypt large plaintext inputs by creating a cryptographic chain wherein each ciphertext block is dependent on the last. In CBC mode, each block of plaintext is XORed with the previous ciphertext block before being encrypted.",
    "category": "Security"
  },
  {
    "acronym": "CCMP",
    "fullform": "Counter Mode/CBC-MAC Protocol",
    "definition": "is a encryption protocol based on the Advanced Encryption Standard (AES) encryption algorithm using the Counter Mode with CBC-MAC (CCM) mode of operation. It is an encryption protocol that forms part of the 802.11i standard for wireless local area networks (WLANs). The CCM mode combines Counter Mode (CTR) for confidentiality and Cipher Block Chaining Message Authentication Code (CBC-MAC) for authentication and integrity. CCMP offers enhanced security compared with similar technologies such as Temporal Key Integrity Protocol (TKIP).",
    "category": "Security"
  },
  {
    "acronym": "CCTV",
    "fullform": "Closed-circuit Television",
    "definition": "",
    "category": "Security"
  },
  {
    "acronym": "CERT",
    "fullform": "Computer Emergency Response Team",
    "definition": "is a group of information security experts who protect organizations from computer, network, or cybersecurity issues. Their mission is to contain computer security incidents, minimize their impact on the organization's operations and reputation. Also referred to as CIRT (Computer Incident Response Team) or CIRC (Computer Incident Response Center)",
    "category": "Security"
  },
  {
    "acronym": "CFB",
    "fullform": "Cipher Feedback",
    "definition": "is an AES block cipher mode similar to Cipher Block Chaining (CBC). It uses an initialization vector and it uses the cipher from the previous block. The main difference is that with CFB, the ciphertext block from the previous block is encrypted first, and then XORed with the current block.",
    "category": "Security"
  },
  {
    "acronym": "CHAP",
    "fullform": "Challenge Handshake Authentication Protocol",
    "definition": "is a peer authentication protocol that verifies a client's identity using a challenge-response method. CHAP is based on a shared secret between the client and server, and it doesn't expose passwords. The protocol is used in other authentication protocols, such as RADIUS and Diameter. It is a challenge and response authentication method used in Point-to-Point Protocol (PPP) servers. The purpose is to verify the identity of a remote user accessing the network.",
    "category": "Security"
  },
  {
    "acronym": "CIA",
    "fullform": "Confidentiality, Integrity, Availability",
    "definition": "The CIA triad is a model in information security that guides organizations in establishing security policies and procedures. Confidentiality protects information from unauthorized access and disclosure, including personal privacy and proprietary information. Integrity ensures that information is accurate, complete, and trustworthy, and that it hasn't been modified or destroyed by an unauthorized user. Availability ensures that information is accessible and usable when needed, without affecting its confidentiality or integrity.",
    "category": "Security"
  },
  {
    "acronym": "CIO",
    "fullform": "Chief Information Officer",
    "definition": "",
    "category": "Business"
  },
  {
    "acronym": "CIRT",
    "fullform": "Computer Incident Response Team",
    "definition": "The terms CIRT, CERT (Computer Emergency Response Team), and CIRC (Computer Incident Response Center) are often used interchangeably. All of them indicate cyber incident response teams working towards the same goal of responding to and investigating computer security incidents and mitigating their consequences.",
    "category": "Security"
  },
  {
    "acronym": "CMS",
    "fullform": "Content Management System",
    "definition": "are often used to manage websites and can help organizations keep their sites online and update the user-side portion of the site easily and consistently. Content in a CMS is usually stored in a database and displayed in a presentation layer based on templates.",
    "category": "Computing"
  },
  {
    "acronym": "COOP",
    "fullform": "Continuity of Operation Planning",
    "definition": "A predetermined set of instructions or procedures that describe how an organization’s mission-essential functions will be sustained within 12 hours and for up to 30 days as a result of a disaster event before returning to normal operations.",
    "category": "Business"
  },
  {
    "acronym": "COPE",
    "fullform": "Corporate Owned, Personally Enabled",
    "definition": "business model in which an organization provides its employees with mobile devices that are owned by a company and provided to employees for both work and personal use. COPE devices allow employees to install applications on the devices, but organizations can also install their own applications. A COPE model can also be used to improve morale and build a strong corporate identity. COPE models have better data storage security features than BYOD models because the devices are uniform. This means it's quick to onboard new employees, new records and easier to deploy MDM solutions.",
    "category": "Business"
  },
  {
    "acronym": "CP",
    "fullform": "Contingency Planning",
    "definition": "is a proactive approach that helps organizations prepare for potential emergencies by creating strategies to mitigate risks in advance. It's an important part of ensuring the security and availability of an organization's information systems.",
    "category": "Business"
  },
  {
    "acronym": "CRC",
    "fullform": "Cyclical Redundancy Check",
    "definition": "is a mathematical technique that provides a way to detect errors in transmitted data by appending a special code, called a checksum, to the original information. This checksum is then recalculated at the receiving end to verify the integrity of the data.",
    "category": "Computing"
  },
  {
    "acronym": "CRL",
    "fullform": "Certification Revocation List",
    "definition": "is a list of digital certificates that a certificate authority (CA) has revoked before their scheduled expiration date or have been marked as temporarily invalid (hold). The CRL does not include expired certificates. CRLs are made public so that anyone can verify if a certificate used to sign a message is valid. the CRL issuer (third party) may not be the same entity as the CA that issued the revoked certificate.",
    "category": "Security"
  },
  {
    "acronym": "CSO",
    "fullform": "Chief Security Officer",
    "definition": "",
    "category": "Business"
  },
  {
    "acronym": "CSP",
    "fullform": "Cloud Service Provider",
    "definition": "is a company that offers components of cloud computing such as infrastructure as a service (IaaS), software as a service (SaaS) or platform as a service (PaaS).",
    "category": "Computing"
  },
  {
    "acronym": "CSR",
    "fullform": "Certificate Signing Request",
    "definition": "is one of the first steps towards getting your own SSL/TLS certificate. The CA will use the data from the CSR to build your SSL Certificate. The key pieces of information include the following: Common Name (CN), Organization (O), Organizational Unit (OU), City/Locality (L), State/County/Region (S), Country (C), and Email Address.",
    "category": "Security"
  },
  {
    "acronym": "CSRF",
    "fullform": "Cross-site Request Forgery",
    "definition": "is a cyber attack that tricks a user into performing actions on a website or web application using their credentials without their consent.",
    "category": "Security"
  },
  {
    "acronym": "CSU",
    "fullform": "Channel Service Unit",
    "definition": "is a hardware device that converts a digital data frame from the communications technology used on a local area network (LAN) into a frame appropriate to a wide-area network (WAN) and vice versa. If you have a Web business from your own home and have leased a digital line (perhaps a T-1 or fractional T-1 line) to a phone company or a gateway at an Internet service provider, you have a CSU/DSU at your end, and the phone company or gateway host has a CSU/DSU at its end, and the units at both ends must be set to the same communications standard.",
    "category": "Networking"
  },
  {
    "acronym": "CTM / CTR",
    "fullform": "Counter Mode",
    "definition": "is a block cipher mode that acts like a stream cipher compared to CBC and CFB which are fixed-size blocks. This is another way to encrypt data.",
    "category": "Security"
  },
  {
    "acronym": "CTO",
    "fullform": "Chief Technology Officer",
    "definition": "",
    "category": "Business"
  },
  {
    "acronym": "CVE",
    "fullform": "Common Vulnerability Enumeration",
    "definition": "is a standardized list of known cybersecurity vulnerabilities that's publicly available for sharing. The goal of CVE is to help organizations and security researchers communicate and share information about vulnerabilities, and their potential effects.",
    "category": "Security"
  },
  {
    "acronym": "CVSS",
    "fullform": "Common Vulnerability Scoring System",
    "definition": "attempts to assign severity scores to vulnerabilities, allowing responders to prioritize responses and resources according to threat. Scores are calculated based on a formula that depends on several metrics that approximate ease and impact of an exploit. Scores range from 0 to 10, with 10 being the most severe.",
    "category": "Security"
  },
  {
    "acronym": "CYOD",
    "fullform": "Choose Your Own Device",
    "definition": "business model in which an organization allows its employees to select a device from a list of company-approved options for work purposes.",
    "category": "Business"
  },
  {
    "acronym": "DAC",
    "fullform": "Discretionary Access Control",
    "definition": "is an access policy that allows the owner of an object to control who has access to it and what level of access they have.",
    "category": "Security"
  },
  {
    "acronym": "DBA",
    "fullform": "Database Administrator",
    "definition": "is responsible for maintaining, securing, and operating databases and also ensures that data is correctly stored and retrieved.",
    "category": "Computing"
  },
  {
    "acronym": "DDoS",
    "fullform": "Distributed Denial of Service",
    "definition": "is a type of DoS attack that comes from many distributed sources, such as a botnet DDoS attack. It is designed to force a website, computer, or online service offline. This is accomplished by flooding the target with many requests, consuming its capacity and rendering it unable to respond to legitimate requests",
    "category": "Security"
  },
  {
    "acronym": "DEP",
    "fullform": "Data Execution Prevention",
    "definition": "is a technology built into Windows that helps protect you from executable code launching from places it's not supposed to. It prevents code from being run from data pages such as the default heap, stacks, and memory pools.",
    "category": "Security"
  },
  {
    "acronym": "DES",
    "fullform": "Digital Encryption Standard",
    "definition": "is an outdated, symmetric-key algorithm.",
    "category": "Security"
  },
  {
    "acronym": "DHCP",
    "fullform": "Dynamic Host COnfiguration Protocol",
    "definition": "is a network management protocol that automatically assigns IP addresses and other communication parameters to devices connected to a network. It provides better fault tolerance than static IP allocation by allowing for redundancy and failover mechanisms.",
    "category": "Networking"
  },
  {
    "acronym": "DHE",
    "fullform": "Diffie-Hellman Ephemeral",
    "definition": "The Diffie–Hellman key exchange method allows two parties that have no prior knowledge of each other to jointly establish a shared secret key over an insecure channel. When a key exchange uses Ephemeral Diffie-Hellman a temporary DH key is generated for every connection and thus the same key is never used twice. This enables Forward Secrecy (FS), which means that if the long-term private key of the server gets leaked, past communication is still secure.",
    "category": "Security"
  },
  {
    "acronym": "DKIM",
    "fullform": "DomainKeys Identified Mail",
    "definition": "is an email authentication method that uses a digital signature to let the receiver of an email know that the message was sent and authorized by the owner of a domain. DKIM can function independently, but it's often used with DMARC for a more comprehensive solution.",
    "category": "Security"
  },
  {
    "acronym": "DLL",
    "fullform": "Dynamic Link Library",
    "definition": "is a collection of small programs that larger programs can load when needed to complete specific tasks. DLL hijacking is a method of injecting malicious code into an application by exploiting the way some Windows applications search and load Dynamic Link Libraries (DLL).",
    "category": "Computing"
  },
  {
    "acronym": "DLP",
    "fullform": "Data Loss Prevention",
    "definition": "is a security strategy that helps organizations detect and prevent data breaches, exfiltration, or unwanted destruction of sensitive data. Organizations use DLP to protect and secure their data and comply with regulations.",
    "category": "Security"
  },
  {
    "acronym": "DMARC",
    "fullform": "Domain-based Message Authentication, Reporting, and Conformance",
    "definition": "is an email authentication protocol that helps protect email domains from unauthorized use, also known as email spoofing. Informs mail servers how to respond to emails that fail DKIM or SPF (Sender Policy Framework) checks. DMARC can instruct mail servers to mark failing emails as spam, deliver them anyway, or drop them. DMARC also provides reporting mechanisms.",
    "category": "Security"
  },
  {
    "acronym": "DNAT",
    "fullform": "Destination Network Address Translation",
    "definition": "is performed on incoming packets when the firewall translates a destination address to a different destination address; for example, it translates a public destination address to a private destination address. Destination NAT also offers the option to perform port forwarding or port translation.",
    "category": "Networking"
  },
  {
    "acronym": "DNS",
    "fullform": "Domain Name System",
    "definition": "is a key part of the internet's infrastructure that translates domain names into IP addresses. DNS flood attack is when attackers send a massive amount of requests to DNS servers at once, which can take down the internet. Cache poisoning inserts malicious IP addresses into the DNS cache, which can redirect users to phishing websites.",
    "category": "Networking"
  },
  {
    "acronym": "DoS",
    "fullform": "Denial of Service",
    "definition": "is a cyberattack that attempts to overload a network or website to make it inaccessible or degrade its performance.",
    "category": "Security"
  },
  {
    "acronym": "DPO",
    "fullform": "Data Privacy Officer",
    "definition": "is an independent company official who ensures that an organization complies with data protection laws and regulations.",
    "category": "Business"
  },
  {
    "acronym": "DRP",
    "fullform": "Disaster Recovery Plan",
    "definition": "is a formal document that outlines how an organization will respond to an unplanned incident and resume business operations. A DRP is an essential part of a business continuity plan (BCP).",
    "category": "Business"
  },
  {
    "acronym": "DSA",
    "fullform": "Digital Signature Algorithm",
    "definition": "is a public-key cryptographic algorithm used to generate digital signatures, authenticate the sender of a digital message, and prevent message tampering.",
    "category": "Security"
  },
  {
    "acronym": "DSL",
    "fullform": "Digital Subscriber Line",
    "definition": "is a modem technology that uses existing telephone lines to transport high-bandwidth data, such as multimedia and video, to service subscribers. DSL provides dedicated, point-to-point, public network access.",
    "category": "Networking"
  },
  {
    "acronym": "EAP",
    "fullform": "Entensible Authentication Protocol",
    "definition": "is an authentication framework, not a specific authentication mechanism. It is used to pass the authentication information between the supplicant (the Wi-Fi workstation) and the authentication server (Microsoft IAS or other). The EAP type actually handles and defines the authentication.",
    "category": "Networking"
  },
  {
    "acronym": "ECB",
    "fullform": "Electronic Code Book",
    "definition": "a simple mode of operation for a block cipher, mostly used with symmetric key encryption, where each plaintext block has a corresponding ciphertext value. The plaintext is broken into blocks of a given size (128 bits in this case), and the encryption algorithm is run on each block of plaintext individually. The weakness of this encryption mode is that it's possible to see patterns in the ciphertext.",
    "category": "Security"
  },
  {
    "acronym": "ECC",
    "fullform": "Elliptic Curve Cryptography",
    "definition": "is a public-key cryptography algorithm that uses elliptic curve theory to generate keys and perform security functions. ECC provides greater cryptographic strength with shorter key lengths, making it ideal for devices with limited computing power.",
    "category": "Security"
  },
  {
    "acronym": "ECDHE",
    "fullform": "Elliptic Curve Diffie-Hellman Ephemeral",
    "definition": "is a key exchange algorithm that allows two parties to establish a shared secret over an insecure communication channel. It is a variant of the Diffie-Hellman key exchange that uses elliptic curve cryptography to provide stronger security with smaller key sizes. A distinct key for every exchange is used allowing for perfect forward secrecy.",
    "category": "Security"
  },
  {
    "acronym": "ECDSA",
    "fullform": "Elliptic Curve Digital Signature Algorithm",
    "definition": "is a public key cryptography encryption algorithm that uses elliptic curve cryptography (ECC) to generate keys, sign, authenticate, and verify messages. ECDSA is a variation of the Digital Signature Algorithm (DSA) that's more efficient because it requires smaller keys to provide the same level of security.",
    "category": "Security"
  },
  {
    "acronym": "EDR",
    "fullform": "Endpoint Detection and Response",
    "definition": "is a cybersecurity technology that monitors endpoints for threats and responds to them. EDR can help protect networks by: Containing threats, Preventing threats from spreading, and Rolling back damage caused by threats. An EDR solution isolates threats and automatically blocks any IOCs upon detecting any malicious activity.",
    "category": "Security"
  },
  {
    "acronym": "EFS",
    "fullform": "Encrypted File System",
    "definition": "is a user-based encryption control technique that enables users to control who can read the files on their system. The typical method of using EFS is to perform encryption at the folder level. This ensures that all files added to the encrypted folder are automatically encrypted.",
    "category": "Security"
  },
  {
    "acronym": "ERP",
    "fullform": "Enterprise Resource Planning",
    "definition": "is a category of business software that automates business processes and provides insights and internal controls, drawing on a central database that collects inputs from departments including accounting, manufacturing, supply chain management, sales, marketing and human resources (HR).",
    "category": "Business"
  },
  {
    "acronym": "ESN",
    "fullform": "Electronic Serial Number",
    "definition": "created by FCC to uniquely identifies mobile devices.",
    "category": "Telecommunications"
  },
  {
    "acronym": "ESP",
    "fullform": "Encapsulated Security Payload",
    "definition": "is a security protocol that protects data sent across networks by providing confidentiality, integrity, and authenticity. ESP is part of the Internet Protocol Security (IPsec) protocol suite.",
    "category": "Networking"
  },
  {
    "acronym": "FACL",
    "fullform": "File System Access Control List",
    "definition": "is a table that informs a computer operating system of the access privileges a user has to a system object, including a single file or a file directory.",
    "category": "Security"
  },
  {
    "acronym": "FDE",
    "fullform": "Full Disk Encryption",
    "definition": "is a security method that encrypts all data on a disk drive, including the operating system, applications, and user data. This ensures that all data stored on the disk is inaccessible without proper authentication, usually in the form of a password or encryption key. FDE is especially useful for devices that can be lost or stolen, such as laptops, desktops, and mobile devices.",
    "category": "Security"
  },
  {
    "acronym": "FIM",
    "fullform": "File Integrity Management",
    "definition": "is a security process that monitors and analyzes the integrity of critical assets, including file systems, directories, databases, network devices, the operating system (OS), OS components and software applications for signs of tampering or corruption, which may be an indication of a cyberattack. The FIM tool compares the current file with a baseline and triggers an alert in the event the file has been altered or updated in a way that violates the company’s predefined security policies.",
    "category": "Security"
  },
  {
    "acronym": "FPGA",
    "fullform": "Field Programmable Gate Array",
    "definition": "is a type of semiconductor that can be programmed and reprogrammed according to your design and device needs.",
    "category": "Computing"
  },
  {
    "acronym": "FRR",
    "fullform": "False Rejection Rate",
    "definition": "measures how well your system can identify legitimate users. It is the percentage of times that a user is incorrectly rejected by your system.",
    "category": "Security"
  },
  {
    "acronym": "FTP",
    "fullform": "File Transfer Protocol",
    "definition": "is a standard protocol that allows users to transfer files between computers over a network, such as the internet.",
    "category": "Networking"
  },
  {
    "acronym": "FTPS",
    "fullform": "Secured File Transfer Protocol",
    "definition": "is an extension of the File Transfer Protocol (FTP) that supports Transport Layer Security (TLS) and Secure Sockets Layer (SSL) cryptographic protocols. Note, SFTP secures file transfer by incorporating Secure Shell (SSH) for authentication and data encryption and is considered more secure than FTPS however, FPTS is more commonly used.",
    "category": "Networking"
  },
  {
    "acronym": "GCM",
    "fullform": "Galois Counter Mode",
    "definition": "is a mode of operation for symmetric-key cryptographic block ciphers which is widely adopted for its performance. GCM is a mode that provides both confidentiality and data integrity, and is also more efficient for parallel processing, which can result in better performance for larger datasets.",
    "category": "Security"
  },
  {
    "acronym": "GDPR",
    "fullform": "General Data Protection Regulation",
    "definition": "is a European Union regulation on information privacy in the European Union and the European Economic Area.",
    "category": "Security"
  },
  {
    "acronym": "GPG",
    "fullform": "Gnu Privacy Guard",
    "definition": "free software that allows you to encrypt and sign your data and communications; it features a versatile key management system, along with access modules for all kinds of public key directories.",
    "category": "Security"
  },
  {
    "acronym": "GPO",
    "fullform": "Group Policy Object",
    "definition": "are a collection of settings that define what a system will look like and how it will behave for a defined group of computers or users.",
    "category": "Computing"
  },
  {
    "acronym": "GPS",
    "fullform": "Global Positioning System",
    "definition": "",
    "category": "Networking"
  },
  {
    "acronym": "GPU",
    "fullform": "Graphics Processing Unit",
    "definition": "",
    "category": "Computing"
  },
  {
    "acronym": "GRE",
    "fullform": "Generic Routing Encapsulation",
    "definition": "is a tunneling protocol that allows devices to share data directly through network nodes by encapsulating data packets that use one routing protocol inside the packets of another protocol. GRE tunnels are insecure and should be paird with IPSec. GRE enables the usage of protocols that are not normally supported by a network, because the packets are wrapped within other packets that do use supported protocols.",
    "category": "Networking"
  },
  {
    "acronym": "HA",
    "fullform": "High Availability",
    "definition": "is a system's ability to operate continuously without downtime or failure, usually by using built-in failover mechanisms. HA systems are designed to operate without fail even in the case of unexpected events.",
    "category": "Computing"
  },
  {
    "acronym": "HDD",
    "fullform": "Hard Disk Drive",
    "definition": "",
    "category": "Computing"
  },
  {
    "acronym": "HIDS",
    "fullform": "Host-based Intrusion Detection System",
    "definition": "collects data from servers, computers, and other host systems, then analyzing the data for anomalies or suspicious activity. Works as a detection mechanism. There are two categories of HIDS: agent based and agentless. An agent-based HIDS relies on software agents that are installed on each host to collect information from the host. This is a “heavier-weight” approach because running agents on hosts increases the resource utilization of the hosts. An agentless HIDS, information from hosts is collected without relying on agents, such as by streaming the data over the network. This type of HIDS is more complex to implement, and agentless HIDS sometimes can’t access as much data as agent-based solutions, but the agentless approach offers the benefit of consuming fewer resources.",
    "category": "Security"
  },
  {
    "acronym": "HIPS",
    "fullform": "Host-based Intrusion Prevention System",
    "definition": "uses behavioral analysis and network filtering to monitor files, registry keys, and running processes. It can take action against threats by blocking malicious activity.",
    "category": "Security"
  },
  {
    "acronym": "HMAC",
    "fullform": "Hashed Message Authentication Code",
    "definition": "is a cryptographic technique that uses a secret key and a hash function to verify the authenticity and integrity of data. With HMAC, you can achieve authentication and verify that data is correct and authentic with shared secrets, as opposed to approaches that use signatures and asymmetric cryptography. HMAC is more secure than Message Authentication Code (MAC) because the key and message are hashed in separate steps.",
    "category": "Security"
  },
  {
    "acronym": "HOTP",
    "fullform": "HMAC-based One-time Password",
    "definition": "is a password algorithm that uses a keyed-hash message authentication code (HMAC) to generate one-time passwords (OTPs). HOTPs are often used in two-factor authentication (2FA) and token-based authentication.",
    "category": "Security"
  },
  {
    "acronym": "HSM",
    "fullform": "Hardware Security Module",
    "definition": "are hardened, tamper-resistant hardware devices that strengthen encryption practices by generating keys, encrypting and decrypting data, and creating and verifying digital signatures. An HSM is a removable unit that runs on its own, while trusted platform modules (TPM) is a chip on your motherboard that can encrypt an entire laptop or desktop disk.",
    "category": "Security"
  },
  {
    "acronym": "HTML",
    "fullform": "Hypertext Markup Language",
    "definition": "",
    "category": "Computing"
  },
  {
    "acronym": "HTTP",
    "fullform": "Hypertext Transfer Protocol",
    "definition": "",
    "category": "Networking"
  },
  {
    "acronym": "HTTPS",
    "fullform": "Hypertext Transfer Protocol Secure",
    "definition": "",
    "category": "Networking"
  },
  {
    "acronym": "HVAC",
    "fullform": "Heating, Ventilation Air Conditioning",
    "definition": "",
    "category": "Building Systems"
  },
  {
    "acronym": "IaaS",
    "fullform": "Infrastructure as a Service",
    "definition": "a cloud computing model that provides computing resources (like storage, networking, servers, and virtualization) on demand over the internet. With an IaaS model, the cloud vendor is responsible for security of the physical data centers and other hardware that power the infrastructure including VMs, disks and networks. Users must secure their own data, operating systems and software stacks that run their applications.",
    "category": "Computing"
  },
  {
    "acronym": "IaC",
    "fullform": "Infrastructure as Code",
    "definition": "is a DevOps practice that uses code to provision and manage computer data center resources instead of manual processes and settings.",
    "category": "Computing"
  },
  {
    "acronym": "IAM",
    "fullform": "Identity and Access Management",
    "definition": "is for making sure that only the right people can access an organization's data and resources.",
    "category": "Security"
  },
  {
    "acronym": "ICMP",
    "fullform": "Internet Control Message Protocol",
    "definition": "is a protocol that devices within a network use to communicate information about data transmission errors and operational success or failure. ICMP can be an attack vector for a network. A ping scan or sweep helps an attacker discover systems to target in future attacks. ICMP tunneling can enable a compromised device to secretly communicate with an attacker, receiving commands or exfiltrating data.",
    "category": "Networking"
  },
  {
    "acronym": "ICS",
    "fullform": "Industrial Control Systems",
    "definition": "are electronic systems that use instrumentation to control industrial processes.",
    "category": "Security"
  },
  {
    "acronym": "IDEA",
    "fullform": "International Data Encryption Algorithm",
    "definition": "is a symmetric key block cipher encryption algorithm designed to encrypt text to an unreadable format for transmission via the internet. It uses a typical block size of 128 bits and takes 64 bits as an input. IDEA is considered more secure than DES because it uses a 128-bit key, while DES uses a 56-bit key.",
    "category": "Security"
  },
  {
    "acronym": "IDF",
    "fullform": "Intermediate Distribution Frame",
    "definition": "is a free-standing or wall-mounted rack for managing and interconnecting a telecommunications cable between end-user devices and the main distribution frame (MDF). It’s essential for connecting users in a network to servers in the same network.",
    "category": "Networking"
  },
  {
    "acronym": "IdP",
    "fullform": "Identity Provider",
    "definition": "is a system that creates, stores, and manages digital identities. IdPs can be organizations, businesses, or federation partners that provide identity authentication and verification services, also known as identity as a service (IDaaS).",
    "category": "Security"
  },
  {
    "acronym": "IDS",
    "fullform": "Intrusion Detection System",
    "definition": "is a device or software application that monitors a network for malicious activity or policy violations. ",
    "category": "Security"
  },
  {
    "acronym": "IEEE",
    "fullform": "Insititute of Electrical and Electronics Engineers",
    "definition": "",
    "category": "Standards Organization"
  },
  {
    "acronym": "IKE",
    "fullform": "Internet Key Exchange",
    "definition": "is a secure key management protocol for establishing secure, authenticated communication channels over IP networks. Internet Key Exchange version 2 (IKEv2) is a tunneling protocol, based on IPsec, that establishes a secure VPN communication between VPN devices and defines negotiation and authentication processes for IPsec security associations (SAs). Various VPN providers refer to this combination as IKEv2/IPsec, or IKEv2 VPN.",
    "category": "Security"
  },
  {
    "acronym": "IM",
    "fullform": "Instant Messaging",
    "definition": "",
    "category": "Communications"
  },
  {
    "acronym": "IMAP",
    "fullform": "Internet Message Access Protocol",
    "definition": "is an internet standard protocol that allows email clients to retrieve email messages from a mail server over a TCP/IP connection. IMAP acts as an intermediary between email servers and email clients, allowing users to access their emails from any device, such as a phone, computer, or friend's computer.",
    "category": "Networking"
  },
  {
    "acronym": "IoC",
    "fullform": "Indicators of Compromise",
    "definition": "are pieces of information that can indicate a potential cyberattack or security breach. They can be files, IP addresses, domain names, registry keys, or other evidence of malicious activity.",
    "category": "Security"
  },
  {
    "acronym": "IoT",
    "fullform": "Internet of Things",
    "definition": "refers to the collective network of connected devices and the technology that facilitates communication between devices and the cloud, as well as between the devices themselves.",
    "category": "Computing"
  },
  {
    "acronym": "IP",
    "fullform": "Internet Protocol",
    "definition": "is a network layer communications protocol that relays datagrams across network boundaries. IP's routing function enables internetworking and is essential to the establishment of the internet. IP is often used in conjunction with Transmission Control Protocol (TCP) to form the TCP/IP suite, which is a set of standardized rules that allow computers to communicate on a network.",
    "category": "Networking"
  },
  {
    "acronym": "IPS",
    "fullform": "Intrusion Prevention System",
    "definition": " is a network security tool (which can be a hardware device or software) that continuously monitors a network for malicious activity and takes action to prevent it, including reporting, blocking, or dropping it, when it does occur.",
    "category": "Security"
  },
  {
    "acronym": "IPSec",
    "fullform": "Internet Protocol Security",
    "definition": "is a set of protocols that secure communication between devices over a network by encrypting and authenticating data packets. IPsec is often used to set up virtual private networks (VPNs), which allow users to access the internet as if they were connected to a private network.",
    "category": "Security"
  },
  {
    "acronym": "IR",
    "fullform": "Incident Response",
    "definition": "is a company's actions to manage the aftermath of a cyberattack or security breach. The goal is to reduce recovery time and costs, and limit damage to the company's reputation and technology infrastructure.",
    "category": "Security"
  },
  {
    "acronym": "IRC",
    "fullform": "Internet Relay Chat",
    "definition": "is a protocol for real-time text messaging between internet-connected computers created in 1988.",
    "category": "Communications"
  },
  {
    "acronym": "IRP",
    "fullform": "Incident Response Plan",
    "definition": "is a written set of instructions that help organizations respond to cybersecurity incidents, such as data breaches and insider threats. It outlines steps to detect and identify an incident, respond to it, reduce its consequences, and prevent it from happening again.",
    "category": "Security"
  },
  {
    "acronym": "ISO",
    "fullform": "International Standards Organization",
    "definition": "",
    "category": "Standards Organization"
  },
  {
    "acronym": "ISP",
    "fullform": "Internet Service Provider",
    "definition": "is a company that provides internet access.",
    "category": "Networking"
  },
  {
    "acronym": "ISSO",
    "fullform": "Information Systems Security Officer",
    "definition": "individual with assigned responsibility for maintaining the appropriate operational security posture for an information system or program.",
    "category": "Security"
  },
  {
    "acronym": "IV",
    "fullform": "Initialization Vector",
    "definition": "is also used as input for a cryptographic primitive to achieve randomization of normally deterministic primitives.",
    "category": "Security"
  },
  {
    "acronym": "KDC",
    "fullform": "Key Distribution Center",
    "definition": "is a system that is responsible for providing keys to the users in a network that shares sensitive or private data. It is a form of symmetric encryption that allows the access of two or more systems in a network by generating a unique ticket type key for establishing a secure connection over which data is shared and transferred. KDC is the main server which is consulted before communication takes place. Due to its central infrastructure, KDC is usually employed in smaller networks where the connection requests do not overwhelm the system. KDC is used instead of standard key encryption because the key is generated every time a connection is requested, which minimizes the chances of attack.",
    "category": "Security"
  },
  {
    "acronym": "KEK",
    "fullform": "Key Encryption Key",
    "definition": "a key that encrypts other key (typically Traffic Encryption Keys or TEKs) for transmission or storage. This process is known as envelope encryption. KEKs are an extra layer of security that are essential when cryptographic keys are stored or sent. Even if a hacker is able to obtain a key that has been encrypted by a KEK, they will not be able to use it.",
    "category": "Security"
  },
  {
    "acronym": "L2TP",
    "fullform": "Layer 2 Tunneling Protocol",
    "definition": "is a virtual private network (VPN) protocol that creates a connection between your device and a VPN server without encrypting your content. Due to its lack of encryption and authentication, L2TP is usually paired with Internet Protocol Security (IPsec) protocol.",
    "category": "Networking"
  },
  {
    "acronym": "LAN",
    "fullform": "Local Area Network",
    "definition": "is a collection of devices connected together in one physical location, such as a building, office, or home.",
    "category": "Networking"
  },
  {
    "acronym": "LDAP",
    "fullform": "Lightweight Directory Access Protocol",
    "definition": "is an open, industry standard protocol that allows users to access and maintain directory information services over an internet protocol network.",
    "category": "Networking"
  },
  {
    "acronym": "MaaS",
    "fullform": "Monitoring as a Service",
    "definition": "is a cloud-based service model that allows businesses to monitor their network infrastructure, applications, and systems through a subscription-based model. MaaS can be used to monitor performance issues, security threats, and other processes.",
    "category": "Computing"
  },
  {
    "acronym": "MAC",
    "fullform": "Mandatory Access Control",
    "definition": "is a security strategy that restricts the ability individual resource owners have to grant or deny access to resource objects in a file system. A subject may access an object only if the subject's clearance is equal to or greater than the object's label.",
    "category": "Security"
  },
  {
    "acronym": "MAC",
    "fullform": "Media Access Control",
    "definition": "is a sublayer of the data link layer (Layer 2) in the OSI model. It is responsible for the control of how devices in a network gain access to a medium and permission to transmit data. Ethernet, Wi-Fi, and Bluetooth protocols use MAC to manage data transmission. Devices use MAC addresses to identify and communicate with each other on a local network.",
    "category": "Networking"
  },
  {
    "acronym": "MAC",
    "fullform": "Message Authentication Code",
    "definition": "is a short piece of information used to authenticate a message and to provide integrity and authenticity assurances on the message. It ensures that the message has not been altered and that it comes from the expected sender.",
    "category": "Security"
  },
  {
    "acronym": "MAN",
    "fullform": "Metropolitan Area Network",
    "definition": "is a network designed to extend over a city or metropolitan area, providing high-speed connectivity for various institutions, including businesses, government entities, and educational institutions within the area. It bridges the gap between smaller LANs and broader WANs.",
    "category": "Networking"
  },
  {
    "acronym": "MBR",
    "fullform": "Master Boot Record",
    "definition": "is a special type of boot sector located at the very beginning of a storage device, such as a hard disk drive (HDD) or solid-state drive (SSD). It contains the partition table for the disk and a small amount of executable code for the boot process.",
    "category": "Computing"
  },
  {
    "acronym": "MD5",
    "fullform": "Message Digest 5",
    "definition": "is a cryptographic hash function that takes an input and returns a fixed-size string of bytes (digest). Primary use case is for checksums. MD5 is considered obsolete and vulnerable to collision attacks.",
    "category": "Security"
  },
  {
    "acronym": "MDF",
    "fullform": "Main Distribution Frame",
    "definition": "is a physical structure that houses connections for telecommunication and data cabling systems. It is used to terminate and manage incoming and outgoing cables, providing a point of interconnection between the external lines from a telecommunications provider and the internal network equipment.",
    "category": "Networking"
  },
  {
    "acronym": "MDM",
    "fullform": "Mobile Device Management",
    "definition": "is a comprehensive approach for managing and securing mobile devices used within an organization. It involves deploying software that enables IT administrators to control and secure data on mobile devices, ensuring corporate policies are enforced and sensitive information is protected.",
    "category": "Security"
  },
  {
    "acronym": "MFA",
    "fullform": "Multifactor Authentication",
    "definition": "is an authentication process that requires two or more independent credentials for verification. These credentials fall into three main categories: something you know (knowledge), something you have (possession), and something you are (inherence).",
    "category": "Security"
  },
  {
    "acronym": "MFD",
    "fullform": "Multifunction Device",
    "definition": "is an integrated office machine that performs several functions traditionally carried out by separate devices, such as printing, copying, scanning, and faxing. Multifunction printer (MFP) is a specific type of MFD.",
    "category": "Hardware"
  },
  {
    "acronym": "MFP",
    "fullform": "Multifunction Printer",
    "definition": "is specifically a type of multifunction device that combines printing with additional functions such as copying, scanning, and sometimes faxing. It is designed primarily for managing document-related tasks.",
    "category": "Hardware"
  },
  {
    "acronym": "ML",
    "fullform": "Machine Learning",
    "definition": "",
    "category": "Computing"
  },
  {
    "acronym": "MMS",
    "fullform": "Multimedia Message Service",
    "definition": "is a messaging service that enables users to send and receive multimedia content such as photos, videos, audio clips, and rich text messages over mobile networks.",
    "category": "Telecommunications"
  },
  {
    "acronym": "MOA",
    "fullform": "Memorandum of Aggreement",
    "definition": "is a formal document that outlines an agreement between two or more parties. It details the terms, responsibilities, and expectations of each party involved, and is often used to outline the specifics of a collaborative effort or partnership. This is different compared to Memorandum of Understanding (MOU) which is often used to express mutual understanding or preliminary agreements without detailed terms.",
    "category": "Business"
  },
  {
    "acronym": "MOU",
    "fullform": "Memorandum of Understanding",
    "definition": "is a written agreement that details the intentions, responsibilities, and mutual understandings between parties involved in a proposed collaboration or project. It serves as a formal acknowledgment of the parties’ commitment to work together but is generally less formal than a contract.",
    "category": "Business"
  }
];

export default list;