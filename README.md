# go-tpm2

This repository contains a go library for interacting with TPM 2.0 devices. Currently supported features are:

 - All authorization modes - password, HMAC session based and policy session based.
   - Salted / unsalted + bound / unbound sessions are supported.
 - Session-based command and response parameter encryption.
 - Backends for Linux TPM character devices and the IBM simulator.
 - All startup, testing and session commands.
 - All object commands, including Unseal.
 - Most NV storage commands.
 - Some PCR commands (Extend, Event and Read).
 - Some extended authorization commands.
 - Most hierarchy commands.
 - Dictionary attack functions.
 - Context management commands.
 
 ## Relevant links
  - [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
  - [IBM's Software TPM 2.0](https://sourceforge.net/projects/ibmswtpm2/)
