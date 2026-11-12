# Installing Soundwave

This guide takes a scanner that's already working and gets its findings into Puppet Enterprise Vulnerability Remediation.

The steps link to [the module's reference pages](../../README.md#reference) for each setting's detail.

## Before this guide

Install and scan with at least one scanner first, using its own guide. Each one works without Soundwave, and its last step gets it ready for Soundwave:

- [Greenbone, with the openvas module](https://github.com/albatrossflavour/openvas/blob/main/docs/guide/README.md), to step 5
- [Vuls, with the vuls module](https://github.com/albatrossflavour/vuls/blob/main/docs/guide/README.md), to step 5

Soundwave goes on the scanner node, because each cassette reads its scanner locally. With both scanners, they share a node.

## The steps

1. [Prepare PE](01-pe.md)
2. [Install Soundwave](02-install.md)
3. [Accept it in PE](03-accept.md)
