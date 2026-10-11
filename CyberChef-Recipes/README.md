# CyberChef Analysis Recipes

This directory maintains reusable CyberChef operational recipes deployed during manual artifact extraction and deobfuscation.

## Catalog

| Recipe File | Description | Target Artifacts |
|---|---|---|
| `Base64_Archive_Extractor.json` | Decodes Base64 data streams and unpacks archive containers, filtering out decoy media assets to isolate binaries. | Base64-encoded ISOs, ZIPs, CABs |

## How to Import
1. Navigate to [CyberChef](https://gchq.github.io/CyberChef/).
2. Click the folder icon (**Open recipe**) located above the Recipe pane.
3. Select and load the corresponding `.json` recipe file.
