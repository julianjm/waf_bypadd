# WAF Bypadd

## Description

This Burp Suite extension is designed to bypass Web Application Firewalls (WAFs) by padding HTTP requests with dummy data. 

Many WAFs only analyze the first few kilobytes of an HTTP request. By filling this portion of the request with harmless data, the WAF can be tricked into not analyzing the actual, potentially malicious payloads. This extension can be particularly useful during penetration testing assignments, where WAFs might prevent certain types of payloads from reaching the application.

## Features

- Ability to add a configurable amount of padding to the POST payloads.
- Configurable settings to choose which Burp Suite tools the extension will work on (Proxy, Scanner, Repeater).

## Installation

1. Download the latest release of the extension.
2. In Burp Suite, go to the Extender tab.
3. Click on the Add button in the Extensions sub-tab.
4. Change the extension type to Python, and select the waf_bypadd.py file you downloaded.

## Configuration

Once installed, the extension will appear as a new tab named "WAF Bypadd" in Burp Suite. In this tab, you can configure the extension settings:

- Check the boxes next to "Intercept Proxy Requests", "Intercept Scanner Requests", and "Intercept Repeater Requests" to decide which tools the extension should work on.
- Specify the padding size in the "Padding Size" text field.

## Contributing

We welcome contributions to this project. Please feel free to submit issues, feature requests, and pull requests.

## License

This project is licensed under the MIT License. See the LICENSE file for more information.

## Disclaimer

This tool is intended for legal, ethical use only, such as during authorized penetration testing or security research. The authors are not responsible for any illegal use or misuse of this tool.

## Contact

For more information or support, please contact:

- Author: Julian J. M.
- Email: julianjm@gmail.com
- Github: https://github.com/julianjm
