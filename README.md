
# Web Crawler and XSS Scanner

This project is a Python script that combines a web crawler and an XSS (Cross-Site Scripting) vulnerability scanner. It crawls a given website, records relevant URLs, and then performs XSS vulnerability scanning on those URLs using predefined payloads.

## Prerequisites

Before running the project, make sure you have the following libraries installed:

- [requests](https://pypi.org/project/requests/): Used for making HTTP requests.
- [BeautifulSoup](https://pypi.org/project/beautifulsoup4/): Used for parsing HTML content.
- [urllib3](https://pypi.org/project/urllib3/): Used to disable SSL certificate warnings.
- [pprint](https://docs.python.org/3/library/pprint.html): Used for pretty-printing data.

You can install these libraries using the following commands:

```bash
	pip install requests beautifulsoup4 urllib3



## Usage

Clone this repository to your local machine: 
```bash
	git clone https://github.com/iyad-alahmad/web-crawler-xss-scanner.git

Navigate to the project directory:
```bash
	cd web-crawler-xss-scanner

Run the script:
```bash
	python xss-scanner.py


##Examples where it works:
	<
	
	https://xss-game.appspot.com/level1/frame
	http://testphp.vulnweb.com/index.php
	https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded
	https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded
	
	>


Follow the on-screen prompts to input the target URL and watch the script in action. The script will first crawl the website, record relevant URLs, and then perform XSS vulnerability scanning on those URLs.
How It Works
UrlCrawler Class
The UrlCrawler class is responsible for crawling a website and recording relevant URLs. It starts from a base URL, explores links, and records URLs up to a specified depth. The relevant URLs are stored in the url.txt file.

XssScanner Class
The XssScanner class performs XSS vulnerability scanning on a list of URLs using predefined payloads. It extracts HTML form details from each URL, submits malicious payloads, and checks for vulnerabilities. If an XSS vulnerability is detected, the relevant information is printed to the console.

The main function orchestrates the entire process by taking user input for the target URL, performing crawling and scanning, and providing color-coded console output for better readability.

Disclaimer
This project is provided for educational and informational purposes only. It should not be used for any malicious or unauthorized activities. Use this tool responsibly and only on websites where you have proper authorization.

License
This project is licensed under the MIT License.


References
- [Cross-Site Scripting (XSS) - Python Code](https://thepythoncode.com/article/make-a-xss-vulnerability-scanner-in-python)
- [Cross-Site Scripting (XSS)](https://portswigger.net/web-security/cross-site-scripting)
- [Cross-Site Scripting (XSS) - OWASP](https://owasp.org/www-community/attacks/xss/)


