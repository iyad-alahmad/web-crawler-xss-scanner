import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time
import urllib3
from pprint import pprint

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
 
class UrlCrawler:
    def __init__(self, base_url, max_depth=10, max_retries=3, retry_delay=5, timeout=10):
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.timeout = timeout
        self.visited_urls = set()  
        self.urls_to_visit = [(self.base_url, 0)]  
        self.relevant_urls = set()  
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.output_file = os.path.join(self.script_dir, "url.txt")
        
    def clear_output_file(self):
        
        with open(self.output_file, "w") as f:
            pass
    
    def crawl_and_record_urls(self):
        self.clear_output_file()  
        
        while self.urls_to_visit:
            current_url, depth = self.urls_to_visit.pop(0)
            if current_url in self.visited_urls or depth > self.max_depth:
                continue
            self.visited_urls.add(current_url)
            if not current_url.startswith(self.base_url):
                continue
            retries = 0
            while retries < self.max_retries:
                try:
                    
                    response = requests.get(current_url, timeout=self.timeout, verify=False)
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        with open(self.output_file, "a") as f:
                            f.write(current_url + '\n')
                            self.relevant_urls.add(current_url)
                        for link in soup.find_all('a'):
                            new_url = urljoin(current_url, link.get('href'))
                            if new_url.startswith(self.base_url):
                                self.urls_to_visit.append((new_url, depth + 1))
                        break
                except (requests.exceptions.RequestException, TimeoutError) as e:
                    print(f"Hata: {current_url} işlenirken hata oluştu: {e}")
                    retries += 1
                    time.sleep(self.retry_delay)
            if retries == self.max_retries:
                print(f"{current_url} adresi {self.max_retries} tekrar denemeden sonra işlenemedi")

        print("Bulunan ilgili URL'ler:")
        for url in self.relevant_urls:
            print(url)

class XssScanner:
    COLOR_RED = '\033[91m'
    COLOR_GREEN = '\033[92m'
    COLOR_YELLOW = '\033[93m'
    COLOR_END = '\033[0m'

    def __init__(self):
        self.vulnerabilities = []  

    def print_fail(self, message):
        print(f"{self.COLOR_RED}[!] {message}{self.COLOR_END}")

    def print_success(self, message):
        print(f"{self.COLOR_GREEN}[+] {message}{self.COLOR_END}")

    def print_info(self, message):
        print(f"{self.COLOR_YELLOW}[*] {message}{self.COLOR_END}")

    def get_all_forms(self, url):
        soup = BeautifulSoup(requests.get(url).content, "html.parser")
        return soup.find_all("form")

    def get_form_details(self, form):
        details = {}
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def submit_form(self, form_details, url, payload):
        target_url = urljoin(url, form_details["action"])
        inputs = form_details["inputs"]
        data = {}
        for input in inputs:
            if input["type"] == "text" or input["type"] == "search":
                input["value"] = payload
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                data[input_name] = input_value
        self.print_info(f"[*] Payload {target_url} adresine gönderiliyor")
        self.print_info(f"[*] Veri: {data}")
        if form_details["method"] == "post":
            return requests.post(target_url, data=data)
        else:
            return requests.get(target_url, params=data)

    def scan_xss(self, url, payload):
        forms = self.get_all_forms(url)
        self.print_info(f"[*] {url} adresinde {len(forms)} form tespit edildi.")
        is_vulnerable = False
        for form in forms:
            form_details = self.get_form_details(form)
            content = self.submit_form(form_details, url, payload).content.decode()
            if payload in content:
                self.print_success(f"[+] {url} adresinde XSS tespit edildi")
                ##self.print_info("[*] Form ayrıntıları:")
                #pprint(form_details)
                is_vulnerable = True
                self.vulnerabilities.append({
                    "url": url,
                    "form_details": form_details,
                    "payload": payload,
                })
                break

        if not is_vulnerable:
            self.print_fail("[-] Bu payload için herhangi bir güvenlik açığı bulunamadı.")
        return is_vulnerable

    def scan_urls_with_payloads(self, urls, payloads):
        for url in urls:
            url = url.strip()
            self.print_info(f"Test Edilen URL: {url}")
            for payload in payloads:
                payload = payload.strip()
                is_vulnerable = self.scan_xss(url, payload)
                if is_vulnerable:
                    self.print_success("Güvenlik Açıkları:")
                    for vuln in self.vulnerabilities:
                        self.print_success(f"URL: {vuln['url']}")
                        self.print_info("Form Ayrıntıları:")
                        pprint(vuln["form_details"])
                        self.print_success(f"Yüklenen Payload: {vuln['payload']}")
                    break

        self.print_info("Tüm URL'lerin testi tamamlandı.")

def main():
    target_url = input("[+] Hedef URL'yi girin: ")
    crawl = UrlCrawler(target_url)
    crawl.crawl_and_record_urls()
    
    scanner = XssScanner()

    url_file_path = "url.txt"
    payloads_file_path = "payloads.txt"

    with open(url_file_path, "r") as url_file:
        urls = url_file.readlines()

    with open(payloads_file_path, "r") as payloads_file:
        payloads = payloads_file.readlines()

    scanner.scan_urls_with_payloads(urls, payloads)

if __name__ == "__main__":
    main()
