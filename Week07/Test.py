import requests
from bs4 import BeautifulSoup
import re
import mechanize
from Wappalyzer import Wappalyzer, WebPage

website = "https://www.una.ac.cr/"

print("-----------REQUEST-----------")
request = requests.get(website)
#Checking status code
if request.status_code == 200:
    #getting web site content
    html_content = request.content
else:
    print("Web site could not be loaded:", request.status_code)


print("---------MECHANIZE-----------")
#Instancia del Browser
browser = mechanize.Browser()
browser.set_handle_robots(False)
browser.open(request.url)

#Retrieve the current page's links.
def refresh_mechanize_links():
    #Set the browser to handle refreshes automatically
    browser.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)
    #Force a refresh by re-requesting the current page
    browser.reload()
    return list(browser.links())
#Navigate to a link by its index if it marches the target, otherwise if will look up for the url that contains word in the target.
def navigate_mechanize_link(index, target):
    try:
        links = refresh_mechanize_links()
        if target in str(links[index].url):
            browser.follow_link(links[index])
        else:
            for link in links:
                if target in link.url:
                     browser.follow_link(link)
    except IndexError:
        print(f"No link found at index {index}.")


refresh_mechanize_links()

print("-----------BEAUTIFULSOUP-----------")
html_content = request.content
soup = BeautifulSoup(html_content, 'html.parser')


# Find all anchor tags (links) on the page
links = []
for link in soup.find_all('a', href=True):
    links.append(link)


print("-----------REGEX-----------")
#Regex pattern to detect word admin in the links.
pattern = re.compile(r"(admin|admin\.[a-z]+)")

#check each URL
for url in links:
    if pattern.search(str(url)):
        print(f"{url} contains 'admin'")

print("-----------MECHANIZE-----------")
navigate_mechanize_link(119, "aulavirtual")
print("Title of webpage: " + browser.title())
print("URL: " + browser.geturl())

#selecting the form by id
browser.select_form(id="login")

#filling the form
browser.form['username'] = 'admin'
browser.form['password'] = 'admin123'
req = browser.submit()

#check if form was sent correctly
if req.getcode() == 200:
    print("Form has been sent")
else:
    print("Error: Form could not be sent")

#after submitting the form, check if cookies were set, and therefore it log in.
for cookie in browser._ua_handlers["_cookies"].cookiejar:
    if "session_id" in cookie.name:
        print("Session cookie found. Login successful!")
        break
else:
    print("No session cookie. Login failed.")


print("-----------WAPPALYZER-----------")
#Instantiate Wappalyzer
wappalyzer = Wappalyzer.latest()
#Create a WebPage object from the URL
webpage = WebPage.new_from_url(request.url)
#Analyze the webpage with Wappalyzer
analysis = wappalyzer.analyze_with_versions_and_categories(webpage)
#Print all the technologies Wappalyzer found
for number, (key, value) in enumerate(analysis.items(), start=1):
    print(f"Tec: {number} {key}: ")
    print(value)
    print()

