from bs4 import BeautifulSoup
import urllib
import bs4
import re
import socket
import whois
from datetime import datetime
import time
import pandas as pd
import csv 


from googlesearch import search

# This import is needed only when you run this file in isolation.
import sys

from patterns import *

# Path of your local server. Different for different OSs.
LOCALHOST_PATH = "C:/wamp64/www/"
#LOCALHOST_PATH = "/Library/WebServer/Documents/"
DIRECTORY_NAME = "code"


def urlHasIP(url):
    ip_address_pattern = ipv4_pattern + "|" + ipv6_pattern
    match = re.search(ip_address_pattern, url)
    return -1 if match else 1


def urlIsLong(url):
    if len(url) < 54:
        return 1
    if 54 <= len(url) <= 75:
        return 0
    return -1


def urlIsShort(url):
    match = re.search(shortening_services, url)
    return -1 if match else 1


def urlHasAtSymbol(url):
    match = re.search('@', url)
    return -1 if match else 1


def urlHasRedirection(url):
    # since the position starts from 0, we have given 6 and not 7 which is according to the document.
    # It is convenient and easier to just use string search here to search the last occurrence instead of re.
    last_double_slash = url.rfind('//')
    return -1 if last_double_slash > 6 else 1


def urlHasHyphen(domain):
    match = re.search('-', domain)
    return -1 if match else 1


def urlHasMultiDomain(url):
    # Here, instead of greater than 1 we will take greater than 3 since the greater than 1 condition is when www and
    # country domain dots are skipped
    # Accordingly other dots will increase by 1
    if urlHasIP(url) == -1:
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5]))|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
            url)
        pos = match.end()
        url = url[pos:]
    num_dots = [x.start() for x in re.finditer(r'\.', url)]
    if len(num_dots) <= 3:
        return 1
    elif len(num_dots) == 4:
        return 0
    else:
        return -1





def urlHasFeviconDomain(wiki, soup, domain):
    try:
        for head in soup.find_all('head'):
            for head.link in soup.find_all('link', href=True):
                dots = [x.start() for x in re.finditer(r'\.', head.link['href'])]
                return 1 if wiki in head.link['href'] or len(dots) == 1 or domain in head.link['href'] else -1
        return 1
    except Exception as ex:
        return 0




def abnormal_url(domain, url):
    hostname = domain.name
    match = re.search(hostname, url)
    return 1 if match else -1




def urlHasAnchorDifferentDomain(wiki, soup, domain):
    try:
        i = 0
        unsafe = 0
        for a in soup.find_all('a', href=True):
            # 2nd condition was 'JavaScript ::void(0)' but we put JavaScript because the space between javascript and ::
            # might not be
            # there in the actual a['href']
            if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (
                    wiki in a['href'] or domain in a['href']):
                unsafe = unsafe + 1
            i = i + 1
            # print a['href']
        try:
            percentage = unsafe / float(i) * 100
        except:
            return 1
        if percentage < 31.0:
            return 1
            # return percentage
        elif 31.0 <= percentage < 67.0:
            return 0
        else:
            return -1
    except Exception as ex:
        return 0


def links_in_tags(wiki, soup, domain):
    try:
        i = 0
        success = 0
        for link in soup.find_all('link', href=True):
            dots = [x.start() for x in re.finditer(r'\.', link['href'])]
            if wiki in link['href'] or domain in link['href'] or len(dots) == 1:
                success = success + 1
            i = i + 1

        for script in soup.find_all('script', src=True):
            dots = [x.start() for x in re.finditer(r'\.', script['src'])]
            if wiki in script['src'] or domain in script['src'] or len(dots) == 1:
                success = success + 1
            i = i + 1
        try:
            percentage = success / float(i) * 100
        except:
            return 1

        if percentage < 17.0:
            return 1
        elif 17.0 <= percentage < 81.0:
            return 0
        else:
            return -1
    except Exception as ex:
        return 0



def sfh(wiki, soup, domain):
    try:
        for form in soup.find_all('form', action=True):
            if form['action'] == "" or form['action'] == "about:blank":
                return -1
            elif wiki not in form['action'] and domain not in form['action']:
                return 0
            else:
                return 1
        return 1
    except Exception as ex:
        return 0
    
# here

# Mail Function
# PHP mail() function is difficult to retrieve, hence the following function is based on mailto
def urlHasMail(soup):
    for form in soup.find_all('form', action=True):
        return -1 if "mailto:" in form['action'] else 1
    # In case there is no form in the soup, then it is safe to return 1.
    return 1


#status bar tempered
def statistical_report(url, hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
    except:
        return -1
    url_match = re.search(
        r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
    ip_match = re.search(
        '146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
        '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
        '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
        '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
        '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
        '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
        ip_address)
    if url_match:
        return -1
    elif ip_match:
        return -1
    else:
        return 1

# IFrame Redirection
def urlHasIframe(soup):
    for i_frame in soup.find_all('i_frame', width=True, height=True, frameBorder=True):
        # Even if one iFrame satisfies the below conditions, it is safe to return -1 for this method.
        if i_frame['width'] == "0" and i_frame['height'] == "0" and i_frame['frameBorder'] == "0":
            return -1
        if i_frame['width'] == "0" or i_frame['height'] == "0" or i_frame['frameBorder'] == "0":
            return 0
    # If none of the iframes have a width or height of zero or a frameBorder of size 0, then it is safe to return 1.
    return 1





def get_hostname_from_url(url):
    hostname = url
    # TODO: Put this pattern in patterns.py as something like - get_hostname_pattern.
    pattern = "https://|http://|www.|https://www.|http://www."
    pre_pattern_match = re.search(pattern, hostname)

    if pre_pattern_match:
        hostname = hostname[pre_pattern_match.end():]
        post_pattern_match = re.search("/", hostname)
        if post_pattern_match:
            hostname = hostname[:post_pattern_match.start()]

    return hostname

#TODO: Put the DNS and domain code into a function.
def predict(data):
    f=0
    weight = [3.33346292e-01, -1.11200396e-01, -7.77821806e-01, 1.11058590e-01, 3.89430647e-01, 1.99992062e+00, 4.44366975e-01, -2.77951957e-01, -6.00531647e-05, 3.33200243e-01, 2.66644002e+00, 6.66735991e-01, 5.55496098e-01, 5.57022408e-02, 2.22225591e-01, -1.66678858e-01];
    for j in data:
        f += data[j] * weight[j]
        if f > 0:
            return 1
            print("pass")
        else:
            return -1
            print("fail")

    



def main(url):
    with open('markup.txt', 'r') as file:
        soup_string = file.read()

    soup = BeautifulSoup(soup_string, 'html.parser')

    result = []
    hostname = get_hostname_from_url(url)

    result.append(urlHasIP(url))
    result.append(urlIsLong(url))
    result.append(urlIsShort(url))
    result.append(urlHasAtSymbol(url))
    result.append(urlHasRedirection(url))
    result.append(urlHasHyphen(hostname))
    result.append(urlHasMultiDomain(url))

    dns = 1
    try:
        domain = whois.query(hostname)
    except:
        dns = -1

    #status.append(-1 if dns == -1 else domain_registration_length(domain))

    result.append(urlHasFeviconDomain(url, soup, hostname))
    result.append(urlHasAnchorDifferentDomain(url, soup, hostname))
    result.append(links_in_tags(url, soup, hostname))
    result.append(sfh(url, soup, hostname))
    result.append(urlHasMail(soup))

    result.append(-1 if dns == -1 else abnormal_url(domain, url))

    result.append(urlHasIframe(soup))

    result.append(dns)

    result.append(statistical_report(url, hostname))
    result.append(predict(result))
    print(result)

    yield result  


# Use the below two lines if features_extraction.py is being run as a standalone file. If you are running this file as
# a part of the workflow pipeline starting with the chrome extension, comment out these two lines.
if __name__ == "__main__":

    df_list=[]
    df = pd.read_csv('dataset//Url-dataset.csv')

    # Add the headers to csv
    df_headers = pd.DataFrame(columns=['havingIPAddress','urlLength', 'urlShorteningService',
                'havingAtsymbol','havingDoubleSlash','havingDashSymbol',
                'havingMultipleSubdomains','domainRegistrationLength',
                'Favicon','urlOfAnchor','linksInTags','SFH',
                'submittingToEmail','abnormalUrl','IFrame','dnsRecord','result'])
    
    with open('verified_online.csv', 'a') as f:
        df_headers.to_csv(f, header=True)

    count = 0 
    with open('verified_online.csv', "a+") as fd:
        for url in df.ix[:,0]:
            count +=1
            print "Record written to file " + str(count)
            writer = csv.writer(fd)
            writer.writerows(main(url))



                      
            