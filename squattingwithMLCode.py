# %%

from urllib.parse import urlparse,parse_qs
import pandas as pd
import ipaddress
import re
import random
from matplotlib import pyplot as plt
from sklearn.metrics import confusion_matrix, accuracy_score, recall_score
from Levenshtein import distance
from thefuzz import fuzz
import pickle
import math

# %%
#reading the brand names csv file and appending one of its column i.e domain's entries to a list brand_names
import csv

def read_brand_names_from_csv (file_path, column_index):
    brand_names = []
    with open(file_path, 'r', encoding='utf-8-sig') as csvfile:
        reader = csv.reader(csvfile)       
        for row in reader:           
                brand_name = row[column_index]                
                brand_names.append(brand_name)             
    return brand_names

# %%
#calling the fucntion to append csv file data of brands to a list

brand_names_file = "sample_brands_new.csv"
brand_names_column = 0  
brand_names = read_brand_names_from_csv(brand_names_file, brand_names_column)
print(brand_names)

# %%
#Reading the dataset .txt file and appending its entries of label and urls into seperate lists. Also count the number of phishing and genuine entries
dataset = []
labels = []
links = []

# dataset_file="dataset23_10_23_shuffled.csv"
dataset_file="first5000.csv"
dataset_column=1
label_column=0

with open(dataset_file, 'r', encoding='utf-8-sig') as csvfile:
        reader = csv.reader(csvfile)       
        for row in reader:           
                url = row[dataset_column]                
                links.append(url) 
                label=row[label_column]  
                labels.append(label)
print(links)
given_result = []
cnt_legit = 0
cnt_phish = 0
for x in labels:
       if x=="phishing":
              cnt_phish += 1
              given_result.append(1)
       else:
              cnt_legit += 1
              given_result.append(0)

# %%
#creating a list of domains i.e domain_list which is without www 

import tldextract
def extract_domain(url):
       domain = urlparse(url).netloc    
       if domain.startswith("www."):
              domain = domain[4:]
       return domain


domain_list = []
for x in links:
    domain = extract_domain(x)
    domain_list.append(domain)

# %%
#creating a function to return domain without the top level domains..
import tldextract
def domain_without_tld(dom):
    extracted=tldextract.extract(dom) 
    return extracted.domain  

# %%
#creating a function to return only the top level domain of a particular domain
def tld(dom):
    extracted=tldextract.extract(dom)
    return extracted.suffix

# %%
#function to return the subdomain..if present.
def subdomain(dom):
    extracted=tldextract.extract(dom)
    if extracted.subdomain !='':
            return extracted.subdomain
    else:
            return ''

# %%
#function to return the path and hostname of a URL
def extract_path(url):
    parsed_url = urlparse(url)
    path = parsed_url.path     
    netloc=parsed_url.netloc     
    return (path,netloc)


# %%
#function to create sublists of URLs which contain a primary domain..eg google.com, co.in, play.google,googleapis,facebook,facebooklive..
def create_sublists(brand_list):
    sublists = {}
    for entry in brand_list:        
        if len(domain_without_tld(entry))>=6: 
             
            brand_found = False
            for brand_name in sublists:               
                if brand_name in entry:                
                    sublists[brand_name].append(entry)
                    brand_found = True
                    break             
            if not brand_found:
                brand_name = domain_without_tld(entry)
                sublists[brand_name] = [entry]

    return sublists

sublists = create_sublists(brand_names)
for brand_name, sublist in sublists.items():
    print(f"Brand: {brand_name}")
    print("Sublist:")
    print(sublist)
    print()

# %%
# 1.function to check if  brand name is present in the path without any seperator i.e - or _ or %
def is_brand_in_path(url): 
    print("path is:"+extract_path(url)[0])
    domain=domain_without_tld(extract_domain(url))
    if extract_path(url)[0]!='/' and extract_path(url)[0]!='':                                                                          
        """brand_in_domain=0  
        print("inside first if of path")  
        for brand_name,sublist in sublists.items():  # to check whether theres a brand as domain eg google            
            if domain_without_tld(extract_domain(url))==brand_name: 
                if extract_domain(url) in sublist:  #checks only the particular brand sublist..eg play.google.com                
                    brand_in_domain=1
                    print("brand in domain now check for path")                  
        for brand_name,sublist in sublists.items():           
                print(extract_path(url)[0]+"to b matched with brand: "+ brand_name)
                if len(domain_without_tld(brand_name))>=6:
                    if brand_name in (extract_path(url)[0]).lower() and brand_in_domain==0: 
                        print("brand in path is true")
                        return 1"""
        for brand_name, sublist in sublists.items():
            special_symbol=['-','_','%']
            if brand_name in (extract_path(url)[0]).lower():
                brand_in_path=1
                for special in special_symbol:                
                    if special+brand_name in (extract_path(url)[0]).lower() or brand_name+special in (extract_path(url)[0]).lower() or (brand_name==domain and brand_name in (extract_path(url)[0]).lower()) :
                        brand_in_path=0
                        return 0
                    
                if brand_in_path==1:
                    return 1           
    return 0



# %%
#2.function to check if brand name or missplet brand name is present in the subdomain of the suspicious URL (also handles if present as a substring)
                 #example- facebook.abc.com or thisismyfakebook.abc.com
 

def brand_in_subdomain(domain,threshold=73):
    brand_in_subdomain=0
    if subdomain(domain)!='':        
        if '.' in subdomain(domain) or '_' in subdomain(domain) or '-' in subdomain(domain):
            print("dot in subdomain")
            subdomain_tokens= re.split(r'[._-]', subdomain(domain))
            print(subdomain_tokens)
            for subdomain_token in subdomain_tokens:
                for brand,sublist in sublists.items():                                                 
                    if len(brand)>=6 and len(subdomain_token)>=6: 
                        print(" suspicious subdomain"+subdomain_token.lower()+ "2 b matched with "+brand )                       
                        pr=(fuzz.partial_ratio(brand,subdomain_token.lower())+fuzz.ratio(brand,subdomain_token.lower()))/2
                        print(pr) 
                        if abs(len(brand)-len(subdomain_token)) <=2:  #use levenstein distance for terms with diff in length <=2
                            if distance(brand,subdomain_token)==0:
                                print("subdomain same as a brand")
                                brand_in_subdomain=1
                                break                    
                            elif 0 < distance(brand,subdomain_token)<=2 or 100> pr>=threshold:
                                print("misspelt brand in subdomain returned true")
                                brand_in_subdomain=1
                                break
                        else:                                 
                                            
                            if fuzz.partial_ratio(brand,subdomain_token.lower())==100 and len(subdomain_token)>=len(brand):
                                print(brand  +"brand in or as substring in subdomain")        
                                brand_in_subdomain=1
                                break
                            else:
                                if 100>pr>=threshold:
                                    print(" subdomain is a missplet brand"+brand)            
                                    brand_in_subdomain=1 
                                    break
                if brand_in_subdomain==1:
                   break                
        else:
                print("no dot in subdomain")
                for brand,sublist in sublists.items():           
                    print(" suspicious subdomain"+subdomain(domain).lower()+ "2 b matched with "+brand ) 
                    if len(brand)>=6 and len(subdomain(domain))>=6: 
                        pr=(fuzz.partial_ratio(brand,subdomain(domain).lower())+fuzz.ratio(brand,subdomain(domain).lower()))/2
                        print(pr) 
                        if abs(len(brand)-len(subdomain(domain))) <=2:  #use levenstein distance for terms with diff in length <=2
                            if distance(brand,subdomain(domain))==0:
                                print("subdomain same as a brand")
                                brand_in_subdomain=1
                                break                    
                            elif 0 < distance(brand,subdomain(domain))<=2 or pr>=threshold:
                                print("misspelt brand in subdomain returned true")
                                brand_in_subdomain=1
                                break
                        else:                                 
                                            
                            if fuzz.partial_ratio(brand,subdomain(domain).lower())==100:
                                print(brand  +"brand in or as substring in subdomain")        
                                brand_in_subdomain=1
                                break
                            else:
                                if 100>pr>=threshold:
                                    print(" subdomain is a missplet brand"+brand)            
                                    brand_in_subdomain=1 
                                    break                           
    if brand_in_subdomain==1:
        return 1
    else:
        return 0                   



# %%
#3.function to check if a domain has a brand as substring example- dffdamazondsf.com
def brand_as_substring_in_domain(domain): 
    brand_as_substring=0 
    brand_found=0   
    for brand,sublist in sublists.items(): 
        if brand_found==1:
            break
        if len(brand)>=6 and len(domain_without_tld(domain))>=6 and len(domain_without_tld(domain))>len(brand):                     
            print(domain_without_tld(domain).lower()+"2 b matched for brand as substring in domain  :"+ brand)
            pr=fuzz.partial_ratio(brand,domain_without_tld(domain).lower())       
            if pr==100:             #means if brand is either same or a substring in domain
                if brand!=domain_without_tld(domain).lower() :  #means the brand is not same as the domain..hence substring
                    brand_as_substring=1
                    brand_found=1
                    print(domain_without_tld(domain) +" has a substring of "+brand)
                    print(sublist)
                    for entry in sublists[brand]:  #to check if the brand as substring is genuine or not..eg-facebooklive.com
                        
                        if domain_without_tld(domain)== domain_without_tld(entry):
                            print("domain match with sublist entry..so genuine")
                            brand_as_substring=0                             
                            break                        
                    #if domain is same as the brand                    
                else:
                    break     
                 
    if brand_as_substring==1:
        return 1
    else:
        return 0    
    


# %%
#4.function to check if a domain has typosquatting of a brand..eg-anazom.com or shopanazom.com((also handles if present as a substring)
def brand_typo_in_domain(domain,brand_names,threshold=73):
    brand_typo=0    
    for brand,sublist in sublists.items(): 
            print("suspicious domain:"+domain_without_tld(domain)+"2 b matchd with:"+ brand)
            if len(brand)>=6 and len(domain_without_tld(domain))>=6:
                pr=(fuzz.partial_ratio(brand,domain_without_tld(domain).lower())+fuzz.ratio(brand,domain_without_tld(domain).lower()))/2
                print(pr)
                if abs(len(brand)-len(domain_without_tld(domain))) <=2:  #use levenstein distance for terms with diff in length <=2
                    if len(brand)>=7 or len(domain_without_tld(domain))>=7:
                        if  distance(brand,domain_without_tld(domain))==0:
                            break
                        elif 0 < distance(brand,domain_without_tld(domain))<=2 or pr>=threshold:
                            print("works with levenshtein for:"+brand)
                            brand_typo=1
                            break
                else:                                                         
                    
                    print(any(char.isupper() for char in domain_without_tld(domain)))
                    if fuzz.partial_ratio(brand,domain_without_tld(domain).lower())==100 and any(char.isupper() for char in domain_without_tld(domain))==False:
                        print("it came here")
                        break
                    if fuzz.partial_ratio(brand,domain_without_tld(domain).lower())==100 and brand == domain_without_tld(domain).lower() and any(char.isupper() for char in domain_without_tld(domain))==True:                        
                        brand_typo=1     #domain is same as a brand but with some capital letters
                        break
                    if 100>pr>=threshold:   # means brand is not preset as a substring or as a whole in the domain but is similar
                        print("partial ratio of domain >threshold")            
                        print(pr)
                        brand_typo= 1
                        break
               
    if brand_typo==1:
        return 1
    else:           
        return 0    
        

# %%
#5.function to check if a URL has same domain as a brand but with a fake TLD
def brand_with_fake_tld(domain): 
    print("in func for fake tld")
    print("suspicious :"+domain) 
    fake_tld=0     
    for brand,sublist in sublists.items():                                          
        if brand in domain_without_tld(domain).lower():   #checks if the domain matches with the sublist head..eg-google         
            print("matched with brand.now check the sublist")
            for entry in sublists[brand]:                  #now check the sublist for the matched brand eg-googledrive,topgoogle,facebooklive
                print("sublist entry is:"+entry)
                if domain_without_tld(domain).lower()==domain_without_tld(entry):   #if domain matches with an entry in the sublist
                    fake_tld=1
                    if tld(domain)==tld(entry):                             #but not with the top level domain 
                         fake_tld=0
                         break
            break
            
    if fake_tld==1:
        return 1
    else:               
        return 0   
          

# %%
#6.function returns 1 if '//' is present in the path or query portion of the url
def doubleslash(url):
    parsed_url = urlparse(url)
    for component in [parsed_url.netloc, parsed_url.path, parsed_url.params, parsed_url.query, parsed_url.fragment]:
        if '//' in component:
            return 1
    
    return 0  
    

# %%

#7. Checks for IP address in the hostname (Have_IP)
def havingIP(url):
    domain=extract_domain(url)
    ip = None    
    # Regular expression pattern to match IPv4 and IPv6 addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    
    # Search for IP addresses in the input string
    match = re.search(ip_pattern, domain)
    
    if match:
        ip = match.group()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            ip = None
    if ip!=None:
        return 1
    else:
        return 0


# %%
#8.function returns 1 if no.of dots in path>2
def dots_in_path(url):
    path=extract_path(url)[0]
    """if path.count('.')>2:
        return 1
    else:
        return 0"""

    return path.count('.')    

# %%
#9.function to count '/' in the URL path
def path_depth(url):
    path=extract_path(url)[0]
    """if path.count('/')>5:
        print(path.count('/'))
        return 1    
    else:
        return 0"""
    return path.count('/')

# %%
#10.function to get the length of URL
def getURLlength(url):  
    print(len(url))          
    """if len(url) > 140:
              print(len(url))
              return 1
       return 0"""
    return (len(url))


# %%
#11.Existence of “HTTP" Token in the Domain Part of the URL (https_Domain)
def checkhttpDomain(url):
       domain = urlparse(url).netloc
       if 'http' in domain:
              return 1
       else:
              return 0

# %%
#12.function to check presence of hyphen or underscore in domain
def checkHyphenUnderscore(url):
       domain = extract_domain(url)       
       if '-' in domain or '_' in domain:
              return 1
       else:       
              return 0

# %%
 #13. Check for numerical characters in the domain
def has_numerical_characters(url):
       domain = extract_domain(url)
       if any(char.isdigit() for char in domain):
              return 1
       else:
              return 0

# %%
#14.function returns 1 if no.of dots in hostname >3....i.e more than 2 subdomains
def dots_in_hostname(url):
    domain=extract_domain(url)
    """if domain.count('.')>3 and havingIP(url)!=1:    #needs to be checked that the dots are not for IP
        return 1
    else:
        return 0"""
    return domain.count('.')

# %%
#15.to check if length of longest token in domain>15
def longest_token_in_domain(url):
    domain = urlparse(url).netloc
    tokens = re.split(r'[._-]', domain)
    print(tokens)
    longest_length = max(len(token) for token in tokens)
    print(longest_length)
    """if longest_length >= 15:
        return 1
    else:
        return 0   """

    return longest_length     

# %%
#16. check presence of URL shortener
def is_url_shortener(url):
    short=0
    shortening_services =   ["goo.gl","shorte.st","go2l.ink","x.co","ow.ly","t.co","tinyurl","tr.im","is.gd","cli.gs", 
    "yfrog.com","migre.me","ff.im","tiny.cc","url4.eu","twit.ac","su.pr","twurl.nl","snipurl.com", 
    "short.to","BudURL.com","ping.fm","post.ly","Just.as","bkite.com","snipr.com","fic.kr","loopt.us", 
    "doiop.com","short.ie","kl.am","wp.me","rubyurl.com","om.ly","to.ly","bit.do","t.co","lnkd.in","db.tt", 
    "qr.ae","adf.ly","goo.gl","bitly.com","cur.lv","tinyurl.com","ow.ly","bit.ly","ity.im","q.gs", 
    "po.st","bc.vc","twitthis.com","u.to","j.mp","buzurl.com","cutt.us","u.bb","yourls.org","x.co","" 
    "prettylinkpro.com","scrnch.me","filoops.info","vzturl.com","qr.net","1url.com","tweez.me","v.gd", 
    "tr.im","link.zip.net","t.ly","shrtco.de","s.id","shorturl.ac","ko.gl","tiny.one","shorturl.at","rd.gy","bitly.ws","urlz.fr","short.gy",
    "cli.co","cli.re","tiny.pl","bre.is","vu.fr","v.ht","urle.me","gg.gg","twtr.to","pxlme.me"]

    
    domain =  urlparse(url).netloc.lower()    
    for short_domain in shortening_services:
        if  domain== short_domain:
            short= 1
            break

    if short==1:
        return 1
    else:
        return 0  

    

# %%
#17.check if length of hostname >30
def getdomainlength(url):
    domain=extract_domain(url)
    print("domain length")    
    if len(domain)>30:
        print(len(domain))
        """return 1
    else:
        return 0"""
    return len(domain)    

# %%
#18. presence of # in the URL
def url_hash(url):    
    if '#' in url and '#_=_' not in url and '#!' not in url:
        return 1
    else:       
        return 0



# %%
#19. Checks presence of puny code in the domain
def puny_code(url):
   
    if 'xn--' in url :
        return 1
    else:
        return 0                

       

# %%
#20. presence of @ in url
def at_in_url(url):
    
    if '@' in url:
        return 1
    else:
        return 0

# %%
#21.function to detect gibbereish in domain of length>=10
model_data = pickle.load(open('gib_model.pki', 'rb'))

def normalize(line):
    """ Return only the subset of chars from accepted_chars.
    This helps keep the  model relatively small by ignoring punctuation, 
    infrequenty symbols, etc. """

    accepted_chars = 'abcdefghijklmnopqrstuvwxyz '
    return [c.lower() for c in line if c.lower() in accepted_chars]

def ngram(n, l):
    """ Return all n grams from l after normalizing """
    filtered = normalize(l)
    for start in range(0, len(filtered) - n + 1):
        yield ''.join(filtered[start:start + n])

def avg_transition_prob(l, log_prob_mat):
    """ Return the average transition prob from l through log_prob_mat. """
    accepted_chars = 'abcdefghijklmnopqrstuvwxyz '
    pos = dict([(char, idx) for idx, char in enumerate(accepted_chars)])

    log_prob = 0.0
    transition_ct = 0
    for a, b in ngram(2, l):
        log_prob += log_prob_mat[pos[a]][pos[b]]
        transition_ct += 1
    # The exponentiation translates from log probs to probs.
    return math.exp(log_prob / (transition_ct or 1))

def detect_noisy_domains(inpUrl):
    model_mat = model_data['mat']
    threshold = model_data['thresh']

    domain = domain_without_tld(inpUrl)
    
    subdom=subdomain(inpUrl)
    noiseFlagdomain = 0
    noiseFlagsubdomain=0
    if (len(domain) >= 10):
        #validFlag = avg_transition_prob(domainName, model_mat) > threshold
        noiseFlagdomain = avg_transition_prob(domain, model_mat) <= threshold
    if (len(subdom) >= 10):
            #validFlag = avg_transition_prob(domainName, model_mat) > threshold
            noiseFlagsubdomain = avg_transition_prob(subdom, model_mat) <= threshold
            #validFlag = avg_transition_prob(domainName, model_mat) > threshold
            
    if noiseFlagdomain ==1 or noiseFlagsubdomain==1:  # 1 for noise domains else 0 
        return 1
    else:
        return 0 


# %%
#22. Function to detect presence of free web hosting domains
def free_domain(domain):
    freeDomain=["ipage", "wix","weebly","hostinger","ionos","bluehost","ovhcloud","crazydomains","duckdns","cloudns","ddns","freeddns","dynssl","opendns",
    "freedns", "amplifyapp","netlify","jungleheart","webhostingfree","formaloo","webwave","firebaseapp","ipfs","pinata.cloud","nftstorage.link","rebrand.ly",
    "pages.dev","jemi.so",".icu","repl.co","otzo.com","dnset.com","justdied.com","organiccrap.com"]
    for free in freeDomain:
        if free in domain:
            return 1        
    return 0    

# %%
# Function to extract features
def featureExtraction(url, label):
       features = []
       features.append(url)
       features.append(is_brand_in_path(url))                               #1
       features.append(brand_in_subdomain(extract_domain(url)))             #2       
       features.append(brand_as_substring_in_domain(extract_domain(url)))   #3
       features.append(brand_typo_in_domain(extract_domain(url),brand_names))  #4
       features.append(brand_with_fake_tld(extract_domain(url)))      #5
       features.append(doubleslash(url))                #6
       features.append(havingIP(url))                   #7
       features.append(dots_in_path(url))               #8
       features.append(path_depth(url))                 #9
       features.append(getURLlength(url))               #10
       features.append(checkhttpDomain(url))            #11
       features.append(checkHyphenUnderscore(url))      #12
       features.append(has_numerical_characters(url))   #13
       features.append(dots_in_hostname(url))           #14
       features.append(longest_token_in_domain(url))    #15
       features.append(is_url_shortener(url))           #16
       features.append(getdomainlength(url))            #17
       features.append(url_hash(url))                   #18
       features.append(puny_code(url))                  #19
       features.append(at_in_url(url))                 #20
       features.append(detect_noisy_domains(extract_domain(url)))        #21
       features.append(free_domain(extract_domain(url))) #22

       if label=='phishing':
              features.append(1)
       else:
              features.append(0)

       return features

# %%
features_vector = []
# for i in range(0,36350): 
for i in range(0,5000):
       print(i, end='\t')
       print(links[i], end='\n')
       features_vector.append(featureExtraction(links[i], labels[i])) 

# %%
features_name = ['url', 'brand_path', 'brand_subdomain', 'brand_substring_dom', 'brand_typo_dom', 'fake_tld','double_slash', 'have_IP', 'dots_path', 'path_depth', 'URL_length' , 'http_dom', 'dom_seperator','numbers_host', 'dots_host','long_token_dom','tiny_url','dom_length','url_hash','puny_code','@_url','gibberish','free_domain', 'label']

df = pd.DataFrame(features_vector, columns=features_name)
#df = pd.DataFrame(features_vector)
df.head(100)

# %%

df.to_csv('features_extracted_new_31_10_23.csv', mode='a', index=False)


