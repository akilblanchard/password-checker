import requests
import hashlib
import sys

#Used to send GET request to the pwned passwords api
def request_api_data(query):
    url = "https://api.pwnedpasswords.com/range/" + query
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error Fetching : {res.status_code}, check the api and try again")
    return res

#Splits Password into two parts, calls the respective functions for each part of the password 
def pwned_api_check(password):
    #checks if password exists in api response
   sha1password = (hashlib.sha1(password.encode("utf-8")).hexdigest().upper())
   first5, tail = sha1password[:5], sha1password[5:]
   response = request_api_data(first5)
   return get_password_leaks_count(response, tail)

#Iterates and provides a count if the hash suffix matches
def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(":")for line in hashes.text.splitlines())
    for i, count in hashes:
        if i == hash_to_check:
            return count
    return 0 

#
def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was found {count} times....seems a bit risky.")
        else:
            print(f"{password} was not found. All good Chief!")



main(sys.argv[1:])

