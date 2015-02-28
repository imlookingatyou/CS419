#
# Week 7 - Lab 2 - The Great Host/Lexical URL Reputation Bake-off
# CS419 - Defense Against the Dark Arts
#
# Michael Depuy
# Jonathan McNeil 
# Marie Caswell
#

#!/usr/bin/python

import json, sys, getopt, os

REC = {} #empty dictionary structure to store url:score

# Note: I changed the REC{} format to store the URL 
# instead of the IP address since lab2.pdf says 
# that our final output file needs to be in the format 
# <url string>, <malicious bit> (where 1 =malicious, and 0=safe)

def usage():
  print("Usage: %s --file=[filename]" % sys.argv[0])
  sys.exit()

def main(argv):

  file=''
 
  myopts, args = getopt.getopt(sys.argv[1:], "", ["file="])
 
  for o, a in myopts:
    if o in ('-f, --file'):
      file=a
    else:
      usage()

  if len(file) == 0:
    usage()
 
  corpus = open(file)
  urldata = json.load(corpus, encoding="latin1")
  print len(urldata)
  domain_age_total = 0

  for record in urldata:
    rec_url = record['url']
    score = 0

    
    # Do something with the URL record data...
    
    REC[rec_url] = 0
    


    if record["domain_age_days"] < 188:
      score = score + 1
    # I made this rule by taking the average domain age of the data set.  I noticed that not a single domain above this average was malicious.
    if record["domain_age_days"] > 1300:
      score = score - 1
    if record["host_len"] > 10:
      score = score + 1
    if record["default_port"] != 80 or record["default_port"] != 443:
      score = score + 1
    if record["tld"] not in ("com","net","org","edu"):
      score = score + 1
    if record["alexa_rank"] > 1000000 or record["alexa_rank"] == None:
      score = score + 1
    if record["num_domain_tokens"] > 3:
      score = score + 1
    # It stands to reason that links with an executable file have a beter chance of being malicious.  
    if record['file_extension'] in ('exe'):
      score = score + 1


    REC[rec_url] = score

  output = open('output.txt','w') #delete any old data from the output file
  output.truncate(0)
  output.close()

  for r,s in REC.iteritems():
    with open('output.txt', 'a') as output:     #open output file in append mode
      print(r,s)
      output.write('%s, %s\n' % (r, str(s))) #write new data to file

  corpus.close()
  output.close()

if __name__ == "__main__":
  main(sys.argv[1:])
