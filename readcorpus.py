#!/usr/bin/python

import json, sys, getopt, os

REC = {}

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

  for record in urldata:
    rec_ip = record["ips"].get("ip")
    score = 0
    # Do something with the URL record data...
    REC[rec_ip] = 0
    if record["domain_age_days"] < 188:
      score = score + 1
    if record["host_len"] > 10:
      score = score + 1
    if record["default_port"] != 80 or record["default_port"] != 443:
      score = score + 1
    if record["tld"] not in ("com","net","org","edu"):
      score = score + 1
    if record["alexa_rank"] > 1000000 or record["alexa_rank"] == NULL:
      score = score + 1
    if record["num_domain_tokens"] > 3:
      score = score + 1

    REC[rec_ip] = score

  for r,s in REC:
    print(r,s)

  corpus.close()

if __name__ == "__main__":
  main(sys.argv[1:])
