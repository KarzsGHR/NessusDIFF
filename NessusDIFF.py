import xml.etree.ElementTree as ET
from sys import argv
import csv
import argparse

parser = argparse.ArgumentParser(description='NessusDIFF')
parser.add_argument("-o", help="Orgin(First) File")
parser.add_argument("-s", help="Diff(Second) File")
parser.add_argument(
    "-d", help="Diff Direction,1= Orgin - Diff,2= Diff - Orgin", type=int, choices=[1, 2])
parser.add_argument("-c", help="output csv path")
args = parser.parse_args()


class ObjectNessus:
    def parseNessus(self):
        Flist = []
        Ftree = ET.parse(self, parser=None)
        Froot = Ftree.getroot()
        for Parse_report in Froot.iter('Report'):
            for Parse_report_host in Parse_report:
                for Parse_report_host_Vuln in Parse_report_host:
                    if Parse_report_host_Vuln.tag == "HostProperties":
                        for x in Parse_report_host_Vuln:
                            if 'host-ip' in x.attrib.values():
                                IP = x.text
                    for ReportItem in Parse_report_host_Vuln.iter("ReportItem"):
                        pluginID = ReportItem.get('pluginID')
                        port = ReportItem.get('port')
                        severity = ReportItem.get('severity')
                        # Risk visiualization
                        if severity == "0":
                            severity = "Info"
                        elif severity == "1":
                            severity = "Low"
                        elif severity == "2":
                            severity = "Medium"
                        elif severity == "3":
                            severity = "High"
                        elif severity == "4":
                            severity = "Critical"
                        plugin_name = ReportItem.find('plugin_name').text
                        plugin_output = ReportItem.find('plugin_output')
                        if plugin_output is None:
                            plugin_output = "NoResult"
                        else:
                            plugin_output = plugin_output.text
                        Flist.append(
                            [IP, port, severity, pluginID, plugin_name, plugin_output])
        return Flist

    def __str__(self):
        return "WTF"
# Diff Function to set diff return list


def diff(a, b):
    Flist_set = set(map(tuple, a))
    Slist_set = set(map(tuple, b))
    Sd = Flist_set.difference(Slist_set)
    Dd = Slist_set.difference(Flist_set)
    Sd_list = list(Sd)
    Dd_list = list(Dd)
    Sd_list.sort()
    Dd_list.sort()
    return Sd_list, Dd_list


def csvproduce(wlist, outcsv):
    resultFile = open(outcsv, 'w', newline='')
    wr = csv.writer(resultFile, dialect='excel')
    wr.writerows(wlist)


def printdiff(s):
    z = 0
    for x in s:
        print("=" * 20, z, "=" * 20, end='\n')
        for y in range(len(x)):
            print(x[y], ",", sep="")
        z += 1
    

def main():
    if args.o and args.s and args.d and not args.c:
	    a = ObjectNessus.parseNessus(args.o)
	    b = ObjectNessus.parseNessus(args.s)
	    Sd_list, Dd_list = diff(a, b)
	    if args.d == 1:
	    	printdiff(Sd_list)
	    elif args.d == 2:
	        printdiff(Dd_list)
    elif args.o and args.s and args.d and args.c:
        a = ObjectNessus.parseNessus(args.o)
        b = ObjectNessus.parseNessus(args.s)
        Sd_list, Dd_list = diff(a, b)
        if args.d == 1:
            csvproduce(Sd_list, args.c)
            print("CSV Output Finished")
        elif args.d == 2:
            csvproduce(Dd_list, args.c)
            print("CSV Output Finished")
if __name__ == "__main__":
    main()
