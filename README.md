# NessusDIFF
Diff Nessusfile(.nessus) for Vulnerability Analyze

Requirement:
  Python 3

Usage:

-o  <Nessusfile1>

-s  <Nessusfile2>

-d  <Diff>

    1 = Nessusfile1 - Nessusfile2
    
    2 = Nessusfile2 - Nessusfile1
    
-c <export csv>[optional]



Sample:
python3 NessusDIFF.py -o XXXXX.nessus  -s YYYYY.nessus -d 1 

python3 NessusDIFF.py -o XXXXX.nessus  -s YYYYY.nessus -d 1 -c XXX.csv
