from Client import Client
import os, pickle
from timeit import default_timer as timer
import sys
import ast
import argparse
import numpy as np
searchTime = []
client = Client()
client.dumpKeys()
client.initKeyword('Keywords.txt')
client.dump_encrypted_index()
client.dump_search_history()
option = ''
while(option != 'q'):
    print("input 1 to search a keyword")
    print("input 2 to update the index")
    print("input q to quit")
    option = input()
    if(option == '1'):
        option = input("input a keyword: ")
        start = timer()
        client.search(option)
        client.dump_search_history()
        end = timer()
        searchTime.append((end - start)*1000)
        print(">>>>>> average time taken " + str(np.mean(searchTime)) + " ms")
    elif(option == '2'):
        option = input("input a keyword: ")
        fileName = input("input a file name:")
        start = timer()
        client.update(option, fileName)
        client.dump_encrypted_index()
        client.dump_search_history()
        end = timer()
        print('update completed')
        print(">>>>>> time taken " + str((end - start)*1000) + " ms")
        

