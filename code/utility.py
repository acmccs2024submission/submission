import os
import angr
import networkx as nx
from angrutils import *
import glob
import sys
from queue import LifoQueue
from operator import add
import subprocess
import numpy as np
import math
import cv2
import matlab
from sklearn import preprocessing
import glob

'''
read files in a directory
'''


def readFiles(inp_dir):
    os.chdir(inp_dir)  # the parent fold with sub-folders
    list_projs = os.listdir(os.getcwd())  # vector of strings with project name
    no_projs = []  # No. of samples per family

    for file in range(len(list_projs)):
        os.chdir(list_projs[file])  # sub-folder
        no_per_proj = len(glob.glob('*'))  # calculate the num of files in each proj
        no_projs.append(no_per_proj)
        os.chdir('..')  # get back to parent folder
    return no_projs, list_projs


"""
use static analysis to generate control 
flow graph
"""


def cfgFast():
    proj = angr.Project('/Users/zhong/Downloads/fauxware', load_options={'auto_load_libs': False})
    cfg = proj.analyses.CFGFast()  # contruct control flow graph
    callgraph = cfg.kb.functions.callgraph
    print(callgraph)
    black_list = ('frame_dummy', 'call_gmon_start', 'UnresolvableCallTarget', 'UnresolvableJumpTarget')
    # getSuccessors(cfg, callgraph, proj.entry)
    getPredemulated(cfg, callgraph, proj.entry)
    getSuccemulated(cfg, callgraph, proj.entry)


"""
use dynamic analysis to generate control flow graph
"""


def cfgEmulated():
    proj = angr.Project('/Users/zhong/Downloads/fauxware', load_options={'auto_load_libs': False})
    cfg = proj.analyses.CFGEmulated()  # contruct control flow graph
    callgraph = cfg.kb.functions.callgraph
    print(callgraph)
    black_list = ('frame_dummy', 'call_gmon_start', 'UnresolvableCallTarget', 'UnresolvableJumpTarget')
    successorsFilter(cfg, callgraph, proj.entry)
    predecessorsFilter(cfg, callgraph, proj.entry)


"""
:param cfg: control flow graph
:param callgraph: function-level call graph 
:param begin_addr: program entry point
"""


def getSuccessors(cfg, callgraph, begin_addr):
    lfunc_name = []
    di_succ_by_addrs = {}  # key: current function's address, value: successors' addresses
    di_succ_addrs = {}  # key: current function name, value: successors' addresses
    di_succ_by_name = {}  # key: current function's address, value:successors' names
    di_succ_names = {}  # key: current function name, value: successors' names
    di_succ_by_num = {}  # key: current function's address, value:successors' names
    di_num_succ = {}  # key:current function name, value: no. of successors
    for succ_addr in nx.bfs_successors(callgraph, begin_addr):
        # print("succ_addr", succ_addr)
        curr_func_addr, succ_addrs = succ_addr
        if not di_succ_by_addrs.get(curr_func_addr):
            di_succ_by_addrs[curr_func_addr] = succ_addrs
        else:
            di_succ_by_addrs[curr_func_addr] = list(set(di_succ_by_addrs[curr_func_addr] + succ_addrs))

        curr_func = cfg.kb.functions[curr_func_addr]
        lfunc_name.append(curr_func.name)
        if not di_succ_addrs.get(curr_func.name):
            di_succ_addrs[curr_func.name] = succ_addrs
        else:
            di_succ_addrs[curr_func.name] = list(set(di_succ_addrs[curr_func.name] + succ_addrs))
    print("di_succ_by_addrs", di_succ_by_addrs)
    print("di_succ_addrs", di_succ_addrs)

    for curr_func_addr, succ_addrs in di_succ_by_addrs.items():
        succ_name = []
        for succ_addr in succ_addrs:
            func_succ = cfg.kb.functions[succ_addr]
            succ_name.append(func_succ.name)
        if not di_succ_by_name.get(curr_func_addr):
            di_succ_by_name[curr_func_addr] = succ_name
        else:
            di_succ_by_name[curr_func_addr] = di_succ_names[curr_func_addr] + succ_name
    print("di_succ_by_name", di_succ_by_name)

    for curr_func_name, succ_addrs in di_succ_addrs.items():
        succ_name = []
        for succ_addr in succ_addrs:
            func_succ = cfg.kb.functions[succ_addr]
            succ_name.append(func_succ.name)
        if not di_succ_names.get(curr_func_name):
            di_succ_names[curr_func_name] = succ_name
        else:
            di_succ_names[curr_func_name] = di_succ_names[curr_func_name] + succ_name
    print("di_succ_names", di_succ_names)

    for curr_func_addr, succ_name in di_succ_by_name.items():
        if not di_succ_by_num.get(curr_func_addr):
            di_succ_by_num[curr_func_addr] = len(succ_name)
        else:
            di_succ_by_num[curr_func_addr] = di_succ_by_num[curr_func_addr] + len(succ_name)
    print("di_succ_by_num", di_succ_by_num)

    for curr_func_name, succ_name in di_succ_names.items():
        if not di_num_succ.get(curr_func_name):
            di_num_succ[curr_func_name] = len(succ_name)
        else:
            di_num_succ[curr_func_name] = di_num_succ[curr_func_name] + len(succ_name)
    print("di_num_succ", di_num_succ)
    return di_succ_by_addrs, di_succ_addrs, di_succ_by_name, di_succ_names, di_succ_by_num, di_num_succ


"""
:param cfg: control flow graph
:param callgraph: function-level call graph 
:param begin_addr: program entry point
"""


def getPredecessors(cfg, callgraph, begin_addr):
    di_pred_by_addrs = {}
    di_pred_addrs = {}
    di_pred_by_names = {}
    di_pred_names = {}
    di_pred_by_num = {}
    di_num_pred = {}

    for curr_func_addr, preds in nx.predecessor(callgraph, begin_addr).items():
        if not di_pred_by_addrs.get(curr_func_addr):
            di_pred_by_addrs[curr_func_addr] = preds
        else:
            di_pred_by_addrs[curr_func_addr] = di_pred_by_addrs[curr_func_addr] + preds

        curr_func = cfg.kb.functions[curr_func_addr]
        if not di_pred_addrs.get(curr_func.name):
            di_pred_addrs[curr_func.name] = preds
        else:
            di_pred_addrs[curr_func.name] = di_pred_addrs[curr_func.name] + preds
    print("di_pred_by_addrs", di_pred_by_addrs)
    print("di_pred_addrs", di_pred_addrs)

    for curr_func_addr, pred_addrs in di_pred_by_addrs.items():
        if pred_addrs:
            pred_func_name = []
            for pred_addr in pred_addrs:
                pred_func = cfg.kb.functions[pred_addr]
                pred_func_name.append(pred_func.name)
            if not di_pred_by_names.get(curr_func_addr):
                di_pred_by_names[curr_func_addr] = pred_func_name
            else:
                di_pred_by_names[curr_func_addr] = di_pred_by_names[curr_func_addr] + pred_func_name
        else:
            di_pred_by_names[curr_func_addr] = []
            continue
    print("di_pred_by_names", di_pred_by_names)

    for curr_func_name, pred_addrs in di_pred_addrs.items():
        if pred_addrs:
            pred_func_name = []
            for pred_addr in pred_addrs:
                pred_func = cfg.kb.functions[pred_addr]
                pred_func_name.append(pred_func.name)
            if not di_pred_names.get(curr_func_name):
                di_pred_names[curr_func_name] = pred_func_name
            else:
                di_pred_names[curr_func_name] = di_pred_names[curr_func_name] + pred_func_name
        else:
            di_pred_names[curr_func_name] = []
            continue
    print("di_pred_names", di_pred_names)

    for curr_func_addr, pred_names in di_pred_by_names.items():
        if pred_names:
            if not di_pred_by_num.get(curr_func_addr):
                di_pred_by_num[curr_func_addr] = len(pred_names)
            else:
                di_pred_by_num[curr_func_addr] = di_pred_by_num[curr_func_addr] + len(pred_names)
        else:
            di_pred_by_num[curr_func_addr] = 0
    print("di_pred_by_num", di_pred_by_num)

    for curr_func_name, pred_names in di_pred_names.items():
        if pred_names:
            if not di_num_pred.get(curr_func_name):
                di_num_pred[curr_func_name] = len(pred_names)
            else:
                di_num_pred[curr_func_name] = di_num_pred[curr_func_name] + len(pred_names)
        else:
            di_num_pred[curr_func_name] = 0
    print("di_num_pred", di_num_pred)
    return di_pred_by_addrs, di_pred_addrs, di_pred_by_names, di_pred_names, di_pred_by_num, di_num_pred


"""
:param cfg: control flow graph
:param callgraph: call graph
:param begin_addr: program entry point
:return: di_succ_by_addrs: a dictionary with key: current function's addr, value: successor's addrs
         di_succ_addrs: a dictionary with key: current function name, value: successors' addrs
         di_succ_by_name: a dictionary with key: current function's addr, value:successors' names
         di_succ_names: a dictionary with key: current function's name, value: successors' names
         di_succ_by_num: a dictionary with key: current function's addr, value:no. of successors
         di_num_succ: a dictionary with key: current function name, value: no. of successors
"""


def getSuccemulated(cfg, callgraph, begin_addr):
    lfunc_name = []  # save all current function names
    di_succ_by_addrs = {}
    di_succ_addrs = {}
    di_succ_by_name = {}
    di_succ_names = {}
    di_succ_by_num = {}
    di_num_succ = {}
    '''
       contruct  di_succ_by_addrs and di_succ_addrs
    '''
    for succ_addr in nx.bfs_successors(callgraph, begin_addr):
        # print("succ_addr", succ_addr)
        curr_func_addr, succ_addrs = succ_addr
        # if succ_addrs:
        if not di_succ_by_addrs.get(curr_func_addr):  # key curr func addr not exists
            di_succ_by_addrs[curr_func_addr] = succ_addrs  # create the key with value succ addrs
        else:  # already exists
            di_succ_by_addrs[curr_func_addr] = list(
                set(di_succ_by_addrs[curr_func_addr] + succ_addrs))  # combine the old and new

        try:  # if curr func addr points to a func
            '''
                    create a dict with key: curr_func.name, value: succ_addrs
                    '''
            curr_func = cfg.kb.functions[curr_func_addr]
            lfunc_name.append(curr_func.name)
            if not di_succ_addrs.get(curr_func.name):
                di_succ_addrs[curr_func.name] = succ_addrs
            else:
                di_succ_addrs[curr_func.name] = list(set(di_succ_addrs[curr_func.name] + succ_addrs))
        except:  # it isn't a func
            '''
                    create a dict with key: use curr_func_addr as name, value: succ_addrs
                    '''
            lfunc_name.append(curr_func_addr)
            if not di_succ_addrs.get(curr_func_addr):
                di_succ_addrs[curr_func_addr] = succ_addrs
            else:
                di_succ_addrs[curr_func_addr] = list(set(di_succ_addrs[curr_func_addr] + succ_addrs))
    # else:

    print("di_succ_by_addrs", di_succ_by_addrs)
    print("di_succ_addrs", di_succ_addrs)

    '''
       construct di_succ_by_name by using di_succ_by_addrs(curr_func_addr, succ_addrs)
    '''
    for curr_func_addr, succ_addrs in di_succ_by_addrs.items():
        succ_name = []
        for succ_addr in succ_addrs:
            try:  # succ_addr points to a func
                '''
                   get succ's name
                '''
                func_succ = cfg.kb.functions[succ_addr]
                succ_name.append(func_succ.name)
            except:  # not a func
                '''
                    use succ_addr as name
                '''
                succ_name.append([succ_addr])
        if not di_succ_by_name.get(curr_func_addr):  # key curr_func_addr not exist, create one with value succ_name
            di_succ_by_name[curr_func_addr] = succ_name
        else:  # already exists, combine the old and new
            di_succ_by_name[curr_func_addr] = di_succ_names[curr_func_addr] + succ_name
    print("di_succ_by_name", di_succ_by_name)

    '''
       construct di_succ_names by using di_suu_addrs(curr_func_name, succ_addrs)
    '''
    for curr_func_name, succ_addrs in di_succ_addrs.items():
        succ_names = []
        for succ_addr in succ_addrs:
            try:  # succ_addr points to a function, save its name
                func_succ = cfg.kb.functions[succ_addr]
                succ_names.append(func_succ.name)
            except:  # otherwise, save its addr as name
                succ_names.append([succ_addr])

        if not di_succ_names.get(curr_func_name):  # if not exists, create one with its succ's names
            di_succ_names[curr_func_name] = succ_names
        else:  # already exists, combine the old and new
            di_succ_names[curr_func_name] = di_succ_names[curr_func_name] + succ_names
    print("di_succ_names", di_succ_names)

    '''
       create di_succ_by_num by di_succ_by_name (curr_func_addr, succ_names)
    '''
    for curr_func_addr, succ_names in di_succ_by_name.items():
        if not di_succ_by_num.get(curr_func_addr):  # if not exists, create one with no. of succs
            di_succ_by_num[curr_func_addr] = len(succ_names)
        else:  # otherwise, combine the old and new
            di_succ_by_num[curr_func_addr] = di_succ_by_num[curr_func_addr] + len(succ_names)
    print("di_succ_by_num", di_succ_by_num)
    '''
       create di_num_succ by using di_succ_names(curr_func_name, succ_name)
    '''
    for curr_func_name, succ_name in di_succ_names.items():
        if not di_num_succ.get(curr_func_name):
            di_num_succ[curr_func_name] = len(succ_name)
        else:
            di_num_succ[curr_func_name] = di_num_succ[curr_func_name] + len(succ_name)
    print("di_num_succ", di_num_succ)
    return di_succ_by_addrs, di_succ_addrs, di_succ_by_name, di_succ_names, di_succ_by_num, di_num_succ


"""
:param cfg: control flow graph
:param callgraph: call graph
:param begin_addr: program entry point
:return: di_pred_by_addrs: a dictionary with key: current function's addr, value: predeccessor's addrs
         di_pred_addrs: a dictionary with key: current function name, value: predeccessor's addrs
         di_pred_by_names: a dictionary with key: current function's addr, value:predecessor's names
         di_pred_names: a dictionary with key: current function's name, value: predecessor's names
         di_pred_by_num: a dictionary with key: current function's addr, value: no. of successors
         di_num_pred: a dictionary with key: current function's name, value: no. of successors
"""


def getPredemulated(cfg, callgraph, begin_addr):
    di_pred_by_addrs = {}
    di_pred_addrs = {}
    di_pred_by_names = {}
    di_pred_names = {}
    di_pred_by_num = {}
    di_num_pred = {}
    '''
       create di_pred_by_addrs, di_pred_addrs
    '''
    for curr_func_addr, preds in nx.predecessor(callgraph, begin_addr).items():
        if not di_pred_by_addrs.get(curr_func_addr):  # if the key not exists, create one with preds addrs
            di_pred_by_addrs[curr_func_addr] = preds
        else:  # otherwise, combine the old and new
            di_pred_by_addrs[curr_func_addr] = di_pred_by_addrs[curr_func_addr] + preds
        try:  # curr_func_addr points to a func
            '''
               construct di_pred_addrs(curr_func_name, pred addrs)
            '''
            curr_func = cfg.kb.functions[curr_func_addr]
            if not di_pred_addrs.get(curr_func.name):
                di_pred_addrs[curr_func.name] = preds
            else:
                di_pred_addrs[curr_func.name] = di_pred_addrs[curr_func.name] + preds
        except:  # not a func, use curr_func_addr as name
            if not di_pred_addrs.get(curr_func_addr):
                di_pred_addrs[curr_func_addr] = preds
            else:
                di_pred_addrs[curr_func_addr] = di_pred_addrs[curr_func_addr] + preds
    print("di_pred_by_addrs", di_pred_by_addrs)
    print("di_pred_addrs", di_pred_addrs)

    '''
        create di_pred_by_names by di_pred_by_addrs(curr_func_addr, pred_addrs)
    '''
    for curr_func_addr, pred_addrs in di_pred_by_addrs.items():
        if pred_addrs:  # it has preds
            pred_func_name = []
            for pred_addr in pred_addrs:
                try:  # pred_addr points to a func
                    pred_func = cfg.kb.functions[pred_addr]
                    pred_func_name.append(pred_func.name)
                except:  # not a func
                    pred_func_name.append([pred_addr])
            if not di_pred_by_names.get(curr_func_addr):
                di_pred_by_names[curr_func_addr] = pred_func_name
            else:
                di_pred_by_names[curr_func_addr] = di_pred_by_names[curr_func_addr] + pred_func_name
        else:  # no preds
            di_pred_by_names[curr_func_addr] = []
    print("di_pred_by_names", di_pred_by_names)

    '''
       create di_pred_names by di_pred_addrs (curr_func_name, pred_addrs)
    '''
    for curr_func_name, pred_addrs in di_pred_addrs.items():
        if pred_addrs:  # it has preds
            pred_func_name = []
            for pred_addr in pred_addrs:
                try:  # pred_addr points to a func
                    '''
                       save preds names
                    '''
                    pred_func = cfg.kb.functions[pred_addr]
                    pred_func_name.append(pred_func.name)
                except:  # not a func, use its pred's addr as name
                    pred_func_name.append([pred_addr])

            if not di_pred_names.get(curr_func_name):
                di_pred_names[curr_func_name] = pred_func_name
            else:
                di_pred_names[curr_func_name] = di_pred_names[curr_func_name] + pred_func_name
        else:  # no predecessors
            di_pred_names[curr_func_name] = []
            continue
    print("di_pred_names", di_pred_names)

    '''
       create di_pred_by_num by di_pred_by_names(curr_func_addr, pred_names)
    '''
    for curr_func_addr, pred_names in di_pred_by_names.items():
        if pred_names:  # has predecessors
            '''
               key: curr_func_addr, value: no. of predecessors
            '''
            if not di_pred_by_num.get(curr_func_addr):
                di_pred_by_num[curr_func_addr] = len(pred_names)
            else:
                di_pred_by_num[curr_func_addr] = di_pred_by_num[curr_func_addr] + len(pred_names)
        else:
            di_pred_by_num[curr_func_addr] = 0
    print("di_pred_by_num", di_pred_by_num)

    '''
        create di_num_pred by di_pred_names (curr_func_name, pred_names)
    '''
    for curr_func_name, pred_names in di_pred_names.items():
        if pred_names:  # has predecessors
            if not di_num_pred.get(curr_func_name):
                di_num_pred[curr_func_name] = len(pred_names)
            else:
                di_num_pred[curr_func_name] = di_num_pred[curr_func_name] + len(pred_names)
        else:  # no predecessor
            di_num_pred[curr_func_name] = 0
    print("di_num_pred", di_num_pred)
    return di_pred_by_addrs, di_pred_addrs, di_pred_by_names, di_pred_names, di_pred_by_num, di_num_pred


"""
This function filter some addresses that don't point to a function in search of current functions and successors
:param cfg: control flow graph
:param callgraph: call graph
:param begin_addr: program entry point
:return: di_succ_by_addrs: a dictionary with key: current function's addr, value: successor's addrs
         di_succ_addrs: a dictionary with key: current function name, value: successors' addrs
         di_succ_by_name: a dictionary with key: current function's addr, value:successors' names
         di_succ_names: a dictionary with key: current function's name, value: successors' names
         di_succ_by_num: a dictionary with key: current function's addr, value:no. of successors
         di_num_succ: a dictionary with key: current function name, value: no. of successors
"""


def getSuccemulated_filter(cfg, callgraph, begin_addr):
    lfunc_name = []  # save all current function names
    di_succ_by_addrs = {}
    di_succ_addrs = {}
    di_succ_by_name = {}
    di_succ_names = {}
    di_succ_by_num = {}
    di_num_succ = {}
    '''
       contruct  di_succ_by_addrs and di_succ_addrs
    '''
    for succ_addr in nx.bfs_successors(callgraph, begin_addr):
        # print("succ_addr", succ_addr)
        curr_func_addr, succ_addrs = succ_addr
        # if succ_addrs:
        if not di_succ_by_addrs.get(curr_func_addr):  # key curr func addr not exists
            di_succ_by_addrs[curr_func_addr] = succ_addrs  # create the key with value succ addrs
        else:  # already exists
            di_succ_by_addrs[curr_func_addr] = list(
                set(di_succ_by_addrs[curr_func_addr] + succ_addrs))  # combine the old and new

        try:  # if curr func addr points to a func
            '''
                    create a dict with key: curr_func.name, value: succ_addrs
                    '''
            curr_func = cfg.kb.functions[curr_func_addr]
            lfunc_name.append(curr_func.name)
            if not di_succ_addrs.get(curr_func.name):
                di_succ_addrs[curr_func.name] = succ_addrs
            else:
                di_succ_addrs[curr_func.name] = list(set(di_succ_addrs[curr_func.name] + succ_addrs))
        except:  # it isn't a func
            '''
                       skip the current address as it is not a function
                    '''
            print("exception happening for contructing di_succ_by_addrs and di_succ_addrs in getSuccemulated_filter")
            continue
    # else:

    print("di_succ_by_addrs", di_succ_by_addrs)
    print("di_succ_addrs", di_succ_addrs)

    '''
       construct di_succ_by_name by using di_succ_by_addrs(curr_func_addr, succ_addrs)
    '''
    for curr_func_addr, succ_addrs in di_succ_by_addrs.items():
        succ_name = []
        for succ_addr in succ_addrs:
            try:  # succ_addr points to a func
                '''
                   get succ's name
                '''
                func_succ = cfg.kb.functions[succ_addr]
                succ_name.append(func_succ.name)
            except:  # not a func
                '''
                    skip such succ addr as it doesn't point to a function
                '''
                print(
                    "exception happening for contructing di_succ_by_name in getSuccemulated_filter")
                continue
        if not di_succ_by_name.get(curr_func_addr):  # key curr_func_addr not exist, create one with value succ_name
            di_succ_by_name[curr_func_addr] = succ_name
        else:  # already exists, combine the old and new
            di_succ_by_name[curr_func_addr] = di_succ_names[curr_func_addr] + succ_name
    print("di_succ_by_name", di_succ_by_name)

    '''
       construct di_succ_names by using di_suu_addrs(curr_func_name, succ_addrs)
    '''
    for curr_func_name, succ_addrs in di_succ_addrs.items():
        succ_names = []
        for succ_addr in succ_addrs:
            try:  # succ_addr points to a function, save its name
                func_succ = cfg.kb.functions[succ_addr]
                succ_names.append(func_succ.name)
            except:  # otherwise, skip the succ addr as it doesn't point to a func
                print(
                    "exception happening for contructing di_succ_names in getSuccemulated_filter")
                continue

        if not di_succ_names.get(curr_func_name):  # if not exists, create one with its succ's names
            di_succ_names[curr_func_name] = succ_names
        else:  # already exists, combine the old and new
            di_succ_names[curr_func_name] = di_succ_names[curr_func_name] + succ_names
    print("di_succ_names", di_succ_names)

    '''
       create di_succ_by_num by di_succ_by_name (curr_func_addr, succ_names)
    '''
    for curr_func_addr, succ_names in di_succ_by_name.items():
        if not di_succ_by_num.get(curr_func_addr):  # if not exists, create one with no. of succs
            di_succ_by_num[curr_func_addr] = len(succ_names)
        else:  # otherwise, combine the old and new
            di_succ_by_num[curr_func_addr] = di_succ_by_num[curr_func_addr] + len(succ_names)
    print("di_succ_by_num", di_succ_by_num)

    '''
       create di_num_succ by using di_succ_names(curr_func_name, succ_name)
    '''
    for curr_func_name, succ_name in di_succ_names.items():
        if not di_num_succ.get(curr_func_name):
            di_num_succ[curr_func_name] = len(succ_name)
        else:
            di_num_succ[curr_func_name] = di_num_succ[curr_func_name] + len(succ_name)
    print("di_num_succ", di_num_succ)
    return di_succ_by_addrs, di_succ_addrs, di_succ_by_name, di_succ_names, di_succ_by_num, di_num_succ


"""
This function filters some addresses that don't point to a function in search of current functions and predecessors
:param cfg: control flow graph
:param callgraph: call graph
:param begin_addr: program entry point
:return: di_pred_by_addrs: a dictionary with key: current function's addr, value: predeccessor's addrs
         di_pred_addrs: a dictionary with key: current function name, value: predeccessor's addrs
         di_pred_by_names: a dictionary with key: current function's addr, value:predecessor's names
         di_pred_names: a dictionary with key: current function's name, value: predecessor's names
         di_pred_by_num: a dictionary with key: current function's addr, value: no. of successors
         di_num_pred: a dictionary with key: current function's name, value: no. of successors
"""


def getPredemulated_filter(cfg, callgraph, begin_addr):
    di_pred_by_addrs = {}
    di_pred_addrs = {}
    di_pred_by_names = {}
    di_pred_names = {}
    di_pred_by_num = {}
    di_num_pred = {}
    '''
       create di_pred_by_addrs, di_pred_addrs
    '''
    for curr_func_addr, preds in nx.predecessor(callgraph, begin_addr).items():
        '''
              construct di_pred_by_addrs(curr_func_addr, pred addrs)
        '''
        if not di_pred_by_addrs.get(curr_func_addr):  # if the key not exists, create one with preds addrs
            di_pred_by_addrs[curr_func_addr] = preds
        else:  # otherwise, combine the old and new
            di_pred_by_addrs[curr_func_addr] = di_pred_by_addrs[curr_func_addr] + preds
        try:  # curr_func_addr points to a func
            '''
               construct di_pred_addrs(curr_func_name, pred addrs)
            '''
            curr_func = cfg.kb.functions[curr_func_addr]
            if not di_pred_addrs.get(curr_func.name):
                di_pred_addrs[curr_func.name] = preds
            else:
                di_pred_addrs[curr_func.name] = di_pred_addrs[curr_func.name] + preds
        except:  # skip curr_func_addr as it doesn't point to a func
            print("exception happening for constructing di_pred_by_addrs and di_pred_addrs in getPredemulated_filter")
            continue
    print("di_pred_by_addrs", di_pred_by_addrs)
    print("di_pred_addrs", di_pred_addrs)

    '''
        create di_pred_by_names by di_pred_by_addrs(curr_func_addr, pred_addrs)
    '''
    for curr_func_addr, pred_addrs in di_pred_by_addrs.items():
        if pred_addrs:  # it has preds
            pred_func_name = []
            for pred_addr in pred_addrs:
                try:  # pred_addr points to a func
                    pred_func = cfg.kb.functions[pred_addr]
                    pred_func_name.append(pred_func.name)
                except:  # skip such pred addr as it doesn't point to a func
                    print(
                        "exception happening for constructing di_pred_by_names in getPredemulated_filter")
                    continue
            if not di_pred_by_names.get(curr_func_addr):
                di_pred_by_names[curr_func_addr] = pred_func_name
            else:
                di_pred_by_names[curr_func_addr] = di_pred_by_names[curr_func_addr] + pred_func_name
        else:  # no preds
            di_pred_by_names[curr_func_addr] = []
    print("di_pred_by_names", di_pred_by_names)

    '''
       create di_pred_names by di_pred_addrs (curr_func_name, pred_addrs)
    '''
    for curr_func_name, pred_addrs in di_pred_addrs.items():
        if pred_addrs:  # it has preds
            pred_func_name = []
            for pred_addr in pred_addrs:
                try:  # pred_addr points to a func
                    '''
                       save preds names
                    '''
                    pred_func = cfg.kb.functions[pred_addr]
                    pred_func_name.append(pred_func.name)
                except:  # skip pred addr as it doesn't point to a func
                    print(
                        "exception happening for constructing di_pred_names in getPredemulated_filter")
                    continue

            if not di_pred_names.get(curr_func_name):
                di_pred_names[curr_func_name] = pred_func_name
            else:
                di_pred_names[curr_func_name] = di_pred_names[curr_func_name] + pred_func_name
        else:  # no predecessors
            di_pred_names[curr_func_name] = []
    print("di_pred_names", di_pred_names)

    '''
       create di_pred_by_num by di_pred_by_names(curr_func_addr, pred_names)
    '''
    for curr_func_addr, pred_names in di_pred_by_names.items():
        if pred_names:  # has predecessors
            '''
               key: curr_func_addr, value: no. of predecessors
            '''
            if not di_pred_by_num.get(curr_func_addr):
                di_pred_by_num[curr_func_addr] = len(pred_names)
            else:
                di_pred_by_num[curr_func_addr] = di_pred_by_num[curr_func_addr] + len(pred_names)
        else:
            di_pred_by_num[curr_func_addr] = 0
    print("di_pred_by_num", di_pred_by_num)

    '''
        create di_num_pred by di_pred_names (curr_func_name, pred_names)
    '''
    for curr_func_name, pred_names in di_pred_names.items():
        if pred_names:  # has predecessors
            if not di_num_pred.get(curr_func_name):
                di_num_pred[curr_func_name] = len(pred_names)
            else:
                di_num_pred[curr_func_name] = di_num_pred[curr_func_name] + len(pred_names)
        else:  # no predecessor
            di_num_pred[curr_func_name] = 0
    print("di_num_pred", di_num_pred)
    return di_pred_by_addrs, di_pred_addrs, di_pred_by_names, di_pred_names, di_pred_by_num, di_num_pred


"""
This function filter some addresses at the beginning by checking whether 
current function and its successors point to a function
:param cfg: control flow graph
:param callgraph: call graph
:param begin_addr: program entry point
:return: di_succ_by_addrs: a dictionary with key: current function's addr, value: successor's addrs
         di_succ_addrs: a dictionary with key: current function name, value: successors' addrs
         di_succ_by_name: a dictionary with key: current function's addr, value:successors' names
         di_succ_names: a dictionary with key: current function's name, value: successors' names
         di_succ_by_num: a dictionary with key: current function's addr, value:no. of successors
         di_num_succ: a dictionary with key: current function name, value: no. of successors
"""


def successorsFilter(cfg, callgraph, begin_addr):
    lfunc_name = []  # save all current function names
    di_succ_by_addrs = {}
    di_succ_addrs = {}
    di_succ_by_name = {}
    di_succ_names = {}
    di_succ_by_num = {}
    di_num_succ = {}
    '''
       contruct  di_succ_by_addrs and di_succ_addrs
    '''
    for succ_addr in nx.bfs_successors(callgraph, begin_addr):
        # print("succ_addr", succ_addr)
        curr_func_addr, succ_addrs = succ_addr

        try:  # if curr func addr points to a func
            '''
                create a dict with key: curr_func.name, value: succ_addrs
                '''
            curr_func = cfg.kb.functions[curr_func_addr]
            lfunc_name.append(curr_func.name)
            # print("succ_addrs", succ_addrs)
            succ_addrs_filtered = []  # filter the succ addrs not pointing to a func
            for succ_addr in succ_addrs:
                # print("succ_addr", succ_addr)
                if not cfg.functions.function(succ_addr):
                    continue
                else:
                    succ_addrs_filtered.append(succ_addr)

            # print("succ_addrs_filtered", succ_addrs_filtered)
            if not di_succ_by_addrs.get(curr_func_addr):  # key curr func addr not exists
                di_succ_by_addrs[curr_func_addr] = succ_addrs_filtered  # create the key with value succ addrs
            else:  # already exists
                di_succ_by_addrs[curr_func_addr] = list(
                    set(di_succ_by_addrs[curr_func_addr] + succ_addrs_filtered))  # combine the old and new

            if not di_succ_addrs.get(curr_func.name):
                di_succ_addrs[curr_func.name] = succ_addrs_filtered
            else:
                di_succ_addrs[curr_func.name] = list(set(di_succ_addrs[curr_func.name] + succ_addrs_filtered))
        except:  # skip the current address as it is not a function
            print("exception happening for constructing in di_succ_by_addrs and di_succ_addrs in successorsFilter")
            continue

    # print("di_succ_by_addrs", di_succ_by_addrs)
    # print("di_succ_addrs", di_succ_addrs)

    '''
       construct di_succ_by_name by using di_succ_by_addrs(curr_func_addr, succ_addrs)
    '''
    for curr_func_addr, succ_addrs in di_succ_by_addrs.items():
        succ_name = []
        for succ_addr in succ_addrs:
            try:  # succ_addr points to a func
                '''
                   get succ's name
                '''
                func_succ = cfg.kb.functions[succ_addr]
                succ_name.append(func_succ.name)
            except:  # not a func
                '''
                    skip such succ addr as it doesn't point to a function
                '''
                print("exception happening for constructing in di_succ_by_name in successorsFilter")
                continue
        if not di_succ_by_name.get(curr_func_addr):  # key curr_func_addr not exist, create one with value succ_name
            di_succ_by_name[curr_func_addr] = succ_name
        else:  # already exists, combine the old and new
            di_succ_by_name[curr_func_addr] = di_succ_names[curr_func_addr] + succ_name
    # print("di_succ_by_name", di_succ_by_name)

    '''
       construct di_succ_names by using di_suu_addrs(curr_func_name, succ_addrs)
    '''
    for curr_func_name, succ_addrs in di_succ_addrs.items():
        succ_names = []
        for succ_addr in succ_addrs:
            try:  # succ_addr points to a function, save its name
                func_succ = cfg.kb.functions[succ_addr]
                succ_names.append(func_succ.name)
            except:  # otherwise, skip the succ addr as it doesn't point to a func
                print("exception happening for constructing di_succ_names in successorsFilter")
                continue

        if not di_succ_names.get(curr_func_name):  # if not exists, create one with its succ's names
            di_succ_names[curr_func_name] = succ_names
        else:  # already exists, combine the old and new
            di_succ_names[curr_func_name] = di_succ_names[curr_func_name] + succ_names
    # print("di_succ_names", di_succ_names)

    '''
       create di_succ_by_num by di_succ_by_name (curr_func_addr, succ_names)
    '''
    for curr_func_addr, succ_names in di_succ_by_name.items():
        if not di_succ_by_num.get(curr_func_addr):  # if not exists, create one with no. of succs
            di_succ_by_num[curr_func_addr] = len(succ_names)
        else:  # otherwise, combine the old and new
            di_succ_by_num[curr_func_addr] = di_succ_by_num[curr_func_addr] + len(succ_names)
    # print("di_succ_by_num", di_succ_by_num)

    '''
       create di_num_succ by using di_succ_names(curr_func_name, succ_name)
    '''
    for curr_func_name, succ_name in di_succ_names.items():
        if not di_num_succ.get(curr_func_name):
            di_num_succ[curr_func_name] = len(succ_name)
        else:
            di_num_succ[curr_func_name] = di_num_succ[curr_func_name] + len(succ_name)
    # print("di_num_succ", di_num_succ)
    return di_succ_by_addrs, di_succ_addrs, di_succ_by_name, di_succ_names, di_succ_by_num, di_num_succ


"""
This function filter some addresses at the beginning by checking whether 
current function and its predecessors point to a function
:param cfg: control flow graph
:param callgraph: call graph
:param begin_addr: program entry point
:return: di_pred_by_addrs: a dictionary with key: current function's addr, value: predeccessor's addrs
         di_pred_addrs: a dictionary with key: current function name, value: predeccessor's addrs
         di_pred_by_names: a dictionary with key: current function's addr, value:predecessor's names
         di_pred_names: a dictionary with key: current function's name, value: predecessor's names
         di_pred_by_num: a dictionary with key: current function's addr, value: no. of successors
         di_num_pred: a dictionary with key: current function's name, value: no. of successors
"""


def predecessorsFilter(cfg, callgraph, begin_addr):
    di_pred_by_addrs = {}
    di_pred_addrs = {}
    di_pred_by_names = {}
    di_pred_names = {}
    di_pred_by_num = {}
    di_num_pred = {}
    '''
       create di_pred_by_addrs, di_pred_addrs
    '''
    for curr_func_addr, preds in nx.predecessor(callgraph, begin_addr).items():
        '''
              construct di_pred_by_addrs(curr_func_addr, pred addrs)
        '''
        try:  # curr_func_addr points to a func
            curr_func = cfg.kb.functions[curr_func_addr]
            preds_filtered = []
            for pred in preds:
                if not cfg.functions.function(pred):
                    continue
                else:
                    preds_filtered.append(pred)

            if not di_pred_by_addrs.get(curr_func_addr):  # if the key not exists, create one with preds addrs
                di_pred_by_addrs[curr_func_addr] = preds_filtered
            else:  # otherwise, combine the old and new
                di_pred_by_addrs[curr_func_addr] = di_pred_by_addrs[curr_func_addr] + preds_filtered

            '''
            construct di_pred_addrs(curr_func_name, pred addrs)
            '''
            if not di_pred_addrs.get(curr_func.name):
                di_pred_addrs[curr_func.name] = preds_filtered
            else:
                di_pred_addrs[curr_func.name] = di_pred_addrs[curr_func.name] + preds_filtered

        except:  # skip curr_func_addr as it doesn't point to a func
            print("exception happening for contructing di_pred_by_addrs and di_pred_addrs in predecessorsFilter")
            continue
    # print("di_pred_by_addrs", di_pred_by_addrs)
    # print("di_pred_addrs", di_pred_addrs)

    '''
        create di_pred_by_names by di_pred_by_addrs(curr_func_addr, pred_addrs)
    '''
    for curr_func_addr, pred_addrs in di_pred_by_addrs.items():
        if pred_addrs:  # it has preds
            pred_func_name = []
            for pred_addr in pred_addrs:
                try:  # pred_addr points to a func
                    pred_func = cfg.kb.functions[pred_addr]
                    pred_func_name.append(pred_func.name)
                except:  # skip such pred addr as it doesn't point to a func
                    print("exception happening for contructing di_pred_by_names in predecessorsFilter")
                    continue
            if not di_pred_by_names.get(curr_func_addr):
                di_pred_by_names[curr_func_addr] = pred_func_name
            else:
                di_pred_by_names[curr_func_addr] = di_pred_by_names[curr_func_addr] + pred_func_name
        else:  # no preds
            di_pred_by_names[curr_func_addr] = []
    # print("di_pred_by_names", di_pred_by_names)

    '''
       create di_pred_names by di_pred_addrs (curr_func_name, pred_addrs)
    '''
    for curr_func_name, pred_addrs in di_pred_addrs.items():
        if pred_addrs:  # it has preds
            pred_func_name = []
            for pred_addr in pred_addrs:
                try:  # pred_addr points to a func
                    '''
                       save preds names
                    '''
                    pred_func = cfg.kb.functions[pred_addr]
                    pred_func_name.append(pred_func.name)
                except:  # skip pred addr as it doesn't point to a func
                    print("exception happening for contructing di_pred_names in predecessorsFilter")
                    continue

            if not di_pred_names.get(curr_func_name):
                di_pred_names[curr_func_name] = pred_func_name
            else:
                di_pred_names[curr_func_name] = di_pred_names[curr_func_name] + pred_func_name
        else:  # no predecessors
            di_pred_names[curr_func_name] = []
    # print("di_pred_names", di_pred_names)

    '''
       create di_pred_by_num by di_pred_by_names(curr_func_addr, pred_names)
    '''
    for curr_func_addr, pred_names in di_pred_by_names.items():
        if pred_names:  # has predecessors
            '''
               key: curr_func_addr, value: no. of predecessors
            '''
            if not di_pred_by_num.get(curr_func_addr):
                di_pred_by_num[curr_func_addr] = len(pred_names)
            else:
                di_pred_by_num[curr_func_addr] = di_pred_by_num[curr_func_addr] + len(pred_names)
        else:
            di_pred_by_num[curr_func_addr] = 0
    # print("di_pred_by_num", di_pred_by_num)

    '''
        create di_num_pred by di_pred_names (curr_func_name, pred_names)
    '''
    for curr_func_name, pred_names in di_pred_names.items():
        if pred_names:  # has predecessors
            if not di_num_pred.get(curr_func_name):
                di_num_pred[curr_func_name] = len(pred_names)
            else:
                di_num_pred[curr_func_name] = di_num_pred[curr_func_name] + len(pred_names)
        else:  # no predecessor
            di_num_pred[curr_func_name] = 0
    # print("di_num_pred", di_num_pred)
    return di_pred_by_addrs, di_pred_addrs, di_pred_by_names, di_pred_names, di_pred_by_num, di_num_pred


"""
this function is used to obtain the no. of user funcs
and library funcs in the successors that the current func has.
"""


def checkLib_succ(proj, cfg):
    # proj = angr.Project('/Users/zhong/Downloads/fauxware', load_options={'auto_load_libs': False})
    # cfg = proj.analyses.CFGFast()  # contruct control flow graph
    callgraph = cfg.kb.functions.callgraph
    min_addr = proj.loader.main_object.min_addr
    max_addr = proj.loader.main_object.max_addr
    di_succ_by_addrs, di_succ_addrs, di_succ_by_name, di_succ_names, di_succ_by_num, di_num_succ = successorsFilter(cfg,
                                                                                                                    callgraph,
                                                                                                                    proj.entry)
    dict_user_lib_len = {}
    dict_user_lib_addr = {}
    # print("di_succ_by_addrs", di_succ_by_addrs)
    '''
    given by curr_func_addr, succ_addrs, obtain a dict dict_user_lib_len 
    with key: curr_func_addr, value: no. of user funcs and library funcs
    in the successors, and another dict dict_user_lib_addr with 
    key: curr_func_addr, value: address of user funcs and library funcs 
    '''
    for curr_func_addr, succ_addrs in di_succ_by_addrs.items():
        if curr_func_addr < min_addr or curr_func_addr > max_addr:
            continue
        else:
            succ_user_addrs = []
            succ_lib_addrs = []
            for succ_addr in succ_addrs:
                if succ_addr > min_addr and succ_addr < max_addr:
                    succ_user_addrs.append(succ_addr)
                else:
                    succ_lib_addrs.append(succ_addr)
            if not dict_user_lib_len.get(curr_func_addr):
                dict_user_lib_len[curr_func_addr] = [len(succ_user_addrs), len(succ_lib_addrs)]
            else:
                dict_user_lib_len[curr_func_addr] = list(
                    map(add, dict_user_lib_len[curr_func_addr], [len(succ_user_addrs), len(succ_lib_addrs)]))

            if not dict_user_lib_addr.get(curr_func_addr):
                dict_user_lib_addr[curr_func_addr] = [succ_user_addrs, succ_lib_addrs]
            else:

                list_user_lib_new = [succ_user_addrs, succ_lib_addrs]
                list_user_with_lib = [list(set(dict_user_lib_addr[curr_func_addr][i] + list_user_lib_new[i])) for i in
                                      range(len(dict_user_lib_addr))]
                dict_user_lib_addr[curr_func_addr] = list_user_with_lib
            # a dict with key:function name, value:[list of called user func name, list of called lib func name]
    # print("dict_user_lib_addr", dict_user_lib_addr)

    '''
        change corresponding dicts with key curr_func_addr to curr_func_name
    '''
    curr_func_name_addr = {}
    for curr_func_addr, list_user_lib in dict_user_lib_addr.items():
        try:
            curr_func = cfg.kb.functions[curr_func_addr]
            if not curr_func_name_addr.get(curr_func.name):
                curr_func_name_addr[curr_func.name] = list_user_lib
            else:
                '''
                       combine the old and new addresses of user funcs and lib funcs
                    '''
                list_user_with_lib = [list(set(curr_func_name_addr[curr_func.name][i] + list_user_lib[i])) for i
                                      in range(len(curr_func_name_addr[curr_func.name]))]
                curr_func_name_addr[curr_func.name] = list_user_with_lib
        except:
            print("exception happening in constructing curr_func_name in checkLib_succ")
            continue
    # print("curr_func_name", curr_func_name_addr)
    curr_name_len = {}
    for curr_func_name, user_lib_addr in curr_func_name_addr.items():
        if not curr_name_len.get(curr_func_name):
            user_len = len(user_lib_addr[0])
            lib_len = len(user_lib_addr[1])
            curr_name_len[curr_func_name] = [user_len, lib_len]
        else:
            '''
             combine the old and new lens of user funcs and lib funcs
            '''
            curr_name_len[curr_func_name] = list(
                map(add, curr_name_len[curr_func_name], [len(user_lib_addr[0]), len(user_lib_addr[1])]))
    # print("curr_name_len", curr_name_len)
    return dict_user_lib_len, dict_user_lib_addr, curr_name_len, curr_func_name_addr


"""
this function is used to obtain the no. of user funcs
and library funcs in the predecessors that the current func has.
"""


def checkLib_preds():
    proj = angr.Project('/Users/zhong/Downloads/npp.8.4.1.Installer.x64.exe', load_options={'auto_load_libs': False})
    cfg = proj.analyses.CFGFast()  # contruct control flow graph
    callgraph = cfg.kb.functions.callgraph
    min_addr = proj.loader.main_object.min_addr
    max_addr = proj.loader.main_object.max_addr
    di_pred_by_addrs, di_pred_addrs, di_pred_by_names, di_pred_names, di_pred_by_num, di_num_pred = predecessorsFilter(
        cfg, callgraph, proj.entry)

    dict_user_lib_len = {}
    dict_user_lib_addr = {}
    '''
        given by curr_func_addr, succ_addrs, obtain a dict dict_user_lib_len 
        with key: curr_func_addr, value: no. of user funcs and library funcs
        in the predecessors, and another dict dict_user_lib_addr with 
        key: curr_func_addr, value: address of user funcs and library funcs 
    '''
    for curr_func_addr, preds in di_pred_by_addrs.items():
        if curr_func_addr < min_addr or curr_func_addr > max_addr:
            continue
        else:
            pred_user_addrs = []
            pred_lib_addrs = []
            for pred in preds:
                if pred > min_addr and pred < max_addr:
                    pred_user_addrs.append(pred)
                else:
                    pred_lib_addrs.append(pred)

            if not dict_user_lib_len.get(curr_func_addr):
                dict_user_lib_len[curr_func_addr] = [len(pred_user_addrs), len(pred_lib_addrs)]
            else:
                dict_user_lib_len[curr_func_addr] = list(
                    map(add, dict_user_lib_len[curr_func_addr], [len(pred_user_addrs), len(pred_lib_addrs)]))

            if not dict_user_lib_addr.get(curr_func_addr):
                dict_user_lib_addr[curr_func_addr] = [pred_user_addrs, pred_lib_addrs]
            else:
                list_user_lib_new = [pred_user_addrs, pred_lib_addrs]
                list_user_with_lib = [list(set(dict_user_lib_addr[curr_func_addr][i] + list_user_lib_new[i])) for i in
                                      range(len(dict_user_lib_addr))]
                dict_user_lib_addr[curr_func_addr] = list_user_with_lib

    '''
       change the above dict with key from curr_func_addr to curr_func_name
    '''
    curr_func_name_addr = {}
    for curr_func_addr, list_user_lib in dict_user_lib_addr.items():
        try:
            curr_func = cfg.kb.functions[curr_func_addr]
            if not curr_func_name_addr.get(curr_func.name):
                curr_func_name_addr[curr_func.name] = list_user_lib
            else:
                list_user_with_lib = [list(set(curr_func_name_addr[curr_func.name][i] + list_user_lib[i])) for i
                                      in range(len(curr_func_name_addr[curr_func.name]))]
                curr_func_name_addr[curr_func.name] = list_user_with_lib
        except:
            print("exception happening in constructing curr_func_name in checkLib_succ")
            continue
    print("curr_func_name", curr_func_name_addr)
    curr_name_len = {}
    for curr_func_name, user_lib_addr in curr_func_name_addr.items():
        if not curr_name_len.get(curr_func_name):
            user_len = len(user_lib_addr[0])
            lib_len = len(user_lib_addr[1])
            curr_name_len[curr_func_name] = [user_len, lib_len]
        else:
            curr_name_len[curr_func_name] = list(
                map(add, curr_name_len[curr_func_name], [len(user_lib_addr[0]), len(user_lib_addr[1])]))
    print("curr_name_len", curr_name_len)


"""
:param proj: an angr project
:param cfg: control flow graph
:return a list containing all function's pixels by each block
"""


def funcsToimgblock(proj, cfg):
    dict_user_lib_len, dict_user_lib_addr, curr_name_len, curr_func_name_addr = checkLib_succ(proj, cfg)
    llfunc_bb_int = []
    for curr_func_addr, user_lib_addr in dict_user_lib_addr.items():
        print("curr_func_addr", curr_func_addr)
        llfunc_bb_int.append(bytesToimgblock(proj, cfg, curr_func_addr))
    print("llfunc_bb_int", llfunc_bb_int)
    # print(len(llfunc_bb_int))
    return llfunc_bb_int


"""
transform bytes to image pixels
:param proj: an angr project
:param cfg: control flow graph
:param func_addr: func_addr pointing to a function 
that needs to be converted to image pixels
:return image pixels ranged 0~255
"""


def bytesToimgblock(proj, cfg, func_addr=4195712):
    lfunc_bb_bytes = funcInline(proj, cfg, func_addr)
    lfunc_bb_int = []
    if not lfunc_bb_bytes:
        return lfunc_bb_int
    else:
        for lfunc_bb_byte in lfunc_bb_bytes:
            for i in range(len(lfunc_bb_byte)):
                bb_int = []
                for byte in lfunc_bb_byte[i]:
                    bb_int.append(byte)
                lfunc_bb_int.append(bb_int)
    # print("lfunc_bb_int", lfunc_bb_int)
    return lfunc_bb_int


"""
:param proj: an angr project
:param cfg: control flow graph
:return a list containing all function's pixels by each function
"""


def funcsToimages(proj, cfg):
    dict_user_lib_len, dict_user_lib_addr, curr_name_len, curr_func_name_addr = checkLib_succ(proj, cfg)
    llfunc_bb_int = []
    for curr_func_addr, user_lib_addr in dict_user_lib_addr.items():
        llfunc_bb_int.append(bytesToimage(proj, cfg, curr_func_addr))
    # print("llfunc_bb_int", llfunc_bb_int)
    # print(len(llfunc_bb_int))
    return llfunc_bb_int


"""
transform bytes to image pixels
:param proj: an angr project
:param cfg: control flow graph
:param func_addr: func_addr pointing to a function 
that needs to be converted to image pixels
:return image pixels ranged 0~255
"""


def bytesToimage(proj, cfg, func_addr=4195712):
    lfunc_bb_bytes = funcInline(proj, cfg, func_addr)
    lfunc_bb_int = []
    if not lfunc_bb_bytes:
        return lfunc_bb_int
    else:
        for lfunc_bb_byte in lfunc_bb_bytes:
            for i in range(len(lfunc_bb_byte)):
                for byte in lfunc_bb_byte[i]:
                    lfunc_bb_int.append(byte)
    # print("lfunc_bb_int", lfunc_bb_int)
    return lfunc_bb_int


"""
:param func_name:
:param preds:
:param succs
"""


def checkInline(func_name, preds, succs):
    pass


"""
:param proj: an angr proj to a binary file
:param cfg: control flow graph
:param func_addr: an address pointing a function
:return func_bb_bytes: inlined caller
"""


def funcInline(proj, cfg, func_addr=4195648):
    func = cfg.kb.functions[func_addr]
    com_bb_callee = combineBBCallee(proj, cfg, func_addr)  # key bb addr, value: bb and callee byte codes
    lfunc_bb_bytes = []
    if not com_bb_callee:
        for block in func.blocks:
            lfunc_bb_bytes.append([block.bytes])
    else:
        for block in func.blocks:
            if block.addr not in com_bb_callee.keys():
                lfunc_bb_bytes.append([block.bytes])  # if len(lfunc_bb_bytes[i])>1, it has a callee
            else:
                lfunc_bb_bytes.append(com_bb_callee[block.addr])
            # print(lfunc_bb_bytes)
    print("lfunc_bb_bytes",
          lfunc_bb_bytes)  # lfunc_bb_bytes [[b'1\xedI\x89\xd1^H\x89\xe2H\x83\xe4\xf0PTI\xc7\xc0p\x08@\x00H\xc7\xc1\xe0\x07@\x00H\xc7\xc7\x1d\x07@\x00', b'\xff%\xd2\n \x00']]
    return lfunc_bb_bytes


'''
combine functions with  BB-callee relationship
:param proj: an angr project to a binary file
:param cfg: control flow graph
:param dict_bb_callee: key:basic block addr, value: callee byte codes
:return com_bb_callee: key:basic block addr, value: the last instruction
of basic block replaced by callee byte codes 
'''


def combineBBCallee(proj, cfg, func_addr=4195648):
    dict_bb_callee = getCallee(proj, cfg, func_addr)
    # print("dict_bb_callee", dict_bb_callee)
    com_bb_callee = {}

    for bb_addr, callee in dict_bb_callee.items():
        bb_callee = []
        bb = proj.factory.block(bb_addr)
        offset = bb.instruction_addrs[-1] - bb_addr  # the last instruction's offset
        if offset == 0:
            for calleebl in callee:
                bb_callee.append(calleebl)
        else:
            # print(bb.bytes[0:offset])
            bb_callee.append(bb.bytes[0:offset])  # in terms of its block beginning addr
            bb_callee = bb_callee + callee  # combine a caller's block with all callee blocks
        com_bb_callee[bb_addr] = bb_callee
    # print("com_bb_callee", com_bb_callee)
    return com_bb_callee


"""
:param cfg: control flow graph
:param func_addr: a function that needs to be inlined
:return dict_bb_callee: key: bb addr, value: callee byte codes
"""


def getCallee(proj, cfg, func_addr=4195648):
    dict_target_addr = callsiteAddr(cfg, func_addr)
    min_addr = proj.loader.main_object.min_addr
    max_addr = proj.loader.main_object.max_addr
    dict_bb_callee = {}

    for bb_addr, callee_addr in dict_target_addr.items():
        try:  # to avoid callee_addr not pointing to a func
            callee_func = cfg.kb.functions[callee_addr]
            callee_bytes = []
            print(callee_func.name)
            if callee_addr < min_addr or callee_addr > max_addr:
                callee_bytes.append(callee_func.name)
                # print(callee_func.name)
            else:
                for block in callee_func.blocks:
                    callee_bytes.append(block.bytes)
            dict_bb_callee[bb_addr] = callee_bytes
        except:
            print("exception happening in getCallee")
            continue
    print("dict_bb_callee", dict_bb_callee)
    return dict_bb_callee


"""
given a function, callsiteAddr retrieves all addresses of its callee (function)
:param func_addr: the function addr that points to caller
:return dict_target_addr: key: caller block addr, value: callee function address
"""


def callsiteAddr(cfg, func_addr=4195648):
    # print("func_addr", func_addr)
    func = cfg.kb.functions[func_addr]
    list_call_site = [callsite for callsite in func.get_call_sites()]
    # print("list_call_site", list_call_site)
    dict_target_addr = {}

    for callsite in list_call_site:
        if not dict_target_addr.get(callsite):
            dict_target_addr[callsite] = func.get_call_target(callsite)
        else:  # error
            subprocess.run(["/usr/bin/notify-send", "--icon=error", "one block points two functions..."])
    print("dict_target_addr", dict_target_addr)
    return dict_target_addr


'''
get binary content in 
each basic block
'''


def getblockContent():
    proj = angr.Project('/Users/zhong/Downloads/npp.8.4.1.Installer.x64.exe', load_options={'auto_load_libs': False})
    cfg = proj.analyses.CFGEmulated()  # contruct control flow graph
    callgraph = cfg.kb.functions.callgraph
    print(callgraph)
    predecessorsFilter(cfg, callgraph, proj.entry)
    successorsFilter(cfg, callgraph, proj.entry)


"""

"""


def successors(callgraph, begin_addr):
    dictionary = dict(nx.bfs_successors(callgraph, begin_addr))
    start = [begin_addr]
    output = {}
    while len(start) > 0:
        next = []
        while len(start) > 0:
            current = start.pop(0)
            neighbor = dictionary.get(current)
            if neighbor is not None:
                next = next + neighbor
                if not output.get(current):
                    output[current] = neighbor
        start = next
    print(output)
    return output


"""

"""


def cart2pol(x, y):
    rho = matlab.sqrt(x ** 2 + y ** 2)
    phi = matlab.arctan2(y, x)
    x = [2, 4]
    center = [4, 0]
    r = math.sqrt(math.pow(x[0] - center[0], 2) + math.pow(x[1] - center[1], 2))
    theta = math.atan2(x[1] - center[1], x[0] - center[0]) / math.pi * 180  # convert to angle
    x = np.float32([0, 1, 2, 0, 1, 2, 0, 1, 2])
    y = np.float32([0, 0, 0, 1, 1, 1, 2, 2, 2])
    r, theta = cv2.cartToPolar(x, y)
    print(theta)
    return (rho, phi)


"""
:param region_size:
cartesian coordinate to log polar coordinate
"""


def cartTopol(region_size):
    center = [np.ceil(region_size[0] / 2), np.ceil(region_size[1] / 2)];
    # radius = np.zeros((region_size[0], region_size[1]))
    # angle = np.zeros((region_size[0], region_size[1]))

    row_ord = []
    col_ord = []
    for row in range(region_size[0]):
        lrow = []
        lcol = []
        for col in range(region_size[1]):
            lrow.append(row)
            lcol.append(col)
        row_ord.append(lrow)
        col_ord.append(lcol)
    radius, angle = cv2.cartToPolar(row_ord - center[0], col_ord - center[1], angleInDegrees=True)
    for e1 in range(len(radius)):
        for e2 in range(len(radius[0])):
            if radius[e1][e2] != 0:
                radius[e1][e2] = matlab.log(radius[e1][e2])
    # print(angle.shape)
    # print("radius shape", radius.shape)
    # print("angle", angle)
    # print("radius", radius)
    return radius, angle


"""
:param radius:
:param angle:
:param bin_size:
:param region_size:
   separate the image pixels into bins, each bin contains multiple pixels
   therein, the center pixel is getting rid of
"""


def get_bin(radius, angle, bin_size, region_size):
    # print("shape", radius.shape)
    max_radius = np.amax(radius)
    bin = list()
    for m in range(bin_size[0]):
        theta_low = m * (360 / bin_size[0])  # lower bound for angle
        theta_high = (m + 1) * (360 / bin_size[0])  # higher bound for angle
        for n in range(bin_size[1]):
            rho_low = max_radius * (n / bin_size[1])  # lower bound for radius
            rho_high = max_radius * ((n + 1) / bin_size[1])  # higher bound for radius
            temp = list()
            temp1 = list()
            temp2 = list()
            for row in range(region_size[0]):  # used for slicing bins
                for col in range(region_size[1]):
                    if (radius[row, col] >= rho_low) & (radius[row, col] <= rho_high) & (
                            angle[row, col] >= theta_low) & (angle[row, col] <= theta_high):
                        temp1.append(row)
                        temp2.append(col)
            temp.append(temp1)
            temp.append(temp2)
            # print(np.array(temp).shape)
            bin.append(temp)
    return bin


"""
:param patch:
:param region:
:param region_size:
:param alpha:
:param center_patch:
correlation surface calculation
"""


def cal_ssd_old(patch, region, region_size, alpha, center_patch):
    # print("region_shape", region_size)
    SSD_region = np.zeros((region_size[0], region_size[1]))

    for row in range(center_patch[0], region_size[0] - center_patch[0]):
        for col in range(center_patch[1], region_size[1] - center_patch[1]):
            temp = region[row - center_patch[0]:row + center_patch[0], col - center_patch[1]: col + center_patch[1],
                   :] - patch[:, :, :]
            SSD_region[row, col] = matlab.sum(np.square(temp))
            SSD_region[row, col] = matlab.exp(-alpha * SSD_region[row, col])

    return SSD_region


"""
:param patch:
:param region:
:param region_size:
:param patch_size:
"""


def cal_ssd_new(patch, region, region_size, patch_size):
    SSD_region = np.zeros((region_size[0], region_size[1]))
    patch_row, patch_col = patch_size
    center_patch = [np.floor(patch_size[0] / 2).astype(int), np.floor(patch_size[1] / 2).astype(int)]
    alpha = 1 / (85 ^ 2)

    if patch_row % 2 == 0:
        if patch_col % 2 == 0:
            for row in range(center_patch[0], region_size[0] - center_patch[0]):
                for col in range(center_patch[1], region_size[1] - center_patch[1]):
                    temp = region[row - center_patch[0]:row + center_patch[0],
                           col - center_patch[1]: col + center_patch[1], :] - patch[:, :, :]
                    SSD_region[row, col] = matlab.sum(np.square(temp))
                    SSD_region[row, col] = matlab.exp(-alpha * SSD_region[row, col])
        else:
            for row in range(center_patch[0], region_size[0] - center_patch[0]):
                for col in range(center_patch[1], region_size[1] - center_patch[1] - 1):
                    temp = region[row - center_patch[0]:row + center_patch[1],
                           col - center_patch[1]: col + center_patch[1] + 1, :] - patch[:, :, :]
                    SSD_region[row, col] = matlab.sum(np.square(temp))
                    SSD_region[row, col] = matlab.exp(-alpha * SSD_region[row, col])
    else:
        if patch_col % 2 == 0:
            for row in range(center_patch[0], region_size[0] - center_patch[0] - 1):
                for col in range(center_patch[1], region_size[1] - center_patch[1]):
                    temp = region[row - center_patch[0]:row + center_patch[1] + 1,
                           col - center_patch[1]: col + center_patch[1], :] - patch[:, :, :]
                    SSD_region[row, col] = matlab.sum(np.square(temp))
                    SSD_region[row, col] = matlab.exp(-alpha * SSD_region[row, col])

        else:
            for row in range(center_patch[0], region_size[0] - center_patch[0] - 1):
                for col in range(center_patch[1], region_size[1] - center_patch[1] - 1):
                    temp = region[row - center_patch[0]:row + center_patch[0] + 1,
                           col - center_patch[1]: col + center_patch[1] + 1, :] - patch[:, :, :]
                    SSD_region[row, col] = matlab.sum(np.square(temp))
                    SSD_region[row, col] = matlab.exp(-alpha * SSD_region[row, col])

    return SSD_region


"""
:param SSD_region:
:param bin:
:param bin_size:
produce a compact descriptors, and account for local affine deformations
"""


def get_self_sim_vec(SSD_region, bin, bin_size):
    vec_size = bin_size[0] * bin_size[1]
    self_similarities_vec = np.zeros((1, vec_size))
    # print("self_similarities_vec", vec_size)
    num_bins = 0
    for m in range(bin_size[0]):
        for n in range(bin_size[1]):
            temp = bin[num_bins]
            max_value = 0
            temp_size = np.array(temp).shape
            # print(temp)
            # print("temp_size", temp_size)
            for loc in range(temp_size[1]):
                row = temp[0][loc]
                col = temp[1][loc]
                max_value = max(max_value, SSD_region[row, col])
            self_similarities_vec[0][num_bins] = max_value
            num_bins = num_bins + 1
    return self_similarities_vec


"""
:param lab:
:param row:
:param col:
:param patch_size:
"""


def getPatch(lab, row, col, patch_size):
    # here are four scenarios
    patch_row, patch_col = patch_size
    if patch_row % 2 == 0:
        if patch_col % 2 == 0:
            return lab[row - patch_row / 2:row + patch_row / 2, col - patch_col / 2: col + patch_col / 2, :]
        else:
            return lab[row - patch_row / 2:row + patch_row / 2, col - patch_col // 2: col + patch_col // 2 + 1, :]
    else:
        if patch_col % 2 == 0:
            return lab[row - patch_row // 2:row + patch_row // 2 + 1, col - patch_col / 2: col + patch_col / 2, :]
        else:
            return lab[row - patch_row // 2:row + patch_row // 2 + 1, col - patch_col // 2: col + patch_col // 2 + 1, :]


"""
:param lab:
:param row:
:param col:
:param region_size:
"""


def getRegion(lab, row, col, region_size):
    region_row, region_col = region_size
    if region_row % 2 == 0:
        if region_col % 2 == 0:
            return lab[row - region_row / 2:row + region_row / 2, col - region_col / 2: col + region_col / 2, :]
        else:
            return lab[row - region_row / 2:row + region_row / 2, col - region_col // 2: col + region_col // 2 + 1, :]
    else:
        if region_col % 2 == 0:
            return lab[row - region_row // 2:row + region_row // 2 + 1, col - region_col / 2: col + region_col / 2, :]
        else:
            return lab[row - region_row // 2:row + region_row // 2 + 1,
                   col - region_col // 2: col + region_col // 2 + 1, :]


"""
:param lab:
:param region_size:
:param patch_size
:param bin:
:param bin_size:
"""


def self_sim_descriptor(lab, region_size, patch_size, bin, bin_size):
    lab_size = lab.shape
    center_region = [np.floor(region_size[0] / 2).astype(int), np.floor(region_size[1] / 2).astype(int)]
    vec_size = bin_size[0] * bin_size[1]
    self_similarities = np.zeros((lab_size[0], lab_size[1], vec_size))

    if region_size[0] % 2 == 0:
        if region_size[1] % 2 == 0:
            for row in range(center_region[0], lab_size[0] - center_region[0]):
                for col in range(center_region[1], lab_size[1] - center_region[1]):
                    patch = getPatch(lab, row, col, patch_size)
                    region = lab[row - center_region[0]:row + center_region[0],
                             col - center_region[1]: col + center_region[1], :]
                    SSD_region = cal_ssd_new(patch, region, region_size, patch_size)
                    vec = get_self_sim_vec(SSD_region, bin, bin_size)  # 1x45
                    min_max = preprocessing.MinMaxScaler(feature_range=(0, 1))
                    X_scale = min_max.fit_transform(vec.T)  # 45x1
                    self_similarities[row, col, :] = X_scale.T  # 1x45
        else:
            for row in range(center_region[0], lab_size[0] - center_region[0]):
                for col in range(center_region[1], lab_size[1] - center_region[1] - 1):
                    patch = getPatch(lab, row, col, patch_size)
                    region = lab[row - center_region[0]:row + center_region[0],
                             col - center_region[1]: col + center_region[1] + 1, :]
                    SSD_region = cal_ssd_new(patch, region, region_size, patch_size)
                    vec = get_self_sim_vec(SSD_region, bin, bin_size)
                    min_max = preprocessing.MinMaxScaler(feature_range=(0, 1))
                    X_scale = min_max.fit_transform(vec.T)
                    self_similarities[row, col, :] = X_scale.T
    else:
        if region_size[1] % 2 == 0:
            for row in range(center_region[0], lab_size[0] - center_region[0] - 1):
                for col in range(center_region[1], lab_size[1] - center_region[1]):
                    patch = getPatch(lab, row, col, patch_size)
                    region = lab[row - center_region[0]:row + center_region[0] + 1,
                             col - center_region[1]: col + center_region[1], :]
                    SSD_region = cal_ssd_new(patch, region, region_size, patch_size)
                    vec = get_self_sim_vec(SSD_region, bin, bin_size)
                    min_max = preprocessing.MinMaxScaler(feature_range=(0, 1))
                    X_scale = min_max.fit_transform(vec.T)
                    self_similarities[row, col, :] = X_scale.T
        else:
            for row in range(center_region[0], lab_size[0] - center_region[0] - 1):
                for col in range(center_region[1], lab_size[1] - center_region[1] - 1):
                    patch = getPatch(lab, row, col, patch_size)
                    region = lab[row - center_region[0]:row + center_region[0] + 1,
                             col - center_region[1]: col + center_region[1] + 1, :]
                    SSD_region = cal_ssd_new(patch, region, region_size, patch_size)
                    vec = get_self_sim_vec(SSD_region, bin, bin_size)
                    min_max = preprocessing.MinMaxScaler(feature_range=(0, 1))
                    X_scale = min_max.fit_transform(vec.T)
                    self_similarities[row, col, :] = X_scale.T
    return self_similarities


"""
:param lab
:param region_size 
:param patch_size
:param bin
:param bin_size
:param jump
"""
def self_sim_descriptor_jump(lab, region_size, patch_size, bin, bin_size, jump):
    lab_size = lab.shape
    center_region = [np.floor(region_size[0] / 2).astype(int), np.floor(region_size[1] / 2).astype(int)]
    vec_size = bin_size[0] * bin_size[1]
    self_similarities = np.zeros(((lab_size[0]-center_region[0])//jump+1, (lab_size[1]-center_region[1])//jump+1, vec_size))

    if region_size[0] % 2 == 0:
        if region_size[1] % 2 == 0:
            for row in range(center_region[0], lab_size[0] - center_region[0], jump):
                for col in range(center_region[1], lab_size[1] - center_region[1], jump):
                    patch = getPatch(lab, row, col, patch_size)
                    region = lab[row - center_region[0]:row + center_region[0],
                             col - center_region[1]: col + center_region[1], :]
                    SSD_region = cal_ssd_new(patch, region, region_size, patch_size)
                    vec = get_self_sim_vec(SSD_region, bin, bin_size)  # 1x45
                    min_max = preprocessing.MinMaxScaler(feature_range=(0, 1))
                    X_scale = min_max.fit_transform(vec.T)  # 45x1
                    self_similarities[(row-center_region[0])//jump, (col-center_region[1])//jump, :] = X_scale.T  # 1x45
        else:
            for row in range(center_region[0], lab_size[0] - center_region[0], jump):
                for col in range(center_region[1], lab_size[1] - center_region[1] - 1, jump):
                    patch = getPatch(lab, row, col, patch_size)
                    region = lab[row - center_region[0]:row + center_region[0],
                             col - center_region[1]: col + center_region[1] + 1, :]
                    SSD_region = cal_ssd_new(patch, region, region_size, patch_size)
                    vec = get_self_sim_vec(SSD_region, bin, bin_size)
                    min_max = preprocessing.MinMaxScaler(feature_range=(0, 1))
                    X_scale = min_max.fit_transform(vec.T)
                    self_similarities[(row-center_region[0])//jump, (col-center_region[1])//jump, :] = X_scale.T
    else:
        if region_size[1] % 2 == 0:
            for row in range(center_region[0], lab_size[0] - center_region[0] - 1, jump):
                for col in range(center_region[1], lab_size[1] - center_region[1], jump):
                    patch = getPatch(lab, row, col, patch_size)
                    region = lab[row - center_region[0]:row + center_region[0] + 1,
                             col - center_region[1]: col + center_region[1], :]
                    SSD_region = cal_ssd_new(patch, region, region_size, patch_size)
                    vec = get_self_sim_vec(SSD_region, bin, bin_size)
                    min_max = preprocessing.MinMaxScaler(feature_range=(0, 1))
                    X_scale = min_max.fit_transform(vec.T)
                    self_similarities[(row-center_region[0])//jump, (col-center_region[1])//jump, :] = X_scale.T
        else:
            for row in range(center_region[0], lab_size[0] - center_region[0] - 1), jump:
                for col in range(center_region[1], lab_size[1] - center_region[1] - 1, jump):
                    patch = getPatch(lab, row, col, patch_size)
                    region = lab[row - center_region[0]:row + center_region[0] + 1,
                             col - center_region[1]: col + center_region[1] + 1, :]
                    SSD_region = cal_ssd_new(patch, region, region_size, patch_size)
                    vec = get_self_sim_vec(SSD_region, bin, bin_size)
                    min_max = preprocessing.MinMaxScaler(feature_range=(0, 1))
                    X_scale = min_max.fit_transform(vec.T)
                    self_similarities[(row-center_region[0])//jump, (col-center_region[1])//jump, :] = X_scale.T
    return self_similarities


"""
:param bb_path:
:param region_size:
:param patch_size:
:param bin_size:
"""
def com_Self_Similarities_jump(bb_path, region_size, patch_size, bin_size):
    radius, angle = cartTopol(region_size)
    bin = get_bin(radius, angle, bin_size, region_size)

    img = cv2.imread(bb_path, cv2.IMREAD_COLOR)
    lab = cv2.cvtColor(img, cv2.COLOR_BGR2LAB)
    lab = lab[:, :, ::-1]
    # print("lab shape", lab.shape)
    width = lab.shape[0] // 3
    height = lab.shape[1] // 3
    dim = (width, height)
    lab = cv2.resize(lab, dim, interpolation=cv2.INTER_AREA)

    jump = 3
    self_similarities = self_sim_descriptor_jump(lab, region_size, patch_size, bin, bin_size, jump)
    print("self_similarities", self_similarities.shape)
    print(self_similarities[1:1, 0:3, :].shape)
    # print(len(self_similarities[0, 0:3, :].shape))
    # print(self_similarities[1])
    print(np.count_nonzero(self_similarities))
    return self_similarities


"""
:param bb_path:
:param region_size:
:param patch_size:
:param bin_size:
"""
def com_Self_Similarities_new(bb_path, region_size, patch_size, bin_size):
    radius, angle = cartTopol(region_size)
    bin = get_bin(radius, angle, bin_size, region_size)

    img = cv2.imread(bb_path, cv2.IMREAD_COLOR)
    lab = cv2.cvtColor(img, cv2.COLOR_BGR2LAB)
    lab = lab[:, :, ::-1]
    # print("lab shape", lab.shape)
    width = lab.shape[0] // 3
    height = lab.shape[1] // 3
    dim = (width, height)
    lab = cv2.resize(lab, dim, interpolation=cv2.INTER_AREA)
    self_similarities = self_sim_descriptor(lab, region_size, patch_size, bin, bin_size)
    print("self_similarities", self_similarities.shape)
    print(self_similarities[1:1, 0:3, :].shape)
    # print(len(self_similarities[0, 0:3, :].shape))
    # print(self_similarities[1])
    print(np.count_nonzero(self_similarities))
    return self_similarities



"""
:param imgRgb:
:param region_size:
:param patch_size:
:param bin:
:param bin_size: 
transform an image into the binned log-polar representation 
"""


def com_Self_Similarities_old(imgRgb, region_size, patch_size, bin, bin_size):
    img = cv2.imread(imgRgb, cv2.IMREAD_COLOR)
    lab = cv2.cvtColor(img, cv2.COLOR_BGR2LAB)
    lab = lab[:, :, ::-1]
    print("shape", lab.shape)
    width = lab.shape[0] // 3
    height = lab.shape[1] // 3
    dim = (width, height)
    lab = cv2.resize(lab, dim, interpolation=cv2.INTER_AREA)
    lab_size = lab.shape
    print("lab_size", lab_size)
    alpha = 1 / (85 ^ 2)
    vec_size = bin_size[0] * bin_size[1]
    self_similarities = np.zeros((lab_size[0], lab_size[1], vec_size))
    center_region = [np.floor(region_size[0] / 2).astype(int), np.floor(region_size[1] / 2).astype(int)]
    center_patch_size = [np.floor(patch_size[0] / 2).astype(int), np.floor(patch_size[1] / 2).astype(int)]
    print("center_patch_size", center_patch_size)
    for row in range(int(center_region[0]), int(lab_size[0] - center_region[0])):
        for col in range(int(center_region[1]), int(lab_size[1] - center_region[1])):
            patch = lab[row - center_patch_size[0]:row + center_patch_size[0] + 1,
                    col - center_patch_size[1]: col + center_patch_size[1] + 1, :]
            region = lab[row - center_region[0]:row + center_region[0] + 1,
                     col - center_region[1]: col + center_region[1] + 1, :]
            # print("patch_size", patch.shape)
            # print("patch", patch)
            SSD_region = cal_ssd_old(patch, region, region_size, alpha, center_patch_size)
            vec = get_self_sim_vec(SSD_region, bin, bin_size, vec_size)
            min_max = preprocessing.MinMaxScaler(feature_range=(0, 1))
            X_scale = min_max.fit_transform(vec.T)
            # [LSSD, ps] = mapminmax(vec,0,1)
            self_similarities[row, col, :] = X_scale.T
    return self_similarities


''' 
 read unhidden files
'''


def listdir_nohidden(path):
    return glob.glob('*')


"""
directory: binary
subdirectory: function
read traces in function directory
"""


def getBinary():
    inp_dir = '/Users/zhong/Desktop/VisBSD'
    os.chdir(inp_dir)  # the parent fold with sub-folders
    # list_binaries = os.listdir(os.getcwd()) #vector of strings with family names
    # print(list_binaries)
    # print("getcwd", os.getcwd())
    list_binaries = sorted(listdir_nohidden(os.getcwd()))
    binary_funcs = []  # list of functions per binary
    no_funcs = []  # No. of functions per binary
    no_bbs = []  # No. of basic blocks per function
    # print(list_binaries)
    for binary in range(len(list_binaries)):  # which binary
        os.chdir(list_binaries[binary])
        list_funs = sorted(listdir_nohidden(os.getcwd()))
        # print(list_funs)
        no_func = len(list_funs)
        no_funcs.append(no_func)
        binary_funcs.append(list_funs)
        for func in range(len(list_funs)):  # which function
            os.chdir(list_funs[func])
            list_bb = sorted(listdir_nohidden(os.getcwd()))
            # print(list_bb)
            no_bb = len(list_bb)  # No. of basic blocks for the function
            no_bbs.append(no_bb)
            os.chdir('..')  # go back to "function" directory
        os.chdir('..')  # go back to "binary" directory
    print(list_binaries, no_funcs, no_bbs)
    return list_binaries, binary_funcs, no_funcs, no_bbs
    #    no_per_family = len(glob.glob('*.jpg'))
    #    no_imgs.append(no_per_family)
    #    os.chdir('..')
    # return no_imgs, list_fams


"""
:param list_binaries: list of binaries
"""


def getFunc(list_binaries):
    func_path = []
    for binary in range(len(list_binaries)):
        os.chdir(list_binaries[binary])
        list_funs = sorted(glob.glob(os.path.join(os.getcwd(), '*')))
        func_path.append(list_funs)
        os.chdir('..')
    # print(func_path)
    return func_path


"""
:param list_funs: list of function paths
"""


def getBB(list_funs):
    # print(list_funs)
    bb_path_per_binary = []
    for binary in range(len(list_funs)):  # which function
        bb_path_per_func = []
        for func in range(len(list_funs[binary])):
            os.chdir(list_funs[binary][func])
            #list_bb = sorted(listdir_nohidden(os.getcwd()))
            # print(list_bb)
            list_bb = sorted(glob.glob(os.path.join(os.getcwd(), '*')))
            # print(list_bb)
            bb_path_per_func.append(list_bb)
            os.chdir('..')  # go back to "function" directory
        bb_path_per_binary.append(bb_path_per_func)
    # print("bb_binary", bb_path_per_binary)
    return bb_path_per_binary


"""

"""


def draw_result(src_img, sig_score_img, region_size, scale):
    ma = np.maximum(np.maximum(sig_score_img))
    mi = np.minimum(np.minimum(sig_score_img))

    norm_sig_score_img = (sig_score_img - mi) / (ma - mi)
    norm_sig_score_img = norm_sig_score_img * 255
    norm_sig_score_img = cv2.resize(norm_sig_score_img, scale)

    indices = np.where(norm_sig_score_img == norm_sig_score_img.max())
    rect_img = np.zeros(norm_sig_score_img.shape[0], norm_sig_score_img.shape[1])
    for indice in indices:
        x, y = indice
        rect_img[x - np.floor(region_size[0] / 2):x + np.floor(region_size[0] / 2),
        y - np.floor((region_size[1] / 2)):y + np.floor(region_size[1] / 2)] = 128
        rect_img = cv2.resize(rect_img, scale)
        rect_size = [src_img.shape[0], src_img.shape[1]]
        src_img[:, :, 1] = src_img[:, :, 1] + rect_img[0:rect_size[0], 0:rect_size[1]]


"""
:param bb: basic block image
:param func: all basic block images in a func
:param sub: a sub region for comparison
:param max_match: an array memorizes the max self-similarity region
:param num_img: heading to a certain image
:param match_score: saves all match scores

"""


def com_similarity_match(bb, func, sub, max_match, num_img, match_score):
    for bb2 in func:
        if bb2 != bb:
            self_similarities2 = com_Self_Similarities_new(bb2, region_size, patch_size,
                                                           bin_size)
            print("self_similarities2.shape", self_similarities2.shape)
            print(self_similarities2[0, 0, :])
            sub_descriptors = []

            if np.count_nonzero(sub.shape) == 3:
                for row in range(self_similarities2.shape[0] - sub.shape[0] + 1):
                    for col in range(self_similarities2.shape[1] - sub.shape[1] + 1):
                        sub_descriptors.append(self_similarities2[row:row + sub.shape[0], col:col + sub.shape[1], :])

                sub_descriptors = np.reshape(sub_descriptors, [self_similarities2.shape[0] - sub.shape[0] + 1,
                                                               self_similarities2.shape[1] - sub.shape[1] + 1,
                                                               sub.shape[0], sub.shape[1], sub.shape[2]])
                temp1 = np.tile(sub,
                                [self_similarities2.shape[0] - sub.shape[0] + 1,
                                 self_similarities2.shape[1] - sub.shape[1] + 1, 1, 1, 1])
                dsq = np.square(sub_descriptors - temp1)
                temp2 = np.sum(dsq, axis=len(dsq.shape) - 1)
                temp2 = np.sum(temp2, axis=len(temp2.shape) - 1)
                temp2 = np.sum(temp2, axis=len(temp2.shape) - 1)
                temp2 = -1 * temp2

            elif np.count_nonzero(sub.shape) == 2:
                for row in range(self_similarities2.shape[0] - sub.shape[0] + 1):
                    for col in range(self_similarities2.shape[1] - sub.shape[1] + 1):
                        sub_descriptors.append(self_similarities2[row:row + sub.shape[0], col:col + sub.shape[1], :])

                sub_descriptors = np.reshape(sub_descriptors, [self_similarities2.shape[0] - sub.shape[0] + 1,
                                                               self_similarities2.shape[1] - sub.shape[1] + 1,
                                                               sub.shape[0], sub.shape[1]])
                temp1 = np.tile(sub,
                                [self_similarities2.shape[0] - sub.shape[0] + 1,
                                 self_similarities2.shape[1] - sub.shape[1] + 1, 1, 1])
                temp2 = -1 * (np.sum(np.square(sub_descriptors - temp1), axis=len(temp1.shape) - 1))
                temp2 = np.sum(temp2, axis=len(temp2.shape) - 1)

            else:
                temp1 = np.tile(sub,
                                [self_similarities2.shape[0],
                                 self_similarities2.shape[1], 1])

                temp2 = -1 * (np.sum(np.square(self_similarities2 - temp1), axis=len(temp1.shape) - 1))

            """
            compare self_descriptor values in one sub region with another sub region
            """

            # max_match[0, num_img] = np.maximum(np.maximum(temp2))
            max_match[0, num_img] = np.max(temp2)
            print("max", np.max(temp2))
            match = np.reshape(temp2, [-1, 1])
            match_score.append(match)


"""
:param binary: basic block image
:param bb_path: all binaries 
:param sub: a sub region for comparison
:param max_match: an array memorizes the max self-similarity region
:param num_img: heading to a certain image
:param match_score: saves all match scores

"""
def com_similarity_match_new(bb_path, binary, sub, sub_region, max_match, match_score):
    num_files = 0
    for binary2 in bb_path:
        if binary2 != binary:
            for func2 in binary2:
                for bb2 in func2:
                    self_similarities2 = com_Self_Similarities_new(bb2, region_size, patch_size,
                                                                   bin_size)
                    print("self_similarities2.shape", self_similarities2.shape)

                    sub_descriptors = []
                    if np.count_nonzero(sub.shape) == 3:
                        for row in range(self_similarities2.shape[0] - sub.shape[0] + 1):
                            for col in range(self_similarities2.shape[1] - sub.shape[1] + 1):
                                sub_descriptors.append(
                                    self_similarities2[row:row + sub.shape[0], col:col + sub.shape[1], :])

                        sub_descriptors = np.reshape(sub_descriptors, [self_similarities2.shape[0] - sub.shape[0] + 1,
                                                                       self_similarities2.shape[1] - sub.shape[1] + 1,
                                                                       sub.shape[0], sub.shape[1], sub.shape[2]])
                        temp1 = np.tile(sub,
                                        [self_similarities2.shape[0] - sub.shape[0] + 1,
                                         self_similarities2.shape[1] - sub.shape[1] + 1, 1, 1, 1])
                        dsq = np.square(sub_descriptors - temp1)
                        temp2 = np.sum(dsq, axis=len(dsq.shape) - 1)
                        temp2 = np.sum(temp2, axis=len(temp2.shape) - 1)
                        temp2 = np.sum(temp2, axis=len(temp2.shape) - 1)
                        temp2 = -1 * temp2

                    elif np.count_nonzero(sub.shape) == 2:
                        if sub_region[0] <= 1:
                            for row in range(self_similarities2.shape[0]):
                                for col in range(self_similarities2.shape[1] - sub.shape[0] + 1):
                                    sub_descriptors.append(
                                        self_similarities2[row, col:col + sub.shape[0], :])
                            sub_descriptors = np.reshape(sub_descriptors,
                                                         [self_similarities2.shape[0],
                                                          self_similarities2.shape[1] - sub.shape[0] + 1,
                                                          sub.shape[0], sub.shape[1]])
                            temp1 = np.tile(sub,
                                            [self_similarities2.shape[0],
                                             self_similarities2.shape[1] - sub.shape[0] + 1, 1, 1])

                        else:
                            for row in range(self_similarities2.shape[0] - sub.shape[0] + 1):
                                for col in range(self_similarities2.shape[1]):
                                    sub_descriptors.append(
                                        self_similarities2[row:row + sub.shape[0], col, :])
                            sub_descriptors = np.reshape(sub_descriptors,
                                                     [self_similarities2.shape[0] - sub.shape[0] + 1,
                                                      self_similarities2.shape[1],
                                                      sub.shape[0], sub.shape[1]])
                            temp1 = np.tile(sub,
                                        [self_similarities2.shape[0] - sub.shape[0] + 1,
                                         self_similarities2.shape[1], 1, 1])

                        temp2 = -1 * (np.sum(np.square(sub_descriptors - temp1), axis=len(temp1.shape) - 1))
                        temp2 = np.sum(temp2, axis=len(temp2.shape) - 1)


                    else:
                        temp1 = np.tile(sub,
                                        [self_similarities2.shape[0],
                                         self_similarities2.shape[1], 1])

                        temp2 = -1 * (np.sum(np.square(self_similarities2 - temp1), axis=len(temp1.shape) - 1))

                    """
                    compare self_descriptor values in one sub region with another sub region
                    """

                    # max_match[0, num_img] = np.maximum(np.maximum(temp2))
                    max_match[0, num_files] = np.max(temp2)
                    num_files = num_files + 1
                    print("max", np.max(temp2))
                    match = np.reshape(temp2, [-1, 1])
                    match_score.append(match)
    return max_match


"""
:param region_size: a region
:param patch_size: a patch inside a region
:param bin_size: the no. of bins distributed by radius and angle
:param sub_region: look for self-similarities according to regions
"""


def bsd(region_size, patch_size, bin_size, sub_region):
    list_binaries, binary_funcs, no_funcs, no_bbs = getBinary()
    list_funs = getFunc(list_binaries)
    bb_path = getBB(list_funs)
    print("bb_path_bsd", bb_path)
    center_sub = [np.floor(sub_region[0] / 2).astype(int), np.floor(sub_region[1] / 2).astype(int)]
    max_match_binary = []
    for binary in bb_path:
        max_match_func = []
        print("binary", binary)
        for func in binary:
            max_match_img = []
            print("func", func)
            for bb in func:
                print("bb", bb)
                self_similarities1 = com_Self_Similarities_new(bb, region_size, patch_size, bin_size)
                img_size1 = self_similarities1.shape
                num_img = 0
                max_matches = np.zeros((img_size1[0], img_size1[1], len(func) - 1))
                """
                considering the odd and even for the size of a sub region
                """

                if sub_region[0] % 2 == 0:
                    if sub_region[1] % 2 == 0:
                        for row in range(center_sub[0], img_size1[0] - center_sub[0]):
                            for col in range(center_sub[1], img_size1[1] - center_sub[1]):
                                if sub_region[0] == 0:
                                    if sub_region[1] == 0:
                                        sub = self_similarities1[row, col, :]
                                    else:
                                        sub = self_similarities1[row, col - center_sub[1]:col + center_sub[1], :]
                                else:
                                    if sub_region[1] == 0:
                                        sub = self_similarities1[row - center_sub[0]:row + center_sub[0], col, :]
                                    else:
                                        sub = self_similarities1[row - center_sub[0]:row + center_sub[0], \
                                              col - center_sub[1]:col + center_sub[1], :]

                                print("sub.shape", sub.shape)
                                max_match = np.zeros((1, len(func) - 1))
                                match_score = []
                                com_similarity_match(bb, func, sub, max_match, num_img, match_score)
                                max_matches[row, col, :] = max_match
                                num_img = num_img + 1

                    else:
                        for row in range(center_sub[0], img_size1[0] - center_sub[0]):
                            for col in range(center_sub[1], img_size1[1] - center_sub[1] - 1):
                                if sub_region[1] <= 1:
                                    sub = self_similarities1[row - center_sub[0]:row + center_sub[0], col, :]
                                else:
                                    sub = self_similarities1[row - center_sub[0]:row + center_sub[0], \
                                          col - center_sub[1]:col + center_sub[1] + 1, :]
                                max_match = np.zeros((1, len(func) - 1))
                                match_score = []
                                com_similarity_match(bb, func, sub, max_match, num_img, match_score)
                                max_matches[row, col, :] = max_match
                                num_img = num_img + 1

                else:
                    if sub_region[1] % 2 == 0:
                        for row in range(center_sub[0], img_size1[0] - center_sub[0] - 1):
                            for col in range(center_sub[1], img_size1[1] - center_sub[1]):
                                if sub_region[0] <= 1:
                                    sub = self_similarities1[row, \
                                          col - center_sub[1]:col + center_sub[1], :]
                                else:
                                    sub = self_similarities1[row - center_sub[0]:row + center_sub[0] + 1, \
                                          col - center_sub[1]:col + center_sub[1], :]
                                max_match = np.zeros((1, len(func) - 1))
                                match_score = []
                                com_similarity_match(bb, func, sub, max_match, num_img, match_score)
                                max_matches[row, col, :] = max_match
                                num_img = num_img + 1

                    else:
                        for row in range(center_sub[0], img_size1[0] - center_sub[0] - 1):
                            for col in range(center_sub[1], img_size1[1] - center_sub[1] - 1):
                                if sub_region[0] <= 1:
                                    if sub_region[1] <= 1:
                                        sub = self_similarities1[row, col, :]
                                    else:
                                        sub = self_similarities1[row, col - center_sub[1]:col + center_sub[1] + 1, :]
                                else:
                                    if sub_region[1] <= 1:
                                        sub = self_similarities1[row - center_sub[0]:row + center_sub[0] + 1, \
                                              col, :]
                                    else:
                                        sub = self_similarities1[row - center_sub[0]:row + center_sub[0] + 1, \
                                              col - center_sub[1]:col + center_sub[1] + 1, :]

                                max_match = np.zeros((1, len(func) - 1))
                                match_score = []
                                com_similarity_match(bb, func, sub, max_match, num_img, match_score)
                                max_matches[row, col, :] = max_match
                                num_img = num_img + 1
                print("max_matches.shape", max_matches.shape)
                max_match_img.append(max_matches)
            max_match_func.append(max_match_img)
        max_match_binary.append(max_match_func)


"""
:param region_size: a region
:param patch_size: a patch inside a region
:param bin_size: the no. of bins distributed by radius and angle
:param sub_region: look for self-similarities according to regions
"""
def bsd_new(region_size, patch_size, bin_size, sub_region):
    list_binaries, binary_funcs, no_funcs, no_bbs = getBinary()
    list_funs = getFunc(list_binaries)
    bb_path = getBB(list_funs)
    print("bb_path_bsd", bb_path)
    center_sub = [np.floor(sub_region[0] / 2).astype(int), np.floor(sub_region[1] / 2).astype(int)]
    max_match_binary = []
    for binary in bb_path:
        max_match_func = []
        print("binary", binary)
        for func in binary:
            max_match_img = []
            print("func", func)
            for bb in func:
                print("bb", bb)
                self_similarities1 = com_Self_Similarities_new(bb, region_size, patch_size, bin_size)
                img_size1 = self_similarities1.shape
                num_files = countImgs(binary)
                max_matches = np.zeros((img_size1[0], img_size1[1], num_files))
                """
                considering the odd and even for the size of a sub region
                """

                if sub_region[0] % 2 == 0:
                    if sub_region[1] % 2 == 0:
                        for row in range(center_sub[0], img_size1[0] - center_sub[0]):
                            for col in range(center_sub[1], img_size1[1] - center_sub[1]):
                                if sub_region[0] == 0:
                                    if sub_region[1] == 0:
                                        sub = self_similarities1[row, col, :]
                                    else:
                                        sub = self_similarities1[row, col - center_sub[1]:col + center_sub[1], :]
                                else:
                                    if sub_region[1] == 0:
                                        sub = self_similarities1[row - center_sub[0]:row + center_sub[0], col, :]
                                    else:
                                        sub = self_similarities1[row - center_sub[0]:row + center_sub[0], \
                                              col - center_sub[1]:col + center_sub[1], :]

                                print("sub.shape", sub.shape)
                                max_match = np.zeros((1, num_files))
                                match_score = []
                                max_match = com_similarity_match_new(bb_path, binary, sub, max_match, sub_region, match_score)
                                max_matches[row, col, :] = max_match


                    else:
                        for row in range(center_sub[0], img_size1[0] - center_sub[0]):
                            for col in range(center_sub[1], img_size1[1] - center_sub[1] - 1):
                                if sub_region[0] == 0:
                                    if sub_region[1] <= 1:
                                        sub = self_similarities1[row, col, :]
                                    else:
                                        sub = self_similarities1[row, col-center_sub[1]:col+center_sub[1]+1, :]

                                else:
                                    if sub_region[1] <= 1:
                                        sub = self_similarities1[row - center_sub[0]:row + center_sub[0], col, :]
                                    else:
                                        sub = self_similarities1[row - center_sub[0]:row + center_sub[0], \
                                              col - center_sub[1]:col + center_sub[1] + 1, :]
                                max_match = np.zeros((1, num_files))
                                match_score = []
                                max_match = com_similarity_match_new(bb_path, binary, sub, max_match, sub_region, match_score)
                                max_matches[row, col, :] = max_match


                else:
                    if sub_region[1] % 2 == 0:
                        for row in range(center_sub[0], img_size1[0] - center_sub[0] - 1):
                            for col in range(center_sub[1], img_size1[1] - center_sub[1]):
                                if sub_region[0] <= 1:
                                    if sub_region[1] == 0:
                                        sub = self_similarities1[row, col, :]
                                    else:
                                        sub = self_similarities1[row, \
                                              col - center_sub[1]:col + center_sub[1], :]
                                else:
                                    if sub_region[1] == 0:
                                        sub = self_similarities1[row - center_sub[0]:row + center_sub[0] + 1, \
                                              col, :]
                                    else:
                                        sub = self_similarities1[row - center_sub[0]:row + center_sub[0] + 1, \
                                              col - center_sub[1]:col + center_sub[1], :]
                                max_match = np.zeros((1, num_files))
                                match_score = []
                                max_match = com_similarity_match_new(bb_path, binary, sub, max_match, sub_region, match_score)
                                max_matches[row, col, :] = max_match


                    else:
                        for row in range(center_sub[0], img_size1[0] - center_sub[0] - 1):
                            for col in range(center_sub[1], img_size1[1] - center_sub[1] - 1):
                                if sub_region[0] <= 1:
                                    if sub_region[1] <= 1:
                                        sub = self_similarities1[row, col, :]
                                    else:
                                        sub = self_similarities1[row, col - center_sub[1]:col + center_sub[1] + 1, :]
                                else:
                                    if sub_region[1] <= 1:
                                        sub = self_similarities1[row - center_sub[0]:row + center_sub[0] + 1, \
                                              col, :]
                                    else:
                                        sub = self_similarities1[row - center_sub[0]:row + center_sub[0] + 1, \
                                              col - center_sub[1]:col + center_sub[1] + 1, :]

                                max_match = np.zeros((1, num_files))
                                match_score = []
                                max_match = com_similarity_match_new(bb_path, binary, sub, max_match, sub_region, match_score)
                                max_matches[row, col, :] = max_match
                print("max_matches.shape", max_matches.shape)
                max_match_img.append(max_matches)
            max_match_func.append(max_match_img)
        max_match_binary.append(max_match_func)


def countImgs(bin):
    list_binaries, binary_funcs, no_funcs, no_bbs = getBinary()
    list_funs = getFunc(list_binaries)
    bb_path = getBB(list_funs)
    num_files = 0
    for binary in bb_path:
        if binary != bin:
            for func in binary:
                for _ in func:
                    num_files = num_files+1
    print("num_files", num_files)
    return num_files


"""
calculate the similarity between traces
"""
def imgProcess(list_files):
    n_img = 5
    region_size = [45, 37]
    patch_size = [5, 5]
    bin_size = [15, 3]
    radius, angle = cartTopol(region_size)
    bin = get_bin(radius, angle, bin_size, region_size)
    src_img = r"driverlicense.jpeg"

    width = 1
    height = 1
    center_sub = [matlab.floor(width / 2), matlab.floor(height / 2)]
    for img1 in list_files:
        self_similarities1 = com_Self_Similarities_old(img1, region_size, patch_size, bin, bin_size)
        img1_size = self_similarities1.shape
        sig_score_img = np.zeros(img1_size[0], img1_size[1])
        for row in range(center_sub[0], img1_size[0] - center_sub[0]):
            for col in range(center_sub[1], img1_size[1] - center_sub[1]):
                sub_img = np.reshape(self_similarities1[row - center_sub[0]:row + center_sub[0],
                                     col - center_sub[1]: col + center_sub[1], :], (1, 1, -1))
                max_match = np.zeros(len(list_files) - 1, 1)
                num_img = 0
                match_score = []
                for img2 in list_files:
                    if img2 != img1:
                        self_similarities2 = com_Self_Similarities_old(img2, region_size, patch_size, bin, bin_size)
                        temp1 = np.tile(sub_img, [self_similarities2.shape[0], self_similarities2.shape[1], 1])
                        temp2 = -1 * (np.sum(np.square(self_similarities2 - temp1), axis=2))
                        max_match[num_img, 1] = np.maximum(np.maximum(temp2))
                        match_score.append(np.reshape(temp2, [-1, 1]))
                        num_img = num_img + 1
                avgMatch = np.mean(match_score, axis=0)
                stdMatch = np.std(match_score, axis=0)
                sig_score_img[row, col] = np.sum((max_match - avgMatch) / stdMatch)
        draw_result(src_img, sig_score_img / (len(list_files) - 1), region_size, 3)


def verbit(region_size, patch_size, bin_size, sub_region):
    list_binaries, binary_funcs, no_funcs, no_bbs = getBinary()
    list_funs = getFunc(list_binaries)
    bb_path = getBB(list_funs)
    print("bb_path_bsd", bb_path)
    center_sub = [np.floor(sub_region[0] / 2).astype(int), np.floor(sub_region[1] / 2).astype(int)]
    pass



