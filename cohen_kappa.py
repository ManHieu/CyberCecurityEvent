import os
from score_f1 import XmlParser
from collections import defaultdict


TYPES = ['DISCOVER.Misconfiguration', 'DISCOVER.Kernel_Flaws',
                    'DISCOVER.Buffer_Overflow', 'DISCOVER.Insufficient_Authentication_Validation',
                    'DISCOVER.SQLI', 'DISCOVER.XSS', 'DISCOVER.Back_door',
                    'DISCOVER.Incorrect_Permission', 'DISCOVER.Social_Engineering',
                    
                    'PATCH.Misconfiguration', 'PATCH.Kernel_Flaws',
                    'PATCH.Buffer_Overflow', 'PATCH.Insufficient_Authentication_Validation',
                    'PATCH.SQLI', 'PATCH.XSS', 'PATCH.Back_door',
                    'PATCH.Incorrect_Permission', 'PATCH.Social_Engineering',
                    
                    'ATTACK.User_Compromise', 'ATTACK.Root_Compromise', 'ATTACK.Web_Compromise',
                    'ATTACK.Viruss', 'ATTACK.Spyware', 'ATTACK.Trojan', 'ATTACK.Worms',
                    'ATTACK.Arbitrary_Code_Execution', 'ATTACK.DoS',
                    
                    'IMPACT.Distort', 'IMPACT.Disrupt', 'IMPACT.Destruct',
                    'IMPACT.Breach', 'IMPACT.Discovery']

def Cohen_1vs1(path_goal, path_test):
    xml_parser = XmlParser()
    type_count_goal, events_doc_goal = xml_parser.parse(path_goal)
    type_count_test, events_doc_test = xml_parser.parse(path_test)
    print(events_doc_test)
    print(events_doc_goal)
    tp = 0
    for item in events_doc_test:
        if item in events_doc_goal:
            tp += 1
    
    p0 = tp / max(len(events_doc_goal), len(events_doc_test))
    pe = 0
    for typ in TYPES:
        pe += type_count_goal[typ] * type_count_test[typ]

    pe = pe / (len(events_doc_goal) * len(events_doc_test))

    k = (p0 - pe) / (1 - pe + 0.001)

    return k, type_count_goal, events_doc_goal, type_count_test, events_doc_test, tp

# print(Cohen_1vs1('.\\thn_data\\cyber_attack\\new_anotate\\20130409T2124000200.xml', '.\\thn_data\\cyber_attack\\DucLt\\20130409T2124000200.xml'))

def Compute_cohen_kappa(path_goal, path_test):

    files = [filename
            for filename in os.listdir(path_goal)
            if os.path.isfile(os.path.join(path_test, filename))]

    # print('\n'.join(files))

    tp = 0
    test_len = 0
    goad_len = 0
    type_count_goal = defaultdict(int)
    type_count_test = defaultdict(int)

    for item in files:
        doc_test_path = path_test + '\\' + item
        doc_goal_path = path_goal + '\\' + item
        print('===========================================================')
        print(doc_test_path)
        print(doc_goal_path)

        k, type_count_goal_file, events_doc_goal, type_count_test_file, events_doc_test, tp_file = Cohen_1vs1(doc_goal_path, doc_test_path)
        goad_len += len(events_doc_goal)
        test_len += len(events_doc_test)
        tp += tp_file
        for typ in TYPES:
            type_count_goal[typ] += type_count_goal_file[typ]
            type_count_test[typ] += type_count_test_file[typ]
    
    p0 = tp / (max(goad_len, test_len) + 1)
    pe = 0
    for typ in TYPES:
        pe += type_count_goal[typ] * type_count_test[typ]
    pe = pe / (goad_len * test_len)
    
    k = (p0 - pe) / (1 - pe + 0.001)

    return k

print('Cohen kappa: ', Compute_cohen_kappa('.\\thn_data\\Xample\\HieuMan', '.\\thn_data\\Xample\\TrongDucLe'))
