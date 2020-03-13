import os
from score_f1 import XmlParser
from collections import defaultdict


class Statistic():
    def __init__(self):
        self.collec = defaultdict(int)
        self.types = ['DISCOVER.Misconfiguration', 'DISCOVER.Kernel_Flaws',
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
        
        self.paser = XmlParser()

    def statistic(self, data_path):
        files = [filename
            for filename in os.listdir(data_path)
            if os.path.isfile(os.path.join(data_path, filename))]
        print("{} files".format(len(files)))
        with open(".\\test\\falts.txt", mode='w') as f:
            for item in files:
                doc = data_path + '\\' + item
                type_counts, evs = self.paser.parse(doc)
                # for start, end, ev_type, text in evs:
                #     # if text.count(' ') > 0:
                #     #     f.write(item + '\n')
                #     #     f.write(text + '\n')
                # #     # if text.lower() in ['gain', 'gained', 'gaining']:
                # #     #     print(item)
                #     if ev_type == 'ATTACK.DoS':
                #         print(item)
                #         break
                for typ in self.types:
                    self.collec[typ] += type_counts[typ]
            
        return self.collec

    
statis = Statistic()
ev_types = statis.statistic(".\\thn_data\\data")
sum = 0
for key, values in ev_types.items():
    sum += values
    print("{}: {}".format(key, values))

print("total: {} evs".format(sum))

# stack leak, heap leak
# kernel 
# check lại một lần nữa.
# đã check một lần lỗi cú pháp!
# đã check sqli
# đã check kernel_flaw
# đã check bufer_overflow
# đã check Insufficient_Authentication_Validation
# đã check Attack.Trojan
# đã check Attack.Spyware
# đã check Attack.Viruss

