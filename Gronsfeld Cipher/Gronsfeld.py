import sys
sys.path.append("../Utils")
from ngram_score import ngram_score
from pycipher import Gronsfeld
import re
from itertools import permutations

qgram = ngram_score('../Utils/quadgrams.txt')
trigram = ngram_score('../Utils/trigrams.txt')


#ctext = 'ujh wfeuiu mhc egwisolrfu ksx odrz roedgv ibek pfvwis uksvng ff ukmgvhh'
ctext = input("\nEnter cipher text: ")

ctext = re.sub(r'[^A-Z]','',ctext.upper())

class nbest(object):
    def __init__(self,N=1000):
        self.store = []
        self.N = N
        
    def add(self,item):
        self.store.append(item)
        self.store.sort(reverse=True)
        self.store = self.store[:self.N]
    
    def __getitem__(self,k):
        return self.store[k]

    def __len__(self):
        return len(self.store)

N=100
for KLEN in range(3,20):
    rec = nbest(N)

    for i in permutations('0123456789',3):
        key = ''.join(i) + '0'*(KLEN-len(i))
        key = [int(i) for i in list(key)]
        pt = Gronsfeld(list(key)).decipher(ctext)
        score = 0
        for j in range(0,len(ctext),KLEN):
            score += trigram.score(pt[j:j+3])
        rec.add((score,''.join(i),pt[:30]))

    next_rec = nbest(N)
    for i in range(0,KLEN-3):
        for k in range(N):
            for c in '0123456789':
                key = rec[k][1] + c
                fullkey = key + '0'*(KLEN-len(key))
                fullkey = [int(i) for i in list(fullkey)]
                pt = Gronsfeld(list(fullkey)).decipher(ctext)
                score = 0
                for j in range(0,len(ctext),KLEN):
                    score += qgram.score(pt[j:j+len(key)])
                next_rec.add((score,key,pt[:30]))
        rec = next_rec
        next_rec = nbest(N)
    bestkey = rec[0][1]
    bestkey = [int(i) for i in list(bestkey)]
    pt = Gronsfeld(list(bestkey)).decipher(ctext)
    bestscore = qgram.score(pt)
    for i in range(N):
        scam = list(rec[i][1])
        scam = [int(i) for i in scam]
        pt = Gronsfeld(scam).decipher(ctext)
        score = qgram.score(pt)
        if score > bestscore:
            bestkey = scam
            bestscore = score       
    print('klen',KLEN,'key -','['+''.join(str(x) for x in bestkey)+']',Gronsfeld(bestkey).decipher(ctext))
    
