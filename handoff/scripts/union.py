import sys
for p in sys.argv[1:]:
    out=[];state=0
    for line in open(p).read().split('\n'):
        if line.startswith('<<<<<<< '): state=1; continue
        if line.startswith('=======') and state==1: state=2; continue
        if line.startswith('>>>>>>> ') and state==2: state=0; continue
        out.append(line)
    open(p,'w').write('\n'.join(out))
    print(p, 'resolved')
