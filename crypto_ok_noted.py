#!/usr/bin/env python3
import base64, json, re, sys, time, urllib.parse, urllib.request
from hashlib import sha256
FIELD=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G_LIB=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
       0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def inv(a,n):
    if a == 0: return 0
    lm,hm=1,0; low,high=a%n,n
    while low>1:
        r=high//low; nm,new=hm-lm*r,high-low*r
        lm,low,hm,high=nm,new,lm,low
    return lm%n
def to_jacobian(p): return (p[0],p[1],1)
def jacobian_double(p):
    if not p[1]: return (0,0,0)
    ysq=(p[1]**2)%FIELD
    S=(4*p[0]*ysq)%FIELD
    M=(3*p[0]**2)%FIELD
    nx=(M**2-2*S)%FIELD
    ny=(M*(S-nx)-8*ysq**2)%FIELD
    nz=(2*p[1]*p[2])%FIELD
    return (nx,ny,nz)
def jacobian_add(p,q):
    if not p[1]: return q
    if not q[1]: return p
    U1=(p[0]*q[2]**2)%FIELD; U2=(q[0]*p[2]**2)%FIELD
    S1=(p[1]*q[2]**3)%FIELD; S2=(q[1]*p[2]**3)%FIELD
    if U1==U2:
        if S1!=S2: return (0,0,1)
        return jacobian_double(p)
    H=U2-U1; R=S2-S1
    H2=(H*H)%FIELD; H3=(H*H2)%FIELD; U1H2=(U1*H2)%FIELD
    nx=(R**2-H3-2*U1H2)%FIELD
    ny=(R*(U1H2-nx)-S1*H3)%FIELD
    nz=(H*p[2]*q[2])%FIELD
    return (nx,ny,nz)
def from_jacobian(p):
    z=inv(p[2],FIELD)
    return ((p[0]*z**2)%FIELD,(p[1]*z**3)%FIELD)
def jacobian_multiply(a,n):
    if a[1]==0 or n==0: return (0,0,1)
    if n==1: return a
    if n<0 or n>=N: return jacobian_multiply(a,n%N)
    if n%2==0: return jacobian_double(jacobian_multiply(a,n//2))
    if n%2==1: return jacobian_add(jacobian_double(jacobian_multiply(a,n//2)),a)
    raise ValueError('unexpected scalar multiplication case')
def multiply(a,n): return from_jacobian(jacobian_multiply(to_jacobian(a),int(n)))
def add(a,b): return from_jacobian(jacobian_add(to_jacobian(a),to_jacobian(b)))
class Point:
    def __init__(self,x,y): self.point=(int(x),int(y))
    def __add__(self,o): return Point(*add(self.point,o.point))
    def __mul__(self,n): return Point(*multiply(self.point,int(n)))
    __rmul__=__mul__
    def __neg__(self): return Point(self.point[0],-self.point[1])
    def __eq__(self,o): return (self+(-o)).point[0]==0
    def __repr__(self): return str(self.point)
G=Point(*G_LIB)
def sum_pts(points):
    r=0*G
    for p in points:r=r+p
    return r
def eval_comms(c,i):
    return sum_pts([c[k]*pow(i,k,N) for k in range(7)])
def sha_args(*args): return int.from_bytes(sha256(str(args).encode()).digest(),'big')
def sqrt_p(x):
    r=pow(int(x)%FIELD,(FIELD+1)//4,FIELD)
    return r if r*r%FIELD==x%FIELD else None

def req(base,path,fields=None):
    data=urllib.parse.urlencode(fields or {}).encode() if fields is not None else None
    r=urllib.request.Request(base+path,data=data,headers={'Content-Type':'application/x-www-form-urlencoded'} if data else {})
    return json.load(urllib.request.urlopen(r,timeout=8))
class Tunnel:
    def __init__(self,host,port,name):
        self.base=f'http://{host}:{port}';self.name=name;self.sid=req(self.base,f'/svc/{name}/new',{})['sid']
    def send(self,b):
        ans=req(self.base,f'/svc/{self.name}/send',{'sid':self.sid,'data':base64.b64encode(b).decode()})
        if not ans.get('ok'): raise RuntimeError('send failed')
    def recv(self): return base64.b64decode(req(self.base,f'/svc/{self.name}/recv',{'sid':self.sid})['data'])
    def until(self,marker,timeout=8):
        buf=bytearray();end=time.monotonic()+timeout
        while time.monotonic()<end:
            b=self.recv()
            if b:buf.extend(b)
            if marker in buf:return bytes(buf)
            if not b:time.sleep(.03)
        raise TimeoutError(f'marker not seen: {marker!r}; tail={bytes(buf[-240:])!r}')
    def until_flag_or_prompt(self,timeout=5):
        buf=bytearray();end=time.monotonic()+timeout;flag_re=re.compile(rb'(?i)(?:flag|FLAG)\{[^}\r\n]+\}')
        prompt=b'Provide your nonces (D_i, E_i) for this round.'
        while time.monotonic()<end:
            b=self.recv()
            if b:buf.extend(b)
            if flag_re.search(buf) or prompt in buf or b'Invalid notary token' in buf or b'Invalid input' in buf or b'commitments invalid' in buf:return bytes(buf)
            if not b:time.sleep(.03)
        return bytes(buf)
    def close(self):
        try:req(self.base,f'/svc/{self.name}/close',{'sid':self.sid})
        except Exception:pass

def notarize(host,port):
    t=Tunnel(host,port,'legacy')
    try:
        t.until(b'Choice: ')
        block=b'A'*15+b'\x01'
        t.send(b'2\n'+block.hex().encode()+b'\n');out=t.until(b'Choice: ')
        tag1=bytes.fromhex(re.findall(rb'Tag: ([0-9a-fA-F]+)',out)[-1].decode())
        t.send(b'2\n'+block[:-1].hex().encode()+b'\n');out=t.until(b'Choice: ')
        tag2=bytes.fromhex(re.findall(rb'Tag: ([0-9a-fA-F]+)',out)[-1].decode())
        state=tag1+tag2
        forged=block+bytes(a^b for a,b in zip(state,block))
        t.send(b'3\n'+forged.hex().encode()+b'\n'+tag1.hex().encode()+b'\n')
        out=t.until(b'Notary token: ',timeout=4)
        m=re.search(rb'Notary token: ([^\r\n]+)',out)
        if not m:
            out+=t.until(b'\n',timeout=2)
            m=re.search(rb'Notary token: ([^\r\n]+)',out)
        if not m: raise RuntimeError('notary token missing')
        return m.group(1).decode().strip()
    finally:t.close()

def commitments_from(out):
    ctx=re.search(rb'context string ([0-9a-f]+)',out).group(1).decode()
    cs={i:[None]*7 for i in range(1,9)}
    for a,b,x,y in re.findall(rb'C_(\d+),(\d+) = \((\d+),\s*(\d+)\)',out):cs[int(a)][int(b)]=Point(int(x),int(y))
    if any(any(p is None for p in arr) for arr in cs.values()):raise RuntimeError('commitment parse incomplete')
    return ctx,cs

def choose_bad_inputs(context,cs):
    p0=sum_pts([cs[i][0] for i in range(1,9)])
    root=sqrt_p(p0.point[0])
    if root is None:return None
    c0=None
    for lam in (root,(-root)%FIELD):
        y=(p0.point[1]-lam*p0.point[0])%FIELD
        if y and (p0+Point(0,y)).point[0]==0:c0=Point(0,y);break
    if c0 is None:return None
    own=[c0]+[Point(0,1) for _ in range(6)]
    if any(eval_comms(own,i).point[0]!=0 for i in range(1,10)):return None
    # Fake proof: both points stay at x=0, so the broken x-only equality accepts it.
    R=Point(0,1);mu=0
    c=sha_args(bytes.fromhex(context),9,c0,R)
    if not (R == (mu*G)+(-(c*c0))):return None
    q=sum_pts([eval_comms(cs[i],9) for i in range(1,9)]+[eval_comms(own,9)])
    sq=sqrt_p(q.point[0])
    if sq is None:return None
    U=None
    for lam in (sq,(-sq)%FIELD):
        y=(-q.point[1]-lam*q.point[0])%FIELD
        if y and Point(0,y)==q:U=Point(0,y);break
    if U is None:return None
    k=p0+c0
    if k.point[0]!=0:return None
    return own,R,mu,U

def solve_one(host,port,token):
    last='no valid degenerate point setup after retries'
    for attempt in range(1,9):
        t=Tunnel(host,port,'cosign')
        try:
            t.until(b'Notary token: ')
            t.send(token.encode()+b'\n')
            out=t.until(b'Now, provide the commitments',timeout=12)
            context,cs=commitments_from(out)
            bad=choose_bad_inputs(context,cs)
            if bad is None:
                t.close();continue
            own,R,mu,U=bad
            payload=b''.join(f'{p.point[0]}\n{p.point[1]}\n'.encode() for p in own)+f'{R.point[0]}\n{R.point[1]}\n{mu}\n'.encode()
            t.send(payload)
            t.until(b'Send share for party 1:',timeout=8)
            t.send(b'0\n'*9)
            t.until(b'Provide your public verification share',timeout=8)
            t.send(f'{U.point[0]}\n{U.point[1]}\n'.encode())
            t.until(b'Provide your nonces (D_i, E_i) for this round.',timeout=8)
            for rnd in range(100):
                t.send(b'0\n1\n0\n1\n')
                t.until(b'Provide your signature share',timeout=8)
                t.send(b'0\n')
                out=t.until_flag_or_prompt(timeout=5)
                m=re.search(rb'(?i)(?:flag|FLAG)\{[^}\r\n]+\}',out)
                if m:return m.group(0).decode(),f'attempt={attempt},round={rnd+1}'
                if b'Invalid' in out or b'[-]' in out:return None,'server rejected crafted session: '+out[-180:].decode(errors='replace')
                if b'Provide your nonces (D_i, E_i) for this round.' not in out:
                    return None,'signing session stopped: '+out[-180:].decode(errors='replace')
            last='100 signing rounds exhausted'
        except Exception as e:last=f'{type(e).__name__}: {e}'
        finally:t.close()
    return None,last

def run(host,port):
    token=notarize(host,port)
    print('NOTARY_TOKEN_FORGED',flush=True)
    flag,info=solve_one(host,port,token)
    return flag,info
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Single-target IBOH ok, noted. challenge PoC")
    parser.add_argument("host", help="one in-scope target IP or hostname")
    parser.add_argument("--port", type=int, default=20561)
    args = parser.parse_args()
    flag, info = run(args.host, args.port)
    if flag:
        print("CAPTURED_FLAG=" + flag)
        print("DETAILS=" + info)
    else:
        print("RESULT=none")
        print("DETAILS=" + info)
