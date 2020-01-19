# -*- coding: utf-8 -*-
import csv, struct, socket, sys

class Tree(object):
  def __init__(self, l, h):
      self.low=l
      self.high=h
      self.maxi=h
      self.height=1
      self.left=None
      self.right=None

class IntervalTree(object):
  def leftRotate(self,t):
    r =  t.right;
    t.right = r.left
    r.left=t
    t.height=max(self.height(t.left), self.height(t.right))+1
    r.height=max(self.height(r.left), self.height(r.right))+1
    t.maxi=t.high
    t.max=self.findMax(t)
    r.max=self.findMax(r)
    return r
  
  def rightRotate(self,t):
    ll =  t.left
    t.left = ll.right
    ll.right=t
    t.height=max(self.height(t.left), self.height(t.right))+1
    ll.height=max(self.height(ll.left), self.height(ll.right))+1
    t.maxi=t.high
    t.maxi=self.findMax(t)
    ll.maxi=self.findMax(ll)
    return ll

  def heightDiff(self,a):
    if a==None:
      return 0   
    return self.height(a.left)-self.height(a.right)
    
  def height(self,a):
    if a==None:
      return 0
    return a.height

  def findMax(self,n):
      if n.left==None and n.right==None:
          return n.maxi
      if n.left==None:
          if n.right.maxi > n.maxi:
              return n.right.maxi
          else:
              return n.maxi
      if n.right==None:
          if n.left.maxi > n.maxi:
              return n.left.maxi
          else:
              return n.maxi
      m=0
      if n.left.maxi<n.right.maxi:
          m=n.right.maxi
      else:
          m=n.left.maxi
      if n.maxi>m:
          m=n.maxi
      return m

  def insert(self,node, l, h):
    if node==None:
      return Tree(l, h)
    else:
        if node.low>l:
            node.left=self.insert(node.left, l, h)
        else:
            node.right=self.insert(node.right, l, h)    
        node.height=max(self.height(node.left), self.height(node.right))+1
        node.maxi=self.findMax(node)
        hd = self.heightDiff(node)
        if hd<-1:
            kk=self.heightDiff(node.right)
            if kk>0:
                node.right=self.rightRotate(node.right)
                return self.leftRotate(node)
            else:
                return self.leftRotate(node)
        elif hd>1:
            if self.heightDiff(node.left)<0:
                node.left = self.leftRotate(node.left)
                return self.rightRotate(node)
            else:
                return self.rightRotate(node)
    return node
    
  def isInside(self,node, l,h):
    if node.low<=l and node.high>=h:
        return True
    return False

  def intervalSearch(self,t,l,h):
    while(t!=None and self.isInside(t, l,h)==False):
      if t.left!=None and t.left.maxi>=l:
        t=t.left
      else:
        t=t.right
    return t

class Firewall(object):
  def __init__(self,fi):
    self.data={}
    self.addressTree=IntervalTree()
    with open(fi) as csvfile:
      readCSV = csv.reader(csvfile, delimiter=',')
      self.insert_all_rules(readCSV)
  
  def insert_all_rules(self,readCSV):
    for row in readCSV:
      direction=row[0]
      protocol=row[1]
      ports=[None]*2
      addresses=[None]*2
      if '-' in row[2]:
        ports[0]=int(row[2].split('-')[0])
        ports[1]=int(row[2].split('-')[1])
      else:
        ports[0]=int(row[2])
        ports[1]=int(row[2])
      if '-' in row[3]:
        addresses[0]=struct.unpack("!L", socket.inet_aton(row[3].split('-')[0]))[0]
        addresses[1]=struct.unpack("!L", socket.inet_aton(row[3].split('-')[1]))[0]
      else:
        addresses[0]=struct.unpack("!L", socket.inet_aton(row[3]))[0]
        addresses[1]=struct.unpack("!L", socket.inet_aton(row[3]))[0]
      self.insert_rule(direction,protocol,ports,addresses)

  def insert_rule(self,direction,protocol,ports,addresses):
    if direction not in self.data:
      self.data[direction]={}
    if protocol not in self.data[direction]:
      self.data[direction][protocol]=[None]*65536
    for i in range(ports[0],ports[1]+1):
      self.data[direction][protocol][i]=self.addressTree.insert(self.data[direction][protocol][i],addresses[0],addresses[1])

  def accept_packet(self,direction,protocol,port,address):
    port=int(port)
    address=struct.unpack("!L", socket.inet_aton(address))[0]
    if direction not in self.data:
      return False
    if protocol not in self.data[direction]:
      return False
    if self.data[direction][protocol][port]==None:
      return False
    if self.addressTree.intervalSearch(self.data[direction][protocol][port],address,address):
      return True
    return False

def main():
    if len(sys.argv)<=1:
      print("Incorrect Usage.")
    fi=sys.argv[1]
    print("Initializing Firewall object with "+str(fi))
    firewall=Firewall(fi)
    while(True):
      x=input("Enter Packet info (direction protocol ports addresses) : ") 
      dire,prot,por,add=x.split(" ")
      result=firewall.accept_packet(dire,prot,por,add)
      print(result)
      return result

if __name__ == '__main__':
    main()