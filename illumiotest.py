
import random, struct, socket, csv, illumio

class Test(object):
  def __init__(self):
    self.rules='illumioTest.csv'
    self.acceptrules='illumioTestACCEPT.csv'

  def create_test(self):
    print('Creating TestFile')
    ran=100
    dirs=['outbound','inbound']
    protocols=['tcp','udp']
    file1=open(self.rules, "w", newline='')
    file2=open(self.acceptrules, "w", newline='')
    writer1 = csv.writer(file1, delimiter=',')
    writer2 = csv.writer(file2, delimiter=',')
    for i in range(ran):
      dirr=random.choice(dirs)
      prot=random.choice(protocols)
      x=random.randrange(0,4294967296)
      y=random.randrange(0,4294967296)
      z=x
      if i%1000==0:
        y=x
      if x!=y:
        z=random.randrange(min(x,y),max(x,y))
      addresses=socket.inet_ntoa(struct.pack('!L', min(x,y)))+"-"+socket.inet_ntoa(struct.pack('!L', max(x,y)))
      acceptaddress=socket.inet_ntoa(struct.pack('!L', z))
      x=random.randrange(1,65536)
      y=random.randrange(1,65536)
      z=x
      if i%1000==0:
        y=x
      if y!=x:
        z=random.randrange(min(x,y),max(x,y))
      ports=str(min(x,y))+"-"+(str(max(x,y)))
      acceptport=str(z)
      writer1.writerow([dirr,prot,ports,addresses])
      writer2.writerow([dirr,prot,acceptport,acceptaddress])
    file1.close()
    file2.close()

  def perform_test(self):
    print('Performing Test')
    print("Initializing Firewall")
    firewall=illumio.Firewall(self.rules)
    fi=open(self.acceptrules, "r")
    readCSV = csv.reader(fi, delimiter=',')
    fl=0
    for row in readCSV:
      if firewall.accept_packet(row[0],row[1],row[2],row[3])==False:
        print("NO. Doesnt work at " + row)
        fl=1
      break
    if fl==0:
      print('Firewall works!!')

def main():
    t=Test()   
    t.create_test()
    t.perform_test()

if __name__ == '__main__':
    main()