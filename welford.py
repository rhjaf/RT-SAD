import math

class Welford:
  def __init__(self):
    self.m_n = 0
  def clear(self):
    self.m_n = 0  
  def push(self,x):
    self.m_n+=1;
    if self.m_n==1:
      self.m_oldM = self.m_newM = x;
      self.m_oldS = 0.0
    else:
      self.m_newM = self.m_oldM + (x - self.m_oldM) / self.m_n;
      self.m_newS = self.m_oldS + (x - self.m_oldM) * (x - self.m_newM)
      # next iteration
      self.m_oldM = self.m_newM
      self.m_oldS = self.m_newS
  def numDataValue(self):
    return self.m_n
  def mean(self):
    if self.m_n>0:
      return self.m_newM
    else:
      return 0.0
  def variance(self):
    if self.m_n>1:
      return self.m_newS / (self.m_n -1)
    else:
      return 0.0
  def standardDeviation(self):
    return math.sqrt(self.variance())
  '''
        int m_n;
        double m_oldM, m_newM, m_oldS, m_newS;
  '''
  
w=Welford()
w.push(17.0)
w.push(19.0)
w.push(24.0)
print(w.mean())
print(w.variance())
print(w.standardDeviation())
                                              