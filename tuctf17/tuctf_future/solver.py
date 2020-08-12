from z3 import *
inp = []

#Creating our input
for i in range(0,25):
    b = BitVec("%s" % i, 8)
    inp.append(b)
print(inp)
# Generate Matrix
mat = [[0 for x in range(0,5)] for y in range(0,5)]
for i in range(0,25):
    m = (i*2)%25
    f = (i*7)%25
    mat[int(m/5)][m%5] = inp[f]
print(mat)
auth = [0 for x in range(19)]
auth[0] = mat[0][0] + mat[4][4];
auth[1] = mat[2][1] + mat[0][2];
auth[2] = mat[4][2] + mat[4][1];
auth[3] = mat[1][3] + mat[3][1];
auth[4] = mat[3][4] + mat[1][2];
auth[5] = mat[1][0] + mat[2][3];
auth[6] = mat[2][4] + mat[2][0];
auth[7] = mat[3][3] + mat[3][2] + mat[0][3];
auth[8] = mat[0][4] + mat[4][0] + mat[0][1];
auth[9] = mat[3][3] + mat[2][0];
auth[10] = mat[4][0] + mat[1][2];
auth[11] = mat[0][4] + mat[4][1];
auth[12] = mat[0][3] + mat[0][2];
auth[13] = mat[3][0] + mat[2][0];
auth[14] = mat[1][4] + mat[1][2];
auth[15] = mat[4][3] + mat[2][3];
auth[16] = mat[2][2] + mat[0][2];
auth[17] = mat[1][1] + mat[4][1];
auth[18] = 0x00
enc = [0x8b, 0xce, 0xb0, 0x89, 0x7b, 0xb0, 0xb0, 0xee, 0xbf, 0x92, 0x65, 0x9d, 0x9a, 0x99, 0x99, 0x94, 0xad, 0xe4, 0x0]
print(mat)
print(auth)
z = Solver()
for x in range(0,19):
    z.add(auth[x]==enc[x])
for x in range(0,25):
    z.add(inp[x] > 32)
    z.add(inp[x] < 127)
z.add(inp[0] == 84)
z.add(inp[1] == 85)
z.add(inp[2] == 67)
z.add(inp[3] == 84)
z.add(inp[4] == 70)
z.add(inp[5] == 123)
z.add(inp[24] == 125)
print(z.check())
solution = z.model()
flag = ""
for i in inp:
    flag += chr(int(str(solution[i])))
print("solution is: " + flag)
