with open("enc_func.py","r") as f:
    contents = f.read()
    contents = contents.split("\n")

output = []
for line in contents:
    if "def" in line:
        line = line.replace("X","result")
        line = line.replace("enc","rev")

    if "=[0]*16" in line:
        i = 0
        output.append("    s = Solver()")
        output.append("    a = bitvec_arr()")
        output.append("")
        continue

    if "v[" in line:
        a = line.index("(")
        b = line.index(")")
        line = line.replace("X","a")

        line = "    s.add" + line[a:b] + " == result[" + str(i) + "])" 
        i += 1

    if "return" in line:
        output.append("    s.check()")
        output.append("    return model2arr(s.model(),a)")
        continue

    output.append(line)


with open("rev_func.py","w") as f:
    for line in output:
        f.write(line)
        f.write("\n")
