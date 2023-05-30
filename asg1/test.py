#open a file and return a list of lines
def read_file(filename):
    with open(filename) as f:
        return f.readlines()

def decode(stri):
    # convert string to byte array
    string = bytes(stri, 'ascii')
    res = "".join([chr(x ^ 0x4d) for x in string])
    print (stri, "=> ", res)

    #  each letter in the line with the key 0x4d to get the decoded line and return it



#main function
def main():
    #get the filename from the user
    filename = "strs.txt"
    #call the read_file function
    lines = read_file(filename)
    #print the lines
    for line in lines:
        decode(line.strip())

#entry point function
if __name__ == "__main__":
    main()
