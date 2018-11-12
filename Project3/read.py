def main(inputFile):
    #open file in the read mode
    file = open(inputFile, "r")

    #read the file content lines by lines
    #lines = file.readlines()
    lines = file.read()
    
    print(lines) 
   
   
    #close the file
    file.close()





if __name__ == "__main__":
    main("RSApub.pem")
