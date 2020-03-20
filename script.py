import os
import csv
import sys

#print("leggo la prima quintupla\n")

#vettore per saltare le linee di intestazione di gt.tie
dodici = range(1,12)
#leggo una linea e divido gli elementi in elementi di un vettore
line = []
#insieme dei package trovati
packages = []
#nomi delle colonne
col_names_temp = []
col_names = []
rows = []
npackage = 0
nbiflussi = 0
nUDP = 0
nTCP = 0
nPTCP = 0
nPUDP = 0
nSSL = 0
nHTTP = 0

n_arg, nome = sys.argv
extTie = ".tie"
nomefile = nome+extTie

#genero il file per le query DNS
#considero solo i campi ip e nome host
os.system("tshark -r traffic.pcap -T fields -e dns.a -e dns.qry.name -Y\"(dns.flags.response == 1)\" > trafficpcap.txt")
#genero il file per il campo SSL
os.system("tshark -r traffic.pcap -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e ssl.handshake.extensions_server_name -Y ssl.handshake.extensions_server_name > ssl.txt")
#genero il comando per il campo http
os.system("tshark -r traffic.pcap -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e http.host -Y http.host > http.txt")

#leggo dal file gt.tie
with open(nomefile,newline = "") as filecsv:
    lettore = csv.reader(filecsv,delimiter="\t")
    for count in dodici: header = next(lettore) #elimino le righe di intestazione
    n_col = 0
    for elem in header:
        col_names_temp.append(elem)
        n_col = n_col + 1 #conto il numero di colonne
    index = 0
    while index < n_col:
        if(col_names_temp[index]!=""): col_names.append(col_names_temp[index]) #correggo la sbagliata indentazione del file .tie che genera colonne vuote
        index = index + 1
    print("i nomi delle colonne sono: ",col_names)
    #aggiungo i campi alla prima riga, le nuove colonne
    col_names.append("package")
    col_names.append("DNS")
    col_names.append("dig")
    col_names.append("whois")
    col_names.append("SNI_TLS")
    col_names.append("HTTP")
    #la prima riga sono i nomi delle colonne
    rows.append(col_names)
    for riga in lettore:
        print("riga: ",riga)
        #assegno il vettore linea
        line = riga
        #leggo i campi dal file
        if(line[0] == "# end of text table"): break
        else:
            nbiflussi = nbiflussi + 1
            id_tie = line[0]
            ipsrc = line[1]
            ipdst = line[2]
            proto = line[3]
            psrc = line[4]
            pdst = line[5]
            dwpkts = line[6]
            uppakts = line[7]
            dwbytes = line[8]
            upbytes = line[9]
            t_start = line[10]
            t_last = line[11]
            app_id = line[12]
            sub_id = line[13]
            app_details = line[14]
            conficence = line[15]
        #converto il protocollo da codice a testo
        if(proto == "6"):
            protoC = "TCP"
            nTCP = nTCP + 1
        elif(proto == "17"):
            protoC = "UDP"
            nUDP = nUDP + 1

        #creo una riga
        row = []
        n_col = 0
        while n_col < 16:
            row.append(line[n_col])
            n_col = n_col + 1

        
        #creo una serie di file output per filtrare dallo strace.log prima indirizzo e porto destinazione
        #poi indirizzo e porto sorgente e poi protocollo

        if(protoC == "TCP"):

            #creo il primo output
            cmd = "grep -i "+ ipsrc + ":" + psrc + " strace.log > src.txt"
            print("eseguo il comando ",cmd)
            os.system(cmd)
            print("comando eseguito")

            #secondo
            cmd = "grep -i "+ ipdst + ":"+ pdst + " src.txt > dst.txt"
            print("eseguo il comando ",cmd)
            os.system(cmd)
            print("comando eseguito")

            #terzo
            cmd = "grep -i "+ protoC + " dst.txt > proto.txt"
            print("eseguo il comando ",cmd)
            os.system(cmd)
            print("comando eseguito")

        elif(protoC == "UDP"):
            ip = ""
            if(ipdst.startswith("192.168")):
                ip = ipsrc
            elif(ipsrc.startswith("192.168")):
                ip = ipdst

            #creo un comando per leggere il package delle socket UDP
            cmdUDP = ""
            cmdUDP = "grep -i UDP strace.log | grep -i " + ip + " > proto.txt" 
            print("eseguo comando ",cmdUDP)
            os.system(cmdUDP)
            print("comando eseguito")

        #leggo dall'ultimo file la prima parola che corrisponde al package

        packfile = open("./proto.txt", "r")
        linep = packfile.readline()
        print("linea letta dal package ",linep)
        packfile.close()
        index = 0 
        package = ""
        #conto il numero di socket UDP e TCP
        if(protoC == "TCP" and len(linep) > 0):
            nPTCP = nPTCP + 1
        elif(protoC == "UDP" and len(linep) > 0):
            nPUDP = nPUDP +1
        while index < len(linep):
            if(linep[index] !=" "):
                package = package + linep[index]
                index = index + 1
            else: break

        print("trovato per la quintupla ",ipsrc,psrc,ipdst,pdst,protoC, "il package ",package)

        line.append(package)

        
        print("linea completa di package:\n",line)
        
        #creo un vettore di package

        if(package != ""):
            packages.append(package)
            row.append(package)
            npackage = npackage + 1
        else:
            packages.append("package non trovato!")
            row.append("N/C")

        #ricerca in traffic.pcap del DNS
        #apro il file trafficpcap.txt
        with open("trafficpcap.txt",newline = "") as filedns:
            readerpcap = csv.reader(filedns,delimiter = "\t")
            rowDns = []
            for rowdns in readerpcap:
                rowDns = rowdns 
                print("linea letta: ",rowDns)
                #leggo gli indirizzi ip della risposta DNS, considero solo il primo IP
                if(ipdst.startswith("192.168")):
                    ip = ipsrc
                elif(ipsrc.startswith("192.168")):
                    ip = ipdst
                if(rowDns[0].find(ip) != -1):
                    i = 0
                    ipdns = ""
                    rowd = rowDns[0]
                    while i < len(rowDns[0]):
                        if(rowd[i] != ","):
                            ipdns = ipdns + rowd[i]
                            i = i + 1
                        else: break

                    row.append(rowDns[1])
                    print("nome dominio aggiunto : ", rowDns[1])
                    cmd1 = "dig +short @8.8.8.8 -x " + ipdns + " > dig.txt"
                    os.system(cmd1)
                    print("comando eseguito: ",cmd1)
                    f = open("dig.txt","r")
                    digline = f.readline()
                    f.close()
                    diglen = len(digline)
                    dig = digline[:(diglen-2)] #leggo la stringa eccetto gli ultimi 2 caratteri
                    if(dig != ""):
                        row.append(dig)
                        print("letto da dig.txt: ",dig)
                    else: row.append("Non Trovato!")
                    cmd2 = "whois " + ipdns + " | grep -i orgname > whois.txt"
                    os.system(cmd2)
                    f2 = open("whois.txt","r")
                    whoisline = f2.readline()
                    index = 16 #OrgName: + 8 spazi
                    whois = ""
                    if(whoisline != ""):
                        while index < len(whoisline):
                            if(whoisline[index] != "\n"): whois = whois + whoisline[index]
                            index = index + 1
                        print("whois: ",whois)
                        f2.close()
                        row.append(whois)
                    else: row.append("Non Trovato!")

                    break

             #ssl_handshake
        filessl = open("ssl.txt","r")
        ssl = filessl.readlines()
        added = False
        for line in ssl:
            linessl = line.split("\t")
            if(linessl[0] == ipsrc and linessl[1] == psrc and linessl[2] == ipdst and linessl[3] == pdst):
                ssline = linessl[4][0:len(linessl[4])-1] #rimuovo l'ultimo carattere che danneggia la formattazione
                row.append(ssline)
                added = True
                nSSL = nSSL + 1
                print("trovato SSL handshake : ",ssline)

        if(added == False):
            row.append("Non Trovato!")


        filessl.close()


                #http

        filehttp = open("http.txt","r")
        httplines = filehttp.readlines()
        for line in httplines:
            http = line.split("\t")
            if(http[0] == ipsrc and http[1] == psrc and http[2] == ipdst and http[3] == pdst):
                nHTTP = nHTTP + 1
                #correzione output
                http[4] = http[4][0:len(http[4])-1]
                row.append(http[4])
                print("trovato HTTP: ",http[4])
        filehttp.close()

        
        filedns.close()
        
        #aggiungo una riga al file virtuale
        rows.append(row)

filecsv.close()

print("ecco la lista di package:\n\n")

trovati = 0
nonTrovati = 0
i = 0
#stampo a video i package trovati e conto il numero di classificati e non classificati
while i < len(packages):
    print(packages[i],"\n")
    if(packages[i] == "package non trovato!"): nonTrovati = nonTrovati + 1
    else: trovati = trovati + 1
    i = i + 1

print("su ",nbiflussi, " biflussi i package letti sono stati ",npackage," di cui quelli non trovati sono ", nonTrovati, " mentre i package trovati sono ", trovati,"\n")

print("le socket TCP aperte sono state ",nPTCP," su ",nTCP," biflussi TCP")

print("le socket UDP aperte sono state ",nPUDP, " su ",nUDP," biflussi UDP")

print("sono stati trovati ", nSSL, " ssl handshake")

print("sono stati trovati ", nHTTP, " pacchetti HTTP")

print("lettura completata... scrivo su file")

#inizio la scrittura su file

extGtTie = ".gt.tie"
nomefileout = nome + extGtTie

with open(nomefileout, 'w') as filecsvw:
    writer = csv.writer(filecsvw, delimiter="\t")
    i = 0
    while i < len(rows):
        writer.writerow(rows[i])
        i = i + 1

filecsvw.close()

#rimozione file temporanei

os.system("rm proto.txt")
os.system("rm src.txt")
os.system("rm dst.txt")
os.system("rm dig.txt")
os.system("rm trafficpcap.txt")
os.system("rm whois.txt")
os.system("rm ssl.txt")
os.system("rm http.txt")

print("file ",nomefileout,"  generato e file temporanei rimossi!")
