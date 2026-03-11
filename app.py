from datetime import datetime
def charger_logs(chemin_fichier):
    liste = []
    with open(chemin_fichier , "r") as fichier:
        for ligne in fichier:
            connexion = {}
            ligne = ligne.strip()
            tab = ligne.split(" ")
            chaineDate = "2026-"+tab[0]+"-"+tab[1]+" "+tab[2]
            connexion['date']=datetime.strptime(chaineDate,"%Y-%b-%d %H:%M:%S")
            connexion['pid'] = tab[4].split("[")[1].split("]")[0]
            if "password" in ligne.split("]: ")[1].split() : #il y a une ip
                connexion['ip'] = ligne.split()[10]
                if ligne.split()[5] == "Failed" :
                    connexion['statut'] = "echec"
                else:
                    connexion['statut'] = "succes"
            else:
                connexion['statut'] = "info"
            connexion['message'] = ligne.split("]: ")[1]
            liste.append( connexion )
    return liste

def extraire_attaquant(liste_logs):
    # Analyse la liste et retourne l'adresse IP ayant le plus grand 
    # nombre de 'Failed password', ainsi que son nombre d'échecs.
    dico = {}
    for log in liste_logs :
        if log['statut'] == "echec" :
            ip = log['ip']
            if ip in dico.keys() :
                dico[ip] = dico[ip] + 1
            else :
                dico[ip] = 1
    max = 0
    worstIp = ""
    for badIp in dico.keys() :
        if dico[badIp] > max :
            max = dico[badIp]
            worstIp = badIp
    return worstIp , max
            
########################  MAIN    #########################
listeLogs = charger_logs("auth.log")

ip,nb =  extraire_attaquant(listeLogs)
print (ip,nb)
