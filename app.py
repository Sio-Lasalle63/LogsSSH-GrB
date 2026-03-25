from datetime import datetime
from flask import Flask, request, render_template, redirect, session, g

app = Flask(__name__)
app.secret_key = "monsupersecretintrouvable"     

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

def lister_utilisateurs(lLog):
    listeUsername = []
    for connexion in lLog :
        if " password for " in connexion["message"] :
            username =  connexion["message"].split( " password for ")[1].split(" from ")[0]
            if username not in listeUsername :
                listeUsername.append(username)
    return listeUsername

# -----------------------------
# Home
# -----------------------------
@app.route("/")
def home():
    tabDico = charger_logs("auth.log")
    listeUsers = lister_utilisateurs( tabDico)
    return render_template("index.html", nbLogs = len(tabDico) , users = listeUsers , tabDico = tabDico)
    
#############   MAIN ######################

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

