# ZurkindenJulianLB-183

# HZ 1

## Aktuelle Bedrohungen in der Cybersicherheit:

In der heutigen zunehmend vernetzten Welt sind Unternehmen und individuelle Benutzer einer ständig wachsenden Vielzahl von Cybersicherheitsbedrohungen ausgesetzt. Im Rahmen meiner Recherche zu aktuellen Gefahren habe ich mich intensiv mit verschiedenen Aspekten der Cybersicherheit auseinandergesetzt.

### 1. Recherche:

In meiner Recherche habe ich viele Infos zu den aktuellen Gefahren in der Cybersicherheit gesammelt. Das beinhaltet Sachen wie Malware (schädliche Software), Phishing (Betrugsversuche), Ransomware (Erpressungssoftware) und DDoS-Angriffe (Überlastungsangriffe). Dafür habe ich aktuelle Studien, Sicherheitsberichte und Fachartikel studiert, um gut zu verstehen, was für Bedrohungen das sind und wie groß das Problem ist.

### 2. Analyse:

Ich habe genau untersucht, wie sich diese Bedrohungen auf verschiedene Arten von Computern und Netzwerken auswirken. Dabei ist mir aufgefallen, dass Malware die wichtigen Dateien auf einem System gefährdet, Phishing die Geheimhaltung von Benutzerinformationen stört, Ransomware zu finanziellen Verlusten führen kann und DDoS-Angriffe die Verfügbarkeit von Online-Diensten beeinträchtigen können. Diese Erkenntnisse haben mir gezeigt, wie wichtig es ist, rasch geeignete Sicherheitsmaßnahmen zu ergreifen.

### 3. Gegenmaßnahmen:

In meiner Analyse habe ich verschiedene Möglichkeiten besprochen, wie Organisationen und Einzelpersonen sich vor den genannten Gefahren schützen können. Diese Maßnahmen umfassen:

- **Code-Reviews:** Regelmäßige Überprüfung des Programmiercodes durch Teammitglieder, um potenzielle Schwachstellen und Sicherheitslücken zu identifizieren.

- **Sichere Programmierpraktiken:** Einhaltung bewährter Methoden beim Schreiben von Code, um Sicherheitsrisiken zu minimieren. Dazu gehören das Validieren von Benutzereingaben, die Verwendung sicherer Bibliotheken und das Prinzip des "Least Privilege".

- **Automatisierte Tests:** Implementierung von automatisierten Tests, um sicherzustellen, dass Änderungen im Code die Sicherheits- und Funktionsintegrität nicht beeinträchtigen.

- **Regelmäßige Software-Updates:** Aktualisierung von Entwicklungsumgebungen, Frameworks und Bibliotheken, um von den neuesten Sicherheitspatches zu profitieren.

- **Sicherheitsbewusstsein:** Schulungen für Entwickler, um das Bewusstsein für aktuelle Bedrohungen zu schärfen und sicherheitsrelevante Praktiken zu fördern.

Diese Erkenntnisse sollen als Grundlage dienen, um eine umfassende Sicherheitsstrategie für die Programmierung und Entwicklung zu entwickeln. Das Ziel ist es, die Integrität von Codes, die Vertraulichkeit von Daten und die Verfügbarkeit von Anwendungen sicherzustellen.


# HZ 2

## Sicherheitslücken und ihre Ursachen in einer Applikation erkennen können. Gegenmassnahmen vorschlagen und implementieren können.

Ich habe mich in meinem fall auf sicherheits lücken beim Login/Authentifirzierung fokussiert und welche lücken sich im Programm auffinden. 

![grafik](https://github.com/julian05z/ZurkindenJulianLB-183/assets/89130623/6d864f0d-82d3-4122-a5ef-3742d108b3fe)

Die Sicherheitslücke in diesem Code liegt in der Art und Weise, wie die SQL-Abfrage zusammengesetzt wird. Hier wird die string.Format-Methode verwendet, um die Benutzereingaben direkt in die SQL-Abfrage einzufügen.

``` csharp
string sql = string.Format("SELECT * FROM Users WHERE username = '{0}' AND password = '{1}'", 
    request.Username, 
    MD5Helper.ComputeMD5Hash(request.Password));
```
Das Problem dabei ist, dass diese Vorgehensweise anfällig für SQL-Injections ist. Ein Angreifer könnte speziell gestaltete Benutzereingaben verwenden, um die SQL-Abfrage zu manipulieren und unerwünschte Aktionen auszuführen.

Angenommen, ein Angreifer gibt im Benutzernamenfeld den Wert ' OR '1'='1' -- ein. Die SQL-Abfrage würde dann wie folgt aussehen:

``` sql
  SELECT * FROM Users WHERE username = '' OR '1'='1' --' AND password = '...'
```
Durch die Verwendung der Bedingung '1'='1' wird die Abfrage immer wahr sein, was dazu führt, dass alle Benutzerdaten zurückgegeben werden, anstatt nur den richtigen Benutzer zu authentifizieren. Dies ermöglicht einem Angreifer den Zugriff auf das System, ohne das korrekte Passwort zu kennen.

### Beispiel an der Applikation:

![video](https://github.com/julian05z/ZurkindenJulianLB-183/assets/89130623/cb4df52f-faee-4c14-9712-f4988e357617.gif)

Um die Sicherheitslücke zu beheben, sollte man Parameter verwenden, anstatt die Benutzereingaben direkt in die SQL-Abfrage einzufügen.

``` csharp
string sql = "SELECT * FROM Users WHERE username = @Username AND password = @Password";

var usernameParam = new SqlParameter("@Username", request.Username);
var passwordParam = new SqlParameter("@Password", MD5Helper.ComputeMD5Hash(request.Password));

User? user = _context.Users.FromSqlRaw(sql, usernameParam, passwordParam).FirstOrDefault();
```
Nach dem schliessen dieser Sicherheitslücke:



![video](https://github.com/julian05z/ZurkindenJulianLB-183/assets/89130623/4d9f644d-1c29-499e-94a0-311880076ca9.gif)


# HZ 3

## Mechanismen für die Authentifizierung und Autorisierung umsetzen 

Der BEnutzer muss sich zuerst als zb Admin einloggen. Anschliesend kann man unter Enable 2Fa die 2FA aktivieren. Ein QR code wird generiert. Diesen kann man nun mit der Google Authenticator app scannen.


<img width="783" alt="screen2authenti" src="https://github.com/julian05z/ZurkindenJulianLB-183/assets/89130623/4042ef56-cdcb-4e49-b2dc-c3bbb011569a">
<img width="1279" alt="ScreenAuthentifizierung" src="https://github.com/julian05z/ZurkindenJulianLB-183/assets/89130623/6e26ac8e-27dd-4feb-9098-19d6d5147ea9">


<img width="800" alt="qrcode" src="https://github.com/julian05z/ZurkindenJulianLB-183/assets/89130623/18d574ba-a9b6-4ec4-bad7-1b4c5a220967">
![Beschreibung des Bildes](https://github.com/julian05z/ZurkindenJulianLB-183/raw/main/assets/89130623/18d574ba-a9b6-4ec4-bad7-1b4c5a220967.png)
