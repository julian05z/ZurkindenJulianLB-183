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

## Umsetzung von Mechanismen für die Authentifizierung und Autorisierung

Die Applikation wurde mit einer Zwei-Faktor-Authentifizierung ausgestattet, die es dem Benutzer ermöglicht, diese nach der Anmeldung zu aktivieren und somit zu verwenden.

Der Benutzer muss sich zuerst als Administrator einloggen. Anschließend kann die Zwei-Faktor-Authentifizierung unter "Enable 2FA" aktiviert werden.

<img width="783" alt="screen2authenti" src="https://github.com/julian05z/ZurkindenJulianLB-183/assets/89130623/4042ef56-cdcb-4e49-b2dc-c3bbb011569a">

Ein QR-Code wird generiert.

<img width="800" alt="qrcode" src="https://github.com/julian05z/ZurkindenJulianLB-183/assets/89130623/18d574ba-a9b6-4ec4-bad7-1b4c5a220967">

Diesen kann man nun mit der Google Authenticator App scannen. Wie man hier sieht, wird nun ein Code generiert, der sich alle 30 Sekunden ändert.

<img width="337" alt="screeenhandy" src="https://github.com/julian05z/ZurkindenJulianLB-183/assets/89130623/82c47512-6f1f-42c9-b9eb-34746a6264c4">

Wenn man sich nun das nächste Mal einloggen möchte, muss man sein normales Login verwenden und den gültigen Code der Authenticator-App.

<img width="1279" alt="ScreenAuthentifizierung" src="https://github.com/julian05z/ZurkindenJulianLB-183/assets/89130623/6e26ac8e-27dd-4feb-9098-19d6d5147ea9">




### Wichtige Code ausschnitte von der Implementierung:

``` csharp
public ActionResult<Auth2FADto> Enable2FA()
{
    var user = _context.Users.Find(_userService.GetUserId());
    if (user == null)
    {
        return NotFound(string.Format("User {0} not found", _userService.GetUsername()));
    }
    {
        var secretKey = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10);
        string userUniqueKey = user.Username + secretKey;
        string issuer = _configuration.GetSection("Jwt:Issuer").Value!;
        TwoFactorAuthenticator authenticator = new TwoFactorAuthenticator();
        SetupCode setupInfo = authenticator.GenerateSetupCode(issuer, user.Username, userUniqueKey, false, 3);

        user.SecretKey2FA = secretKey;
        _context.Update(user);
        _context.SaveChanges();

        Auth2FADto auth2FADto = new Auth2FADto();
        auth2FADto.QrCodeSetupImageUrl = setupInfo.QrCodeSetupImageUrl;

        return Ok(auth2FADto);
    }
}
```
Die Enable2FA-Methode im Code aktiviert die Zwei-Faktor-Authentifizierung für einen Benutzer, indem sie einen neuen geheimen Schlüssel generiert und einen QR-Code für die Authentifizierungs-App erstellt.

``` csharp
if (user.SecretKey2FA != null)
{
    string secretKey = user.SecretKey2FA;
    string userUniqueKey = user.Username + secretKey;
    TwoFactorAuthenticator authenticator = new TwoFactorAuthenticator();
    bool isAuthenticated = authenticator.ValidateTwoFactorPIN(userUniqueKey, request.UserKey);
    if (!isAuthenticated)
    {
        return Unauthorized("login failed");
    }
}

return Ok(CreateToken(user));
```

In diesem Codeabschnitt wird überprüft, ob der Benutzer die Zwei-Faktor-Authentifizierung (2FA) aktiviert hat. Falls ja, wird der eingegebene 2FA-Schlüssel (UserKey) validiert.

## Autorisierung

``` csharp

if (!_userService.IsAdmin() && _userService.GetUserId() != news.AuthorId)
{
    return Forbid();
}

```
Der Codeabschnitt zeigt die Autorisierung in einer Applikation. Es überprüft, ob der aktuelle Benutzer die erforderlichen Berechtigungen hat, um eine bestimmte Aktion durchzuführen. In diesem Fall wird überprüft, ob der Benutzer entweder ein Administrator ist oder der ursprüngliche Autor des News-Eintrags, den er aktualisieren möchte. Wenn diese Bedingungen nicht erfüllt sind, wird ein Forbidden-Status zurückgegeben, was bedeutet, dass der Zugriff verweigert wird.


# HZ 4

## Sicherheitsrelevante Aspekte bei Entwurf, Implementierung und Inbetriebnahme berücksichtigen.

Menschen neigen dazu, Fehler zu machen. Unachtsamkeit, Unwissenheit oder Nachlässigkeit können zu Sicherheitslücken führen. Beispiele sind das Verwenden schwacher Passwörter, das Öffnen von Phishing-E-Mails oder das Vernachlässigen von Sicherheitsrichtlinien. In meinem Fall habe ich mich auf schwache Passwörter fokussiert. Dabei habe ich eine Funktion in meiner Applikation, die bestimmte Voraussetzungen verlangt, um ein neues Passwort zu erstellen.

### Codeausschnitt:

``` csharp

private string validateNewPasswort(string newPassword)
{
    // Check small letter.
    string patternSmall = "[a-zäöü]";
    Regex regexSmall = new Regex(patternSmall);
    bool hasSmallLetter = regexSmall.Match(newPassword).Success;

    string patternCapital = "[A-ZÄÖÜ]";
    Regex regexCapital = new Regex(patternCapital);
    bool hasCapitalLetter = regexCapital.Match(newPassword).Success;

    string patternNumber = "[0-9]";
    Regex regexNumber = new Regex(patternNumber);
    bool hasNumber = regexNumber.Match(newPassword).Success;

    List<string> result = new List<string>();
    if (!hasSmallLetter)
    {
        result.Add("keinen Kleinbuchstaben");
    }
    if (!hasCapitalLetter)
    {
        result.Add("keinen Grossbuchstaben");
    }
    if (!hasNumber)
    {
        result.Add("keine Zahl");
    }

    if (result.Count > 0)
    {
        return "Das Passwort beinhaltet " + string.Join(", ", result);
    }
    return "";
}

```
### Ansicht im Programm:



![screeenHZ4](https://github.com/julian05z/ZurkindenJulianLB-183/assets/89130623/f498abb2-9c52-4c09-8042-da6e3679d2cb)
