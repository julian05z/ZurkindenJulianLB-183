# ZurkindenJulianLB-183

# HZ 1

## Aktuelle Bedrohungen in der Cybersicherheit:

In der heutigen zunehmend vernetzten Welt sind Unternehmen und individuelle Benutzer einer ständig wachsenden Vielzahl von Cybersicherheitsbedrohungen ausgesetzt. Im Rahmen meiner Recherche zu aktuellen Gefahren habe ich mich intensiv mit verschiedenen Aspekten der Cybersicherheit auseinandergesetzt.

### Ransomware

Ransomware, oder Erpressungstrojaner, bedroht die Sicherheit von Computern durch die Verschlüsselung von Dateien. Sie gelangt oft über unsichere Systeme und infizierte E-Mail-Anhänge in die Systeme.

#### Schutzmaßnahmen:
1. Sofortige Systemneuaufsetzung:* Im Falle einer Infektion sollte das betroffene System umgehend neu aufgesetzt werden, um die Ransomware zu entfernen.
2. Datenwiederherstellung aus Backups:* Wichtige Daten sollten aus zuverlässigen Backups wiederhergestellt werden, um den Verlust zu minimieren.
3. Fachkundige Unterstützung:* Bei mangelnden Fachkenntnissen ist die Hilfe von Experten oder spezialisierten Unternehmen erforderlich, um die Bedrohung wirksam zu bekämpfen.

### Gefälschte Drohmails von Behörden: Betrug erkennen und schützen

Gefälschte Drohmails von Behörden, auch als Fake Extortion E-Mails bekannt, täuschen vor, dass die angeschriebene Person schwerwiegende strafrechtliche Vergehen begangen habe. Die Anklage könne angeblich nur durch eine Geldzahlung fallengelassen werden.

**Vorgehensweise:**
Der Empfänger wird oft fälschlicherweise beschuldigt. Eine Frist wird gesetzt, um eine schriftliche Begründung per E-Mail einzureichen. Das Opfer wird zur Zahlung einer Kaution aufgefordert, um einer angeblichen Verhaftung zu entgehen. Die E-Mail täuscht durch offizielle Aufmachung vor, von Strafverfolgungsbehörden wie fedpol, Europol, Interpol oder einer kantonalen Polizei zu stammen. Absender und Dokumente sind jedoch gefälscht, und die Kommunikation erfolgt über private E-Mail-Adressen.

Schutzmaßnahmen:
1. Ignorieren Sie Fake-Extortion-E-Mails:* Lassen Sie sich nicht einschüchtern und reagieren Sie nicht auf unbegründete Forderungen.
2. Wenden Sie sich an die Polizei:* Bei Unsicherheit sollten Sie sich direkt an die Polizei wenden, um die Echtheit der erhaltenen Nachricht zu überprüfen.


### Betrügerische Jobangebote: Erkennen und Schützen

**Risiken:**
Meldungen zu betrügerischen Jobangeboten, die über Messaging-Dienste wie WhatsApp verbreitet werden. Angebliche Recruiting-Firmen locken mit unrealistischen Verdienstversprechen.

Schutzmaßnahmen:
1. Ignorieren Sie betrügerische Nachrichten:* Beachten Sie Nachrichten mit unrealistischen Stellenangeboten nicht.
2. Blockieren und Melden:* Nutzen Sie die in der Anwendung verfügbaren Funktionen zum Blockieren und Melden von betrügerischen Nachrichten.
3. Anzeige bei finanziellen Schäden:* Bei finanziellen Schäden empfiehlt das NCSC, Anzeige bei den kantonalen Strafverfolgungsbehörden zu erstatten.

### Kritische Beurteiliung

Die oben aufgezeigten Bedrohungen und Schutzmaßnahmen sind nur die aktuellen Top-Bedrohungen in diesem Monat. Es gibt noch viele weitere Bedrohungen in der Cybersicherheit. [Hier](https://www.ncsc.admin.ch/ncsc/de/home/cyberbedrohungen.html) finden Sie weitere Informationen.

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


### Kritische Beurteilung

Ich habe die Sicherheitslücke anhand SQL-Injection aufgezeigt und Maßnahmen dagegen implementiert, aber es gibt auch noch viele weitere Sicherheitlücken die nicht durch diese VErbesserung abedeckt sind. Cross-Site Scripting (XSS), das im Modul 183 behandelt wird und ähnlich abläuft. Es ermöglicht den Angreifern, bösartigen Code in Webseiten einzufügen, der dann von anderen Nutzern ausgeführt wird.


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


### Kritische Bewertung

In meinem Projekt erläutere ich die Zwei-Faktor-Authentifizierung für sichere Anmeldungen sowie die Autorisierung für die Edit und Delete-Funktion, um sicherzustellen, dass nur der Administrator bestimmte Aktionen durchführen können oder der ersetller des Eintrags. Es gibt auch noch weitere methoden um eine Authentifizrung zu gewährleisten, welche ich nicht angesprochen habe. Eine davon wäre die verwendung von JWT. Das Token enthält Informationen über den Benutzer und kann dazu verwendet werden, seine Identität zu überprüfen, ohne dass bei jeder Anfrage Benutzername und Passwort erneut übermittelt werden müssen.


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



### Kritische Bewertung

Um das Erreichen dieses Handlungsziels nachzuweisen, bin ich nur auf den Human Factor in Bezug auf die Passwortwahl eingegangen. Der Human Factor zeigt in der Praxis noch weitere Sicherheitsrisiken, z.B. das Öffnen von Phishing-E-Mails oder das Vernachlässigen von Sicherheitsrichtlinien.




# HZ 5

## Informationen für Auditing und Logging generieren. Auswertungen und Alarme definieren und implementieren.

Durch das Hinzufügen von Logging-Nachrichten können Entwickler und Administratoren wichtige Ereignisse in der Anwendung überwachen. Diese Protokolle sind besonders nützlich beim Debuggen, bei der Überwachung der Anwendungsleistung und bei der Identifizierung von Problemen oder Sicherheitsvorfällen. Sie bieten Einblicke in das Geschehen der Anwendung und erleichtern die Nachverfolgung von Aktivitäten im System.

### Codeausschnitt:

``` csharp 

public ActionResult<User> Login(LoginDto request)
{
    if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
    {
        return BadRequest();
    }
    string username = request.Username;
    string passwordHash = MD5Helper.ComputeMD5Hash(request.Password);

    User? user = _context.Users
        .Where(u => u.Username == username)
        .Where(u => u.Password == passwordHash)
        .FirstOrDefault();

    if (user == null)
    {
        _logger.LogWarning($"login failed for user '{request.Username}'");
        return Unauthorized("login failed");
    }

    _logger.LogInformation($"login successful for user '{request.Username}'");
    return Ok(CreateToken(user));
}

```

In der konsole sind nun die Log Informationen ersichtlich



![screenshotHZ5](https://github.com/julian05z/ZurkindenJulianLB-183/assets/89130623/0ceec89e-7c09-4556-8c59-ef5607491749)

![screeenhz5sucess](https://github.com/julian05z/ZurkindenJulianLB-183/assets/89130623/9541da29-60d4-41c9-bdbd-ba0c6062973b)

### Kritische Bewertung
Um die Anwendung und Implementierung von Logging zu beweisen, habe ich die Logs für das Login erstellt und aufgezeigt. Es gibt in der Praxis aber noch weiteres Logging, das für den Entwickler wichtig sein könnte, das mein Artefakt nicht einschließt. Ein wichtiger Aspekt für das Logging wäre das Löschen oder Bearbeiten von Einträgen. Wenn z.B. wichtige Informationen geändert werden, kann man nachverfolgen, wer diese verändert hat.
