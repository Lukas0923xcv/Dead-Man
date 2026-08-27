# Allgemeine Geschäftsbedingungen (AGB) für SecureVault (Schweiz)

**Gültig ab:** 27. August 2026  
**Anwendbares Recht:** Schweizerisches Recht (OR & DSG)  
**Dienst:** SecureVault – Zero-Knowledge Dual-Key Split Digitaler Tresor & Notfall-Nachlass-Dienst  

---

## 1. Geltungsbereich und Vertragspartner

1.1 Diese Allgemeinen Geschäftsbedingungen (nachfolgend **„AGB“**) regeln die Nutzung der Software-as-a-Service-Plattform **SecureVault** (nachfolgend **„Dienst“** oder **„Plattform“**), betrieben durch den Diensteanbieter (nachfolgend **„Anbieter“**).  

1.2 Durch die Registrierung eines Benutzerkontos, den Erwerb eines Abonnements oder die Inanspruchnahme von Speicher- und Verschlüsselungsdiensten erklärt sich der Nutzer (nachfolgend **„Kunde“** oder **„Nutzer“**) mit diesen AGB vollumfänglich einverstanden.  

1.3 Abweichende, entgegenstehende oder ergänzende Geschäftsbedingungen des Nutzers werden nicht Vertragsbestandteil, es sei denn, der Anbieter stimmt deren Geltung ausdrücklich schriftlich zu.  

---

## 2. Leistungsbeschreibung & Zero-Knowledge-Architektur

2.1 **Zero-Knowledge-Verschlüsselung:**  
SecureVault stellt eine kryptographische Verwahrungs- und Nachlass-Infrastruktur bereit. Alle vertraulichen Daten, Texte und Dateianhänge werden auf dem Endgerät des Nutzers im Webbrowser mittels **Client-Side AES-256-GCM** verschlüsselt, bevor sie an den Server übertragen werden.  

2.2 **Dual-Key-Split-Verfahren:**  
Der Hauptschlüssel wird in zwei getrennte 256-Bit-Schlüsselfragmente aufgeteilt:
- **Schlüssel A (Privater Nutzerschlüssel):** Verbleibt ausschliesslich beim Nutzer bzw. dessen berechtigten Erben. Der Server speichert zu keinem Zeitpunkt Schlüssel A.
- **Schlüssel B (Serverschlüssel):** Wird serverseitig bis zum Eintritt eines autorisierten Abrufs oder der Nachlass-Bedingung verwahrt.  

2.3 **Speicherplatz-Kontingent:**  
Jedem Nutzerkonto steht standardmässig ein Gesamtspeicherplatz von **10 GB (Gigabyte)** für verschlüsselte Tresore zur Verfügung, sofern im gewählten Abonnement nicht ausdrücklich ein abweichendes Kontingent vereinbart wurde. Wird das Kontingent erreicht, können keine weiteren Datensätze hochgeladen werden, bis bestehende Tresore gelöscht oder das Kontingent erweitert wird.  

2.4 **Dead Man's Switch (Inaktivitäts-Notfallübergabe):**  
Wird über einen definierten Zeitraum (Standard: **30 aufeinanderfolgende Tage**) keine Aktivität auf dem Konto oder an einem Tresor verzeichnet, wird Schlüssel B automatisch an die vom Nutzer hinterlegten Empfänger-E-Mail-Adressen übermittelt.  

2.5 **Serverstandort Schweiz:**  
Sämtliche verschlüsselten Datensätze und Infrastrukturkomponenten werden auf Servern innerhalb der Schweiz gehostet und unterliegen dem Schweizerischen Datenschutzgesetz (DSG).  

---

## 3. Registrierung, Authentifizierung und Kontosicherheit

3.1 Zur Nutzung des Verschlüsselungsdienstes und zur Verwaltung von Tresoren ist die Erstellung eines Benutzerkontos erforderlich. Der Nutzer ist verpflichtet, wahrheitsgemässe Angaben zu machen und seine Zugangsdaten geheim zu halten.  

3.2 Der Nutzer ist für sämtliche Aktivitäten verantwortlich, die unter Verwendung seiner Zugangsdaten oder Tokens getätigt werden.  

3.3 Ein Login ist für den regulären Eigentümerbetrieb erforderlich. Begünstigte Erben können nach erfolgter Freigabe von Schlüssel B Datensätze öffentlich ohne Benutzerkonto entschlüsseln, sofern sie im Besitz von **Speichercode, Schlüssel A und Schlüssel B** sind.  

---

## 4. Pflichten des Nutzers & Schlüsselverwaltung

4.1 **Alleinige Verantwortung für Schlüssel A:**  
Da der Anbieter nach dem Zero-Knowledge-Prinzip arbeitet, besitzt der Anbieter **keinerlei Kopie, Hinterlegung oder Wiederherstellungsmöglichkeit für Schlüssel A**.  
> **WICHTIGER HINWEIS:** Geht Schlüssel A verloren oder wird dieser nicht an Erben übergeben, sind die verschlüsselten Daten **unwiderruflich verloren**. Der Anbieter kann Daten ohne Schlüssel A unter keinen Umständen rekonstruieren oder entschlüsseln.  

4.2 **Pflege der Empfänger-Adressen:**  
Der Nutzer ist verpflichtet, gültige und erreichbare E-Mail-Adressen für bis zu zwei Notfall-Empfänger zu hinterlegen. Der Anbieter haftet nicht für unzustellbare E-Mails infolge fehlerhafter Angaben, Spam-Filter des Empfängers oder inaktiver Postfächer.  

4.3 **Zulässige Inhalte & Rechtskonformität:**  
Dem Nutzer ist es untersagt, rechtswidrige Inhalte, Schadsoftware (Viren, Ransomware) oder Inhalte, die Rechte Dritter verletzen, über den Dienst zu speichern.  

---

## 5. Notfall-Übergabe & Löschfristen (Data Purge Policy)

5.1 **30-Tage-Abruffrist nach Übergabe:**  
Sobald Schlüssel B infolge Inaktivität (Dead Man's Switch) oder manueller Nachlass-Auslösung an den Empfänger versendet wurde, beginnt eine Frist von **30 Tagen**, innerhalb derer die Daten entschlüsselt und heruntergeladen werden können.  

5.2 **30-Tage-Löschfrist bei Trennung der Nachlassverbindung:**  
Wird die automatisierte Notfallweitergabe für einen Tresor manuell getrennt („Verbindung trennen“), verbleiben ebenfalls **30 Tage** zum Abruf, bevor die Daten gelöscht werden.  

5.3 **Unwiderrufliche Datenlöschung (Purge):**  
Nach Ablauf der jeweiligen 30-Tage-Frist werden der verschlüsselte Datensatz, alle Dateianhänge und Server-Schlüsselfragmente **vollständig, unwiederbringlich und datenschutzkonform vom Server gelöscht**. Eine Wiederherstellung nach Fristablauf ist technisch ausgeschlossen.  

5.4 **Manuelle Löschung:**  
Der Nutzer hat jederzeit das Recht, bestehende Tresore und zugehörige Dateien vorzeitig mit sofortiger Wirkung endgültig vom Server zu löschen.  

---

## 6. Verfügbarkeit und Wartung

6.1 Der Anbieter bemüht sich um eine möglichst unterbrechungsfreie Verfügbarkeit des Dienstes (angestrebte Verfügbarkeit: 99.5 % im Jahresmittel).  

6.2 Ausgenommen von der Verfügbarkeitsberechnung sind planmässige Wartungsfenster, Sicherheitsupdates sowie Ausfälle, die ausserhalb des Einflussbereichs des Anbieters liegen (z. B. Störungen von Internet-Backbones, DNS-Ausfälle, höhere Gewalt oder Angriffe durch Dritte wie DDoS).  

---

## 7. Haftungsausschluss und Haftungsbeschränkung

7.1 **Zero-Knowledge-Haftungsausschluss:**  
Der Anbieter haftet in keinem Fall für Schäden, die aus dem Verlust, dem Diebstahl oder der Nicht-Weitergabe von **Schlüssel A** oder den Login-Zugangsdaten entstehen.  

7.2 **Haftungsumfang nach Schweizer Recht:**  
- Der Anbieter haftet unbeschränkt für Schäden aus der Verletzung von Leben, Körper oder Gesundheit sowie bei **rechtswidriger Absicht** oder **grober Fahrlässigkeit** gemäss Art. 100 Abs. 1 OR.  
- Für **leichte Fahrlässigkeit** wird die Haftung im gesetzlich zulässigen Rahmen vollumfänglich wegbedungen.  
- Die Haftung für indirekte Schäden, Folgeschäden, entgangenen Gewinn, Betriebsunterbrechungen oder reine Vermögensschäden ist ausgeschlossen.  

7.3 **E-Mail-Zustellung:**  
Der Anbieter übernimmt keine Gewähr für die fehlerfreie Zustellung von Benachrichtigungs-E-Mails, sofern die Störung auf Seiten externer Mail-Provider (z. B. Spam-Einstufung, Postfachüberfüllung) oder Netzwerkübertragungsfehler zurückzuführen ist.  

---

## 8. Datenschutz & Geheimhaltung

8.1 Die Bearbeitung von Personendaten erfolgt in strikter Übereinstimmung mit dem **Schweizerischen Bundesgesetz über den Datenschutz (DSG)**.  

8.2 Der Anbieter erhebt und verarbeitet nur diejenigen Personendaten, die für die Bereitstellung des Dienstes, die Authentifizierung und die Notfall-E-Mail-Zustellung zwingend erforderlich sind (z. B. Benutzername, Passwort-Hash, E-Mail-Adressen der Empfänger).  

8.3 Durch die Zero-Knowledge-Architektur hat der Anbieter zu keinem Zeitpunkt Einsicht in die Klartextinhalte verschlüsselter Notizen, Passwörter oder Dateianhänge.  

---

## 9. Preise, Zahlungsbedingungen & Kündigung

9.1 Die Entgelte für kostenpflichtige Abonnements richten sich nach der jeweils aktuellen Preisübersicht auf der Plattform. Alle Preise verstehen sich in Schweizer Franken (CHF) bzw. Euro (EUR) inklusive allfälliger gesetzlicher Mehrwertsteuer.  

9.2 Abonnemente verlängern sich jeweils um die gewählte Laufzeit (monatlich oder jährlich), sofern sie nicht vor Ablauf der aktuellen Periode im Kundenkonto gekündigt werden.  

9.3 Bei Kündigung oder Nichtverlängerung eines Kontos hat der Nutzer vor Ablauf des Abonnements für die Sicherung seiner Daten Sorge zu tragen. Nach Vertragsbeendigung werden nicht verlängerte Daten gemäss Löschrichtlinie bereinigt.  

---

## 10. Änderungen der AGB

10.1 Der Anbieter behält sich vor, diese AGB jederzeit anzupassen, insbesondere bei Weiterentwicklung der Funktionen oder bei Gesetzesänderungen.  

10.2 Über Änderungen wird der Nutzer mindestens 30 Tage vor Inkrafttreten per E-Mail oder über die Plattform informiert. Widerspricht der Nutzer nicht innerhalb dieser Frist, gelten die geänderten AGB als angenommen.  

---

## 11. Salvatorische Klausel

Sollte eine Bestimmung dieser AGB ganz oder teilweise ungültig oder undurchsetzbar sein, so berührt dies die Gültigkeit der übrigen Bestimmungen nicht. Anstelle der unwirksamen Bestimmung gilt eine rechtswirksame Regelung als vereinbart, die dem wirtschaftlichen Zweck der ursprünglichen Bestimmung am nächsten kommt.  

---

## 12. Anwendbares Recht und Gerichtsstand

12.1 Auf das gesamte Vertragsverhältnis zwischen dem Anbieter und dem Nutzer ist ausschliesslich **materielles Schweizer Recht** unter Ausschluss des UN-Kaufrechts (CISG) und kollisionsrechtlicher Normen anwendbar.  

12.2 Ausschliesslicher **Gerichtsstand** für alle Streitigkeiten aus oder im Zusammenhang mit diesem Vertrag ist der **Sitz des Anbieters in der Schweiz**, soweit kein zwingender gesetzlicher Gerichtsstand (z. B. bei Konsumentenverträgen) vorgeht.  

---

*SecureVault • Swiss Zero-Knowledge Digital Vault & Dead Man's Switch Infrastructure*
