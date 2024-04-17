# Programm erstellt von Keanu Caspers | 2023 | Diese Software basiert auf dem Blog Eintrag von Cyber Fenix
# DFIR "iOS Forensics: VMP4 File format" vom 13. September 2020. Wenn weitere type fields ergänzt werden,
# müssen diese in der parsesec Methode der Analyzer Klasse ergänzt werden. Zu dem Zeitpunkt der Erstellung dieser
# Software sind die Typen 10 und 11 erforscht.

import binascii
import os
import tkinter.messagebox
import zlib
from tkinter import Label, Button, Entry
from tkinter.constants import *
from tkinter.filedialog import askopenfilename, asksaveasfilename
from tkinterdnd2 import DND_FILES, TkinterDnD


# Klasse Vmp4analyzer stellt das GUI.
class Vmp4main:

    def __init__(self):

        art = r'''
          ___      ___ ________  _____ ______   ________   
         |\  \    /  /|\   __  \|\   _ \  _   \|\   __  \  
         \ \  \  /  / | \  \|\  \ \  \\\__\ \  \ \  \|\  \ 
          \ \  \/  / / \ \   __  \ \  \\|__| \  \ \   ____\
           \ \    / /   \ \  \ \  \ \  \    \ \  \ \  \___|
            \ \__/ /     \ \__\ \__\ \__\    \ \__\ \__\   
             \|__|/       \|__|\|__|\|__|     \|__|\|__|   
        '''

        print(art)

        # Hier wird eine Variable als Platzhalter vorgemerkt, welche im späteren Verlauf des Programmes weitergegeben
        # werden soll.
        self.file = None
        # Erstellt das Hauptfenster mit angegebenem Titel und Maßen.
        self.mainframe = TkinterDnD.Tk()
        self.mainframe.title("VMP4-Analyzer")
        self.mainframe.geometry('800x200')
        self.mainframe.drop_target_register(DND_FILES)
        self.mainframe.dnd_bind('<<Drop>>', self.handle_drop)
        self.mainframe.grid_columnconfigure(0, weight=1)

        # Einfache Willkommensnachricht als Label.
        self.welcomelabel = Label(self.mainframe, text="Wählen Sie eine Datei aus, die analysiert werden soll:",
                                  font=("Arial", 16, "bold"))
        self.welcomelabel.grid(column=0, row=0, columnspan=2, pady=20)
        self.welcomelabel.grid_configure(sticky="nsew")

        # Button, welcher bei Knopfdruck die Methode choosefile auslöst.
        self.filechooser = Button(self.mainframe, text="Datei auswählen", fg="white", bg="blue",
                                  command=self.choosefile)
        self.filechooser.grid(column=0, row=1, padx=(20, 0), pady=10, sticky="e")

        # Eingabefeld dient der Wiedergabe des Namen der ausgewählten Datei (Eingabefeld wird nur aus Designgründen
        # benutzt, kann aber nicht manuell beschrieben werden).
        self.filename = Entry(self.mainframe, width=40, state="readonly")
        self.filename.grid(column=1, row=1, padx=(0, 20), pady=10, sticky="w")

        # Button, welcher bei Knopfdruck die Methode startwork auslöst
        start = Button(self.mainframe, text="Analyse starten", bg="green", fg="white", command=self.startwork)
        start.grid(column=0, row=2, columnspan=2, pady=20)

        self.mainframe.grid_rowconfigure(1, weight=1)
        self.mainframe.grid_columnconfigure(1, weight=1)
        self.center_elements()

        self.mainframe.mainloop()

        # Die Methode choosefile sorgt dafür, dass sich der Dateiexplorer öffnet und eine Datei mit der *.vmp4
        # Dateiendung ausgewählt werden kann (askopenfilename). Diese Datei wird dann in der zuvor genannten
        # Platzhaltervariable (self.file) hinterlegt. Dabei wird außerdem mit os.path.split der Name der Datei in
        # einem String hinterlegt; wenn eine neue Datei ausgewählt wurde, wird das anfangs erstellte "Eingabefeld"
        # wieder beschreibbar, der erwähnte String hinterlegt und danach wieder unbeschreibbar gemacht. Zusätzlich
        # wird die Beschriftung des Knopfes geändert, sollte eine neue Datei ausgewählt worden sein.

    def choosefile(self):
        newfile = askopenfilename(filetypes=[("Binary content", "*.bin"), ("VMP4 files", "*.vmp4")])
        newfilename = os.path.basename(newfile)

        if newfile:
            print("Chose new file with filename " + newfilename)
            self.filename.configure(state=NORMAL)
            self.filename.delete(0, 'end')
            self.filename.insert(0, newfilename)
            self.filename.configure(state="readonly")

            self.filechooser.configure(text="Datei ändern")
            self.file = newfile

    # Die Methode handle_drop wird aufgerufen, wenn eine Datei per Drag-and-Drop hinzugefügt wird.
    def handle_drop(self, event):
        file = event.data
        if len(file) > 0:
            newfile = file.strip('{}')
            newfilename = os.path.basename(newfile)
            self.filename.configure(state=NORMAL)
            self.filename.delete(0, 'end')
            self.filename.insert(0, newfilename)
            self.filename.configure(state="readonly")
            self.filechooser.configure(text="Datei ändern")
            self.file = newfile
            print("Dropped file: " + newfilename)

        # Wurde bereits eine Dateu ausgewählt, übergibt die Funkion startwork die Daten aus self.file (Daten der
        # ausgewählten Datei) an ein Objekt der Klasse Analyzer. Sollte noch keine Datei ausgewählt worden sein,
        # wird ein PopUp-Window mit einer Hinweismeldung angezeigt.

    def startwork(self):

        if self.file:

            print("Trying to analyse file called " + self.filename.get())
            Analyzer(self.file, os.path.splitext(os.path.basename(self.file))[0])
            self.mainframe.destroy()

        else:

            print("No VMP4 or bin file chosen")
            tkinter.messagebox.showinfo("Hinweis", "Sie haben keine VMP4 oder Binary Datei ausgewählt.")

    # Die Methode center_elements dient der automatischen Zentrierung der Elemente des Hauptfensters mainframe
    def center_elements(self):
        self.mainframe.update_idletasks()
        width = self.mainframe.winfo_width()
        height = self.mainframe.winfo_height()
        x_offset = (self.mainframe.winfo_screenwidth() - width) // 2
        y_offset = (self.mainframe.winfo_screenheight() - height) // 2
        self.mainframe.geometry(f"{width}x{height}+{x_offset}+{y_offset}")


# Die Klasse Analyzer ist zuständig für das dekomprimieren der ausgewählten Datei. Dazu zäht das
# Herausarbeiten der unterschiedlichen Sektoren, als auch eine erneute Überprüfung, ob der Header der Datei
# typisch für ein VMP4-Format ist.
class Analyzer:
    # Dem Konstruktor der Analyzer-Klasse muss ein Parameter mitgegeben werden. Hierbei handelt es sich um den
    # Inhalt der Datei, welche im vorherigen Fenster ausgewählt wurde.
    def __init__(self, data, name: str):
        self.data = data
        self.name = name

        # Dieser boolean stellt fest, ob bereits ein Sektor der Datei vollständig analysiert werden konnte
        self.analysed = False

        # In diesen String werden später alle dekomprimierten Texte herein geschrieben, welche aus den Sektionen der
        # Datei kommen, die dekomprimiert werden konnten.
        self.results = ""

        # Sections erhält im späteren Verlauf die Anzahl der Sektionen, welche die VMP4-Datei enthält
        self.sections = 0

        # Die Cache-Variable wird durch die Klasse als Zwischenspeicher für verschiedene Operationen benötigt.
        self.cache = ""

        # Das Array contentarray, in welchem später die einzelnen Bytes aus der zu dekomprimierenden Datei abgelegt
        # werden.
        self.contentarray = []

        # Bytes der Datei werden in Array gespeichert (Siehe Kommentar an Methode)
        self.loadcontentarray()

        # Hier wird geprüft, ob ein typischer VMP4-Header in der Datei vorhanden ist. Wenn keiner vorhanden ist
        # (Rückgabe 1 der Methode), wird eine Fehlermeldung gezeigt und das Programm beendet.
        if self.checkheader() == 1:
            tkinter.messagebox.showinfo("Fehler",
                                        "Die ausgewählte Datei scheint nicht den standardmäßigen Header einer "
                                        "VMP4-Datei zu enthalten. Bitte wählen Sie eine andere Datei aus, "
                                        "um fortzufahren.")

        # Liest die Anzahl der Sections der angegebenen Datei aus
        self.getseccount()

        self.readsecinfo()

    # Die Methode clearcache leert die Variable "cache" und vermerkt den vorherigen Inhalt in der Konsole
    def clearcache(self):
        if self.cache == "":
            return
        else:
            print("Cleared cache variable | " + self.cache + " |")
            self.cache = ""

    # Der Cache-Speicher wird nun dazu benutzt, die ersten vier Bytes der Datei auszulesen und abzuspeichern,
    # da dieser für den Header der Datei stehen.
    # Jetzt wird ein standardmäßiger VMP4-Header mit den ersten vier Bytes (aus dem Cache) der Datei
    # verglichen. Sollte der Header nicht stimmen, wird "1" zurückgegeben. Es
    # kann sein, dass einfach nur die Endung einer Datei umbenannt wurde, jedoch handelt es sich hier bei laut
    # Header nicht nach einer VMP4-Datei. Nach Beendigung wird der Cache geleert.
    def checkheader(self):
        self.clearcache()
        for i in range(len(self.contentarray)):
            if i == 4:
                break
            self.cache = self.cache + str(self.contentarray[i].decode())

        if self.cache != "564d5034":
            print("File doesn't have a typical VMP4-Header")
            self.clearcache()
            return 1
        else:
            print("VMP4-Header found")
            self.clearcache()
            return 0

    # Diese Methode speichert alle Bytes der Datei einzeln in dem content-array des Objektes der Klasse Analyzer.
    # Dazu wird die im Konstruktor angegebene Datei im "reading binary" Modus geöffnet und Byte für Byte (hex)
    # ausgelesen und abgespeichert.
    def loadcontentarray(self):
        data = open(self.data, "rb")
        count = 0
        byte = data.read(1)
        while byte:
            self.contentarray.append(binascii.hexlify(byte))
            print("Appended hexlified byte to content-array | " + str(self.contentarray[count]) + " |")
            byte = data.read(1)
            count += 1

    # Diese Methode arbeitet die Anzahl der Sektionen der angegebenen Datei heraus. Diese stehen an der Stelle 6 und
    # 7. Dadurch dass Little-Endian verwendet wird, muss das zweite Byte (welches eine größere Zahl interpretieren
    # soll) außerdem mal 256 multipliziert werden.
    def getseccount(self):
        count = 0
        for i in range(6, 8, 1):
            if count == 1:
                self.sections += int(self.contentarray[i].decode("ascii"), 16) * 256
            else:
                self.sections += int(self.contentarray[i].decode("ascii"), 16)
        print("The file has " + str(self.sections) + " sections")

    # Diese Methode arbeitet die Informationen zu den einzelnen Sektoren heraus und übergibt diese Informationen
    # jeweils an die Methode parsesec, wenn das type field des Sektors bekannt ist, erforscht wurde und deshalb
    # dekomprimiert werden kann.
    def readsecinfo(self):

        # Diese for-Schleife wird anhand der Anzahl von Sektoren ausgeführt
        for s in range(0, self.sections):

            # Da diese Daten (type field, offset location, size) pro Sektion erneut herausgefunden werden müssen,
            # werden diese bei jedem Durchlauf dieser Schleife zurückgesetzt.
            tf = 0
            offs = 0
            size = 0

            count = 1
            print("Reading information bytes of " + str(s + 1) + ". section:")

            # Diese for-Schleife geht immer die 10 Bytes des jeweiligen Sektors durch
            for i in range((8 + 10 * s), (8 + 10 * s) + 10):
                print("Checking " + str(i) + ". byte | ", end="")
                print(str(self.contentarray[i]) + " |")

                # Hier muss beachtet werden, dass vmp4-Dateien Sektor-Informationen mit Little-Endian abgebildet
                # werden, weshalb mit 256^count gearbeitet werden muss

                # Diese if-Verzweigung dient der Überprüfung der 2 Byte "Type field"
                if count in range(1, 3):
                    tf += int(self.contentarray[i].decode("ascii"), 16) * (256 ** (count - 1))

                # Diese if-Verzweigung dient der Überprüfung der 4 Byte "offset location"
                elif count in range(3, 7):
                    offs += int(self.contentarray[i].decode("ascii"), 16) * (256 ** (count - 3))

                # Diese if-Verzweigung dient der Überprüfung der 4 Byte "size"
                elif count in range(7, 11):
                    size += int(self.contentarray[i].decode("ascii"), 16) * (256 ** (count - 7))

                count += 1

            print("Giving following information about the " + str(s + 1) + ". section to parsesec():")
            print("Type field: " + str(tf))
            print("Offset location: " + str(offs))
            print("Size: " + str(size))
            self.results += (str(s + 1) + ". Sektion (Type field: " + str(tf) + "; Offset: " + str(offs) + "; Size: " +
                             str(size) + "):\n")
            self.parsesec(s, tf, offs, size)
        self.presresults()

    # Diese Methode lokalisiert und dekomprimiert bzw. "übersetzt" einzelne Sektoren, wenn die zugehörigen type field
    # bekannt und erforscht sind.
    def parsesec(self, s: int, tf: int, offs: int, size: int):
        seccontent = []

        # Da momentan nur type field "10" und "11" erforscht sind, kann keine Sektion ohne diese analysiert werden.
        if tf != 10 and tf != 11:
            print("The data of the " + str(s + 1) + ". section can't be analysed, because the type field " + str(
                tf) + " is unknown till now.")
            self.results += (
                    "Der Inhalt der " + str(s + 1) + ". Sektion kann nicht analysiert werden, da der zugehörige "
                                                     "Typ noch nicht erforscht wurde.\n\n")
            return
        else:

            # Speichere die Daten der Sektion in ein weiteres Array, damit pauschalisiert werden kann.
            count = 0
            for i in range(offs, offs + size):
                seccontent.append(self.contentarray[i])
                print("Appended hexlified byte to seccontent-array | " + str(seccontent[count]) + " |")
                count += 1

            # Wenn im ersten Byte 0 steht, folgen unkomprimierte Daten, welche nur in ASCII übersetzt werden müssen,
            # tue dies
            if seccontent[0] == b'00':
                for byte in seccontent:
                    ascii_char = chr(int(byte, 16))
                    self.results += str(ascii_char)
                    print(ascii_char, end='')
                self.results += "\n\n"
                print("")
                self.analysed = True
                return

            # Wenn im ersten Byte 1 steht, folgen nach einem Offset von 5 (also Stelle 5 und 6) komprimierte Daten. Dann
            # muss erneut an einem Bereich geprüft werden, womit die Daten komprimiert wurden.
            elif seccontent[0] == b'01':
                self.clearcache()
                for i in range(5, 7):
                    self.cache = self.cache + str(seccontent[i].decode())

                # Der Header "789c" steht für Zlib und muss dehalb damit dekomprimiert werden
                if self.cache == "789c":
                    bytestring = b''
                    self.results += "Diese Sektion wurde mit zlib komprimiert und wird nun dekomprimiert:\n"
                    print("File is compressed with zlib default compression; more info on: "
                          "'https://isc.sans.edu/forums/diary/Recognizing+ZLIB+Compression/25182/'")
                    print("Starting decompression: ")

                    # Übergebe alle Bytes ab zlib-Header und dekomprimiere. Da die dekomprimierten Daten nun in utf-8
                    # From vorliegen, müssen diese ebenfalls so decoded werden.
                    for i in range(5, len(seccontent)):
                        bytestring += binascii.unhexlify(seccontent[i].decode())
                    decomp = zlib.decompress(bytes(bytestring))
                    text = decomp.decode("utf-8", errors="replace")
                    self.results += (text + "\n\n")
                    print(text)
                    self.analysed = True
                    return

                # Bis jetzt sind andere Komprimierungstools nicht im Blog vorhanden. Bei neuen Erkenntnissen können
                # diese durch Keanu dem Code hinzugefügt werden
                else:
                    self.results += (
                            "Diese Sektion ist mit einem unbekannten Tool komprimiert worden und besitzt den "
                            "Header: " + self.cache)
                    print("Section is compressed with an unknown compression tool with the header: " + self.cache)
                    self.clearcache()
                return

    # Diese Methode speichert die Ergebnisse der Analyse in einer Textdatei ab.
    def presresults(self):

        # Wenn keine einzige Sektion der Datei analysiert werden konnte, wird eine Meldung ausgegeben und das
        # Programm beendet.
        if not self.analysed:
            tkinter.messagebox.showinfo("Hinweis", "Die Datei enthält keine derzeit analysierbaren Sektionen.")
            exit()

        print(" \nResults: " + self.results)

        save_path = asksaveasfilename(defaultextension=".txt", initialfile=(self.name + "-Analyseergebnisse.txt"))
        if save_path:
            with open(save_path, "w", encoding="utf-8") as file:
                file.write(self.results)
                file.close()
        return

    # Diese Methode präsentiert die Ergebnisse der Dateianalyse; wurde keine Sektion analysiert, erhält der Nutzer
    # einen Hinweis. Sonst werden alle Ergebnisse der erfolgreich analysierten Sektoren aufgeführt.


Vmp4main()
