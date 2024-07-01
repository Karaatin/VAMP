# Program created by Keanu Caspers | 2023 | This software is based on the blog entry by Cyber Fenix
# DFIR "iOS Forensics: VMP4 File format" from September 13, 2020. If additional type fields are added,
# these must be added to the parsesec method of the Analyzer class. At the time of creating this
# software, types 10 and 11 are researched.

import binascii
import os
import tkinter.messagebox
import zlib
from tkinter import Label, Button, Entry, messagebox
from tkinter.constants import *
from tkinter.filedialog import askopenfilename, asksaveasfilename
#from tkinterdnd2 import DND_FILES, TkinterDnD

# Class Vmp4main represents the GUI.
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

            # Here a variable is noted as a placeholder, which should be passed on later in the course of the program.
        self.file = None
            # Creates the main window with specified title and dimensions.
        self.mainframe = tkinter.Tk()
        self.mainframe.title("VAMP | vmp4-data-analyzer")
        #self.mainframe.iconbitmap('VAMPIcon-vmp4_analyzer.ico')
        self.mainframe.geometry('400x200')
        self.mainframe.resizable(False, False)
        self.mainframe.configure(bg="grey")
        self.mainframe.grid_columnconfigure(0, weight=1)

            # Because of tkinterdnd not working in a genereated .exe file, this function is outsorted; mainframe would need to be set to a tkinterdnd window
        #self.mainframe.drop_target_register(DND_FILES)
        #self.mainframe.dnd_bind('<<Drop>>', self.handle_drop)

            # Simple welcome message as a label.
        self.welcomelabel = Label(self.mainframe, text="Choose a file to be analyzed:",
                                  font=("Arial", 16, "bold"), bg="grey", fg="black")
        self.welcomelabel.grid(column=0, row=0, columnspan=2, pady=20)
        self.welcomelabel.grid_configure(sticky="nsew")

            # Button, which triggers the choosefile method when clicked.
        self.filechooser = Button(self.mainframe, text="Select file", fg="white", bg="blue",
                                  command=self.choosefile)
        self.filechooser.grid(column=0, row=1, padx=(20, 0), pady=10, sticky="e")

            # Input field serves to display the name of the selected file (input field is only used for design reasons,
            # but cannot be described manually).
        self.filename = Entry(self.mainframe, width=40, state="readonly", fg="black")
        self.filename.grid(column=1, row=1, padx=(0, 20), pady=10, sticky="w")

            # Button, which triggers the startwork method when clicked
        start = Button(self.mainframe, text="Analyze", bg="green", fg="white", command=self.startwork)
        start.grid(column=0, row=2, columnspan=2, pady=20)

        self.mainframe.grid_rowconfigure(1, weight=1)
        self.mainframe.grid_columnconfigure(1, weight=1)
        self.center_elements()

        self.mainframe.mainloop()

            # The choosefile method opens the file explorer and allows selection of a file with the *.vmp4
            # file extension (askopenfilename). This file is then stored in the previously mentioned
            # placeholder variable (self.file). Additionally, with os.path.split, the name of the file is stored in
            # a string; if a new file is selected, the initially created "input field"
            # is made writable again, the mentioned string is stored, and then made readonly again. Additionally,
            # the label of the button is changed if a new file has been selected.
    def choosefile(self):
        newfile = askopenfilename(filetypes=[("Files with vmp4 content", "*.bin;*.vmp4;*.vf"), ("Binary content", "*.bin"), ("VMP4 files", "*.vmp4"), ("VectorTile files", "*.vf")])
        newfilename = os.path.basename(newfile)

        if newfile:
            print("Chose new file with filename " + newfilename)
            self.filename.configure(state=NORMAL)
            self.filename.delete(0, 'end')
            self.filename.insert(0, newfilename)
            self.filename.configure(state="readonly")

            self.filechooser.configure(text="Change file")
            self.file = newfile

            # The handle_drop method is called when a file is added via drag and drop.
    def handle_drop(self, event):
        file = event.data
        if len(file) > 0:
            newfile = file.strip('{}')
            newfilename = os.path.basename(newfile)
            self.filename.configure(state=NORMAL)
            self.filename.delete(0, 'end')
            self.filename.insert(0, newfilename)
            self.filename.configure(state="readonly")
            self.filechooser.configure(text="Change file")
            self.file = newfile
            print("Dropped file: " + newfilename)

            # If a file has already been selected, the function startwork passes the data from self.file (data of
            # the selected file) to an object of the Analyzer class. If no file has been selected yet,
            # a pop-up window with a warning message is displayed.
    def startwork(self):

        if self.file:

            print("Trying to analyse file called " + self.filename.get())
            Analyzer(self.file, os.path.splitext(os.path.basename(self.file))[0])
            self.mainframe.destroy()
            self.analyzeloop()

        else:

            print("No VMP4 or bin file chosen")
            tkinter.messagebox.showinfo("Note", "You have not selected a file including vmp4 content.")

            # The center_elements method automatically centers the elements of the main window mainframe
    def center_elements(self):
        self.mainframe.update_idletasks()
        width = self.mainframe.winfo_width()
        height = self.mainframe.winfo_height()
        x_offset = (self.mainframe.winfo_screenwidth() - width) // 2
        y_offset = (self.mainframe.winfo_screenheight() - height) // 2
        self.mainframe.geometry(f"{width}x{height}+{x_offset}+{y_offset}")

            # This method is used to ask the user if he wants to analyze another file after finishing an analysis
    def analyzeloop(self):
        loop=messagebox.askquestion('Finished', 'Do you want to analyze another file?')
        if loop == 'yes' :
            self.__init__()

        else :
            quit()


            # The Analyzer class is responsible for decompressing the selected file. This includes
            # extracting the different sectors, as well as rechecking whether the file header is
            # typical for a VMP4 format.
class Analyzer:

            # content of the file selected in the previous window.
    def __init__(self, data, name: str):
        self.data = data
        self.name = name

            # This boolean determines whether a sector of the file could be fully analyzed
        self.analysed = False

            # All decompressed texts coming from the sectors of the
            # file, which could be decompressed, are written into this string later.
        self.results = ""

            # Sections later receives the number of sections contained in the VMP4 file
        self.sections = 0

            # The cache variable is needed by the class as a temporary storage for various operations.
        self.cache = ""

            # The contentarray array, in which the individual bytes from the file to be decompressed are stored later.
        self.contentarray = []

            # Bytes of the file are stored in array (See comment on method)
        self.loadcontentarray()

            # Here it is checked whether a typical VMP4 header is present in the file. If none is present
            # (return 1 of the method), an error message is displayed and the program is terminated.
        if self.checkheader() == 1:
            tkinter.messagebox.showinfo("Error",
                                        "The selected file does not seem to contain the standard header of a "
                                        "VMP4 file. Please select another file to continue.")

            # Reads the number of Sections of the specified file
        self.getseccount()

        self.readsecinfo()

            # The clearcache method clears the "cache" variable and notes the previous content in the console
    def clearcache(self):
        if self.cache == "":
            return
        else:
            print("Cleared cache variable | " + self.cache + " |")
            self.cache = ""

            # The Cache memory is now used to read and store the first four bytes of the file,
            # as this represents the header of the file.
            # Now a standard VMP4 header is compared with the first four bytes (from the Cache) of the file
            # If the header does not match, "1" is returned. It
            # may be that only the extension of a file has been renamed, but according to the header, this is not a VMP4 file.
            # After completion, the Cache is cleared.
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

            # This method stores all bytes of the file individually in the content-array of the Analyzer class object.
            # For this purpose, the file specified in the constructor is opened in "reading binary" mode
            # and read and stored byte by byte (hex).
    def loadcontentarray(self):
        data = open(self.data, "rb")
        count = 0
        byte = data.read(1)
        while byte:
            self.contentarray.append(binascii.hexlify(byte))
            print("Appended hexlified byte to content-array | " + str(self.contentarray[count]) + " |")
            byte = data.read(1)
            count += 1

            # This method works out the number of sections of the specified file. These are at positions 6 and
            # 7. Because Little-Endian is used, the second byte (which is to interpret a larger number
            # must also be multiplied by 256.
    def getseccount(self):
        count = 0
        for i in range(6, 8, 1):
            if count == 1:
                self.sections += int(self.contentarray[i].decode("ascii"), 16) * 256
            else:
                self.sections += int(self.contentarray[i].decode("ascii"), 16)
        print("The file has " + str(self.sections) + " sections")

            # This method compares a decimal_value (in this purpose the type field) to return, which vmp4 section type it is
    def get_vmp4_section_type(self, decimal_value):
        section_types = {
            1: "ChapterGlobal",
            10: "Vmp4SectionType is ChapterLabels",
            11: "Vmp4SectionType is ChapterLabelLanguages",
            13: "Vmp4SectionType is ChapterLabelLocalizations2",
            20: "Vmp4SectionType is ChapterVertices",
            30: "Vmp4SectionType is ChapterPointFeatures",
            31: "Vmp4SectionType is ChapterLineFeatures",
            32: "Vmp4SectionType is ChapterPolygonFeatures",
            33: "Vmp4SectionType is ChapterBuildingFeatures",
            34: "Vmp4SectionType is ChapterCoastlineFeatures",
            38: "Vmp4SectionType is ChapterWrappingCoastlineFeatures",
            39: "Vmp4SectionType is ChapterBuildingMeshes",
            51: "Vmp4SectionType is ChapterLinePointCharacteristics",
            52: "Vmp4SectionType is ChapterPolygonPointCharacteristics",
            55: "Vmp4SectionType is ChapterPolygonPointLabelPositions",
            60: "Vmp4SectionType is ChapterConnectivity",
            80: "Vmp4SectionType is ChapterGeoIDSegments",
            90: "Vmp4SectionType is ChapterAddressRanges",
            93: "Vmp4SectionType is ChapterTileReferences",
            96: "Vmp4SectionType is ChapterHighResBuildings",
            100: "Vmp4SectionType is ChapterDebugBlob",
            101: "Vmp4SectionType is ChapterElevationRaster",
            102: "Vmp4SectionType is ChapterStyleAttributeRaster",
            103: "Vmp4SectionType is ChapterDaVinciMetadata",
            104: "Vmp4SectionType is ChapterLowResBuildings",
            112: "Vmp4SectionType is ChapterTransitMZROverride",
            119: "Vmp4SectionType is ChapterCoverage",
            128: "Vmp4SectionType is ChapterTransitSystems",
            129: "Vmp4SectionType is ChapterTransitNetwork",
            135: "Vmp4SectionType is ChapterRoadNetwork",
            136: "Vmp4SectionType is ChapterVenueMZROverride",
            137: "Vmp4SectionType is ChapterVenues",
            138: "Vmp4SectionType is ChapterStorefronts",
            139: "Vmp4SectionType is ChapterLowResBorderBuildings",
            140: "Vmp4SectionType is ChapterBorderBuildingMeshes",
            141: "Vmp4SectionType is ChapterLabelPlacementMetadata",
            142: "Vmp4SectionType is ChapterDaVinciBuildings",
            144: "Vmp4SectionType is ChapterPointFeaturesAddendum",
            145: "Vmp4SectionType is ChapterLinesExtended",
            146: "Vmp4SectionType is ChapterTrafficSkeleton1",
            147: "Vmp4SectionType is ChapterTrafficSkeleton2"
    }
        return section_types.get(decimal_value, "Unknown Section Type")

            # This method works out the information about the individual sectors and passes this information
            # to the method parsesec, if the type field of the sector is known, researched and therefore
            # can be decompressed.
    def readsecinfo(self):

            # This for loop is executed based on the number of sectors
        for s in range(0, self.sections):

            # Since this data (type field, offset location, size) has to be found out again per section,
            # these are reset at each iteration of this loop.
            tf = 0
            offs = 0
            size = 0

            count = 1
            print("Reading information bytes of " + str(s + 1) + ". section:")

            # This for loop always goes through the 10 bytes of the respective sector
            for i in range((8 + 10 * s), (8 + 10 * s) + 10):
                print("Checking " + str(i) + ". byte | ", end="")
                print(str(self.contentarray[i]) + " |")

                # Here it must be noted that vmp4 files sector information is represented with Little-Endian
                # which is why 256^count must be worked with

                # This if-branch serves to check the 2-byte "Type field"
                if count in range(1, 3):
                    tf += int(self.contentarray[i].decode("ascii"), 16) * (256 ** (count - 1))

                # This if-branch serves to check the 4-byte "offset location"
                elif count in range(3, 7):
                    offs += int(self.contentarray[i].decode("ascii"), 16) * (256 ** (count - 3))

                # This if-branch serves to check the 4-byte "size"
                elif count in range(7, 11):
                    size += int(self.contentarray[i].decode("ascii"), 16) * (256 ** (count - 7))

                count += 1

            print("Giving following information about the " + str(s + 1) + ". section to parsesec():")
            print("Type field: " + str(tf) + " / " + self.get_vmp4_section_type(tf))
            print("Offset location: " + str(offs))
            print("Size: " + str(size))
            self.results += (str(s + 1) + ". Sektion (Type field: " + str(tf) + " / " + self.get_vmp4_section_type(tf) + "; Offset: " + str(offs) + "; Size: " +
                             str(size) + "):\n")
            self.parsesec(s, tf, offs, size)
        self.presresults()

            # This method locates and decompresses or "translates" individual sectors, if the corresponding type field
            # known and researched.
    def parsesec(self, s: int, tf: int, offs: int, size: int):
        seccontent = []

            # Since only type fields "10" and "11" are currently researched, no section can be analyzed without these.
        if tf != 10 and tf != 11:
            print("The content of the " + str(s + 1) + ". section can't be analysed, because the type field " + str(
                tf) + " is unknown till now.")
            self.results += (
                    "The content of the " + str(s + 1) + ". can't be analysed, because the type field is unknown till now.\n\n")
            return
        else:

            # Save the data of the section in another array so that it can be generalized.
            count = 0
            for i in range(offs, offs + size):
                seccontent.append(self.contentarray[i])
                print("Appended hexlified byte to seccontent-array | " + str(seccontent[count]) + " |")
                count += 1

            # If 0 is in the first byte, uncompressed data follows, which only needs to be translated into ASCII,
            # do so
            if seccontent[0] == b'00':
                for byte in seccontent:
                    ascii_char = chr(int(byte, 16))
                    self.results += str(ascii_char)
                    print(ascii_char, end='')
                self.results += "\n\n"
                print("")
                self.analysed = True
                return

            # If 1 is in the first byte, compressed data follows after an offset of 5 (i.e. position 5 and 6). Then
            # another area must be checked to see which data was compressed.
            elif seccontent[0] == b'01':
                self.clearcache()
                for i in range(5, 7):
                    self.cache = self.cache + str(seccontent[i].decode())

            # The header "789c" stands for Zlib and must therefore be decompressed with it
                if self.cache == "789c":
                    bytestring = b''
                    self.results += "This section was compressed with zlib and is now being decompressed:\n"
                    print("File is compressed with zlib default compression; more info on: "
                          "'https://isc.sans.edu/forums/diary/Recognizing+ZLIB+Compression/25182/'")
                    print("Starting decompression: ")

            # Hand over all bytes from the zlib header and decompress. Since the decompressed data is now in utf-8
            # From, these also have to be decoded accordingly.
                    for i in range(5, len(seccontent)):
                        bytestring += binascii.unhexlify(seccontent[i].decode())
                    decomp = zlib.decompress(bytes(bytestring))
                    text = decomp.decode("utf-8", errors="replace")
                    self.results += (text + "\n\n")
                    print(text)
                    self.analysed = True
                    return

            # Until now, other compression tools are not available in the blog. With new knowledge, they can
            # be added to the code.
                else:
                    self.results += (
                            "This section is compressed with an unknown tool and has the header: " + self.cache)
                    print("Section is compressed with an unknown compression tool with the header: " + self.cache)
                    self.clearcache()
                return

            # The presresults method provides the result in a textfile
            # This method presents the results of the file analysis; if no section is analyzed, the user receives a hint. Otherwise, all results of the successfully analysed sectors are listed.
    def presresults(self):

            # If not a single section of the file could be parsed, a message is issued and the program terminates.
        if not self.analysed:
            tkinter.messagebox.showinfo("Note", "The file does not contain any parsable sections.")
            exit()

        print(" \nResults: " + self.results)

        save_path = asksaveasfilename(defaultextension=".txt", initialfile=(self.name + "-results.txt"))
        if save_path:
            with open(save_path, "w", encoding="utf-8") as file:
                file.write("Analysis results of " + self.name + ":\n" + self.results)
                file.close()
        return


Vmp4main()
