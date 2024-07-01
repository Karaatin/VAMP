# VAMP

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/Karaatin/VAMP/blob/main/VAMPIcon-vmp4_analyzer.png" width="50%">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/Karaatin/VAMP/blob/main/VAMPIcon-vmp4_analyzer.png" width="50%">
    <img src="https://github.com/Karaatin/VAMP/blob/main/VAMPIcon-vmp4_analyzer.png" width="50%">
  </picture>
</p>

A program (with GUI) that makes it possible to decrypt vmp4-files (Apple Maps data) and save the emerging results of the analysis in a textfile.

## Output of test analysis

Analysis results of tile-6bb335:
1. Section (Type field: 1 / ChapterGlobal; Offset: 140; Size: 12):
The content of the 1. section can't be analysed, because the method to decrypt the type field 1 is unknown till now.

2. Section (Type field: 10 / Vmp4SectionType is ChapterLabels; Offset: 152; Size: 207):
This section was compressed with zlib and is now being decompressed:
Alphington Banyule Creek Banyule Drain Bellfield Broadway Dr Bulleen Bulleen North Drain Castleton Road Drain Cleveland Avenue Drain Darebin Creek Eaglemont Glass Creek Heidelberg Heidelberg Heights Heidelberg West Ivanhoe Ivanhoe East Koonung Creek Macleod Plenty River Rosanna Salt Creek Viewbank Watsonia Drain Yallambie Yarra River 

3. Section (Type field: 11 / Vmp4SectionType is ChapterLabelLanguages; Offset: 359; Size: 8):
/en 

4. Section (Type field: 13 / Vmp4SectionType is ChapterLabelLocalizations2; Offset: 367; Size: 454):
The content of the 4. section can't be analysed, because the method to decrypt the type field 13 is unknown till now.

5. Section (Type field: 20 / Vmp4SectionType is ChapterVertices; Offset: 821; Size: 42):
The content of the 5. section can't be analysed, because the method to decrypt the type field 20 is unknown till now.

6. Section (Type field: 30 / Vmp4SectionType is ChapterPointFeatures; Offset: 863; Size: 243):
The content of the 6. section can't be analysed, because the method to decrypt the type field 30 is unknown till now.

7. Section (Type field: 20 / Vmp4SectionType is ChapterVertices; Offset: 1106; Size: 1459):
The content of the 7. section can't be analysed, because the method to decrypt the type field 20 is unknown till now.

8. Section (Type field: 31 / Vmp4SectionType is ChapterLineFeatures; Offset: 2565; Size: 95):
The content of the 8. section can't be analysed, because the method to decrypt the type field 31 is unknown till now.

9. Section (Type field: 20 / Vmp4SectionType is ChapterVertices; Offset: 2660; Size: 29929):
The content of the 9. section can't be analysed, because the method to decrypt the type field 20 is unknown till now.

10. Section (Type field: 32 / Vmp4SectionType is ChapterPolygonFeatures; Offset: 32589; Size: 5310):
The content of the 10. section can't be analysed, because the method to decrypt the type field 32 is unknown till now.

11. Section (Type field: 52 / Vmp4SectionType is ChapterPolygonPointCharacteristics; Offset: 37899; Size: 1249):
The content of the 11. section can't be analysed, because the method to decrypt the type field 52 is unknown till now.

12. Section (Type field: 38 / Vmp4SectionType is ChapterWrappingCoastlineFeatures; Offset: 39148; Size: 229):
The content of the 12. section can't be analysed, because the method to decrypt the type field 38 is unknown till now.

## How to Install

### Downloading the Executable

You can download the `VAMP.exe` file directly from the GitHub repository or fetch it using the command line.

1. **Via GitHub Web Interface**
   - Navigate to the [VAMP Releases](https://github.com/Karaatin/VAMP/releases) page.
   - Locate the `VAMP.exe` file and download it manually.

2. **Via Command Line**
   - Use `curl` or `wget` to download the file directly.

   **Using `curl`:**
   ```sh
   curl -L -o VAMP.exe https://github.com/Karaatin/VAMP/releases/download/v1.0.0/VAMP_v1.0.0.exe
   ```
    
   **Using `wget`:**
   ```sh
   wget -O VAMP.exe https://github.com/Karaatin/VAMP/releases/download/v1.0.0/VAMP_v1.0.0.exe
   ```
