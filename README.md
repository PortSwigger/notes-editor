# **Notes Editor - Burp Suite Extension**  

## **Overview**  
The **Notes Editor** is a **Burp Suite extension** designed to enhance note-taking and report generation during security testing. It provides a **rich text editor** with **tabbed documents**, **syntax highlighting**, and **built-in formatting tools** for penetration testers.  

**Key Features**:  
✔ **Tabbed interface** for multiple notes  
✔ **VS Code-style line numbers**  
✔ **Header/Footer templates** for reports  
✔ **Special symbol insertion** (★, →, ⚠)  
✔ **Save/Import** notes in `.txt` format  
✔ **HTTP request/response logging** from Burp  

**Language**: Written in **Python (Jython 2.7)** for Burp Suite compatibility.  

---

## **UI Components**  

### **1. Tabbed Editor**  
- **Main Tab**: Protected from closing (always remains open).  
- **Additional Tabs**: Closable with red "X" button (hover highlights).  
- **Line Numbers**: Right-aligned in a gray sidebar.  

### **2. Button Panel**  
| Button | Function |  
|--------|----------|  
| ⚙️ | Format headers/footers |  
| 💾 | Save notes to file |  
| 🗑️ | Clear current tab |  
| Highlight | Mark text in blue bold |  
| Import | Load notes from file |  
| New Document | Duplicate current tab |  
| Symbols | Insert special characters |  
| Close Tab | Close current tab (except main) |  

### **3. Formatting Dialogs**  
- **Header/Footer Templates**: Pre-formatted sections for reports.  
- **Symbol Palette**: Quick insertion of Unicode symbols.  

---

## **Code Structure**  

### **1. Core Class: `BurpExtender`**  
Implements Burp's `IBurpExtender`, `ITab`, and `IContextMenuFactory`.  

#### **Key Methods**:  
- **`registerExtenderCallbacks()`**: Initializes UI and buttons.  
- **`getUiComponent()`**: Returns the main panel to Burp.  
- **`createMenuItems()`**: Adds right-click options to send HTTP data to notes.  

### **2. UI Components**  

#### **`create_new_editor_tab()`**  
- Creates a tab with:  
  - Line numbers (`LineNumberView`)  
  - Close button (if not main tab)  
  - Document modification tracking  

#### **`close_tab()` / `close_current_tab()`**  
- Prevents closing the main tab.  
- Confirms before closing unsaved changes.  

#### **`show_format_dialog()`**  
- Opens header/footer formatting tabs.  

### **3. Document Management**  

#### **`save_to_file()`**  
- Saves notes as `.txt`.  
- Updates `modified` flag after save.  

#### **`import_notes()`**  
- Loads `.txt` files into the editor.  

#### **`duplicate_main_tab()`**  
- Copies content to a new tab.  

### **4. Helper Classes**  

#### **`LineNumberView`**  
- Displays line numbers in editor gutter.  
- Syncs with scrolling/editing.  

#### **`DocumentChangeListener`**  
- Tracks unsaved changes.  

---

## **Usage Examples**  
1. **Log HTTP Requests**: Right-click in Burp → "Send to Notes Editor".  
2. **Format Reports**: Use ⚙️ to insert headers/footers.  
3. **Save Notes**: Click 💾 to export as `.txt`.  

---

## **Why Use This Extension?**  
- **Organized Notes**: Tabbed interface keeps findings separate.  
- **Faster Reporting**: Templates reduce manual formatting.  
- **Burp Integration**: Directly log requests/responses.  

**Installation**: Load the `.py` file via Burp's Extender tab.  

--- 


