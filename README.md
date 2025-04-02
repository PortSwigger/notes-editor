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


# Burp Suite Notes Editor Extension - Source Code Documentation

## Overview
This Burp Suite extension provides a rich text editor with multiple tabs, formatting options, and integration with Burp's HTTP traffic. It allows pentesters to take notes, format reports, and save their work.

## Class Structure

### 1. LineNumberView Class
A custom component that displays line numbers for a text editor.

#### Methods:
- `__init__(self, editor)`: Initializes the line number view
  - Sets up fonts, colors, and dimensions
  - Adds a caret listener to track cursor movement
- `paintComponent(self, g)`: Renders the line numbers
  - Calculates visible lines and draws corresponding numbers
  - Handles scrolling and partial line visibility
- `removeNotify(self)`: Cleanup method to remove listeners

#### Inner Class:
- `LineNumberCaretListener`: Listens for caret movements to update line numbers

### 2. BurpExtender Class
Main extension class implementing IBurpExtender, ITab, and IContextMenuFactory interfaces.

#### Core Methods:
- `registerExtenderCallbacks(self, callbacks)`: Entry point for Burp
  - Sets up UI components
  - Initializes editor tabs and buttons
  - Registers context menu handlers

#### UI Creation Methods:
- `create_header_panel(self, parent_dialog)`: Builds header configuration panel
- `create_footer_panel(self, parent_dialog)`: Builds footer configuration panel
- `create_methodology_combo(self)`: Creates methodology dropdown
- `create_styled_button(self, text, color)`: Helper for consistent button styling
- `create_new_editor_tab(self, title)`: Creates a new editor tab
- `create_hover_listener(self, button)`: Creates mouse hover effects for buttons

#### Document Formatting Methods:
- `insert_formatted_header(self, dialog)`: Inserts formatted header into editor
- `insert_formatted_footer(self, dialog)`: Inserts formatted footer into editor
- `show_format_dialog(self, event)`: Shows header/footer formatting dialog
- `update_header_preview(self)`: Updates live header preview
- `update_footer_preview(self)`: Updates live footer preview

#### Tab Management Methods:
- `close_tab(self, title)`: Closes a specific tab
- `close_current_tab(self)`: Closes currently selected tab
- `duplicate_main_tab(self)`: Duplicates the main tab content
- `get_current_editor_data(self)`: Gets data for current editor

#### Symbol Insertion Methods:
- `show_multiple_symbols_panel(self, event)`: Shows symbol palette
- `show_multiple_symbols_fallback(self, event)`: Fallback for symbol display
- `insert_symbol(self, symbol)`: Inserts symbol at cursor position
- `_initialize_symbols_window(self)`: Initializes symbols window
- `_try_display_unicode_symbols(self)`: Attempts to show Unicode symbols
- `_show_text_symbols_fallback(self)`: Shows text fallback for symbols

#### File Operations Methods:
- `save_to_file(self, event)`: Saves current tab to file
- `import_notes(self, event)`: Imports notes from file
- `clear_current_tab(self, event)`: Clears current tab content

#### Context Menu Methods:
- `createMenuItems(self, context_menu_info)`: Creates context menu items
- `send_request_response(self, message, ...)`: Sends HTTP traffic to editor
- `append_to_editor(self, note)`: Appends text to main editor

#### Helper Methods:
- `get_field_value(self, field_name)`: Gets value from form field
- `highlight_selected_text(self, event)`: Highlights selected text in blue

## Key Features

1. **Multi-tab Editor**: Supports multiple documents with tabbed interface
2. **Rich Text Formatting**: Includes headers, footers, and text highlighting
3. **Symbol Palette**: Easy insertion of special characters
4. **Burp Integration**: Adds context menu items for HTTP traffic
5. **Line Numbers**: Visual reference for large documents
6. **File Operations**: Save/load functionality with text files
7. **Report Templates**: Pre-formatted headers and footers for reports

## Technical Details

- Uses Java Swing components via Jython
- Implements custom UI components like LineNumberView
- Maintains state for each editor tab (modified status, file path)
- Handles both Unicode symbols and text fallbacks
- Integrates with Burp's HTTP message processing

The extension provides a comprehensive note-taking solution within Burp Suite, specifically designed for penetration testers to document their findings and generate reports.



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


