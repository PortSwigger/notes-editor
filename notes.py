# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IHttpRequestResponse, IContextMenuFactory
from javax.swing import (
    JPanel, JTextPane, JScrollPane, JButton, JFileChooser,
    JTabbedPane, JMenuItem, JOptionPane, JDialog, JLabel, JFrame,
    JTextField, JTextArea, BorderFactory, JComboBox, JComponent
)
from javax.swing.text import SimpleAttributeSet, StyleConstants, StyledDocument, DefaultCaret
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing.border import TitledBorder, CompoundBorder, EmptyBorder, LineBorder
from javax.swing.event import DocumentListener, CaretListener
from java.awt import BorderLayout, Color, GridLayout, Insets, Font, FlowLayout, Dimension, Point
from java.io import BufferedWriter, FileWriter, File
from java.util import HashMap
from java.lang import System
from java.text import SimpleDateFormat
from java.util import Date
import os
import datetime
from java.awt.event import ActionListener, ActionEvent
from javax.swing.event import DocumentListener
from java.awt.event import MouseAdapter
from javax.swing import BorderFactory
class LineNumberView(JComponent):
        def __init__(self, editor):
            super(LineNumberView, self).__init__()
            self.editor = editor
            self.setFont(Font("Monospaced", Font.PLAIN, 12))
            self.setBackground(Color(240, 240, 240))
            self.setForeground(Color.GRAY)
            self.setPreferredSize(Dimension(40, 0))
            
            self.listener = self.LineNumberCaretListener(self)
            self.editor.addCaretListener(self.listener)

        class LineNumberCaretListener(CaretListener):
            def __init__(self, view):
                self.view = view

            def caretUpdate(self, e):
                self.view.repaint()

        def paintComponent(self, g):
            super(LineNumberView, self).paintComponent(g)
            g.setColor(self.getBackground())
            g.fillRect(0, 0, self.getWidth(), self.getHeight())
            g.setColor(self.getForeground())

            doc = self.editor.getDocument()
            root = doc.getDefaultRootElement()
            font_metrics = g.getFontMetrics()
            line_height = font_metrics.getHeight()
            ascent = font_metrics.getAscent()

            visible_rect = self.editor.getVisibleRect()
            start_offset = self.editor.viewToModel(Point(0, visible_rect.y))
            end_offset = self.editor.viewToModel(Point(visible_rect.width, visible_rect.y + visible_rect.height))

            start_line = root.getElementIndex(start_offset)
            end_line = root.getElementIndex(end_offset) + 1

            for i in range(start_line, end_line):
                try:
                    line_rect = self.editor.modelToView(root.getElement(i).getStartOffset())
                    y = line_rect.y + line_rect.height - ascent
                    line_number = str(i + 1)
                    g.drawString(line_number, 
                                self.getWidth() - 5 - font_metrics.stringWidth(line_number), 
                                y)
                except:
                    continue

        def removeNotify(self):
            if hasattr(self, 'listener'):
                self.editor.removeCaretListener(self.listener)
            super(LineNumberView, self).removeNotify()

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Notes Editor")
        
        self.tabbed_pane = JTabbedPane()
        self.editor_data_map = HashMap()
        
        self.main_tab_title = "Main"
        self.create_new_editor_tab(self.main_tab_title)
        
        buttons_panel = JPanel()
        
        buttons = [
            (u"\u2699", self.show_format_dialog, "Format document", True),
            (u"\U0001F4BE", self.save_to_file, "Save notes", True),
            (u"\U0001F5D1", self.clear_current_tab, "Clear notes", True),
            ("Highlight", self.highlight_selected_text, "Highlight Selected (Blue)", False),
            ("Import", self.import_notes, "Import notes from file", False),
            ("New Document", lambda e: self.duplicate_main_tab(), "New Document", False),
            ("Symbols", self.show_multiple_symbols_panel, "Insert special characters", False),
            ("Close Tab", lambda e: self.close_current_tab(), "Close current tab", False)
        ]
        
        for (display, action, tooltip, use_icon) in buttons:
            btn = JButton(display)
            btn.setToolTipText(tooltip)
            if use_icon:
                btn.setText(display)
                btn.setFont(Font("Dialog", Font.PLAIN, 20))
            else:
                btn.setText(display)
            btn.addActionListener(action)
            buttons_panel.add(btn)
        
        main_panel = JPanel(BorderLayout())
        main_panel.add(self.tabbed_pane, BorderLayout.CENTER)
        main_panel.add(buttons_panel, BorderLayout.SOUTH)
        
        self._panel = main_panel
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
    class HeaderUpdateListener(DocumentListener, ActionListener):
        def __init__(self, outer):
            self.outer = outer
            
        def changedUpdate(self, event):
            self.outer.update_header_preview()
            
        def insertUpdate(self, event):
            self.outer.update_header_preview()
            
        def removeUpdate(self, event):
            self.outer.update_header_preview()
            
        def actionPerformed(self, event):
            self.outer.update_header_preview()

    class FooterUpdateListener(DocumentListener):
        def __init__(self, outer):
            self.outer = outer
            
        def changedUpdate(self, event):
            self.outer.update_footer_preview()
            
        def insertUpdate(self, event):
            self.outer.update_footer_preview()
            
        def removeUpdate(self, event):
            self.outer.update_footer_preview()

    def create_header_panel(self, parent_dialog):
        panel = JPanel(BorderLayout())
        panel.setBorder(EmptyBorder(10, 10, 10, 10))
        
        input_panel = JPanel(GridLayout(0, 2, 10, 10))
        input_panel.setBorder(
            CompoundBorder(
                TitledBorder(LineBorder(Color(200, 200, 200)), "Header Configuration"),
                EmptyBorder(10, 10, 10, 10)
            )
        )

        fields = [
            ("Client Name", "[Client Name]"),
            ("Tester Name", "[Tester Name]"), 
            ("Scope Details", "[Scope Details]"),
            ("Methodology", self.create_methodology_combo()),
            ("Executive Summary", "[Brief summary of findings]")
        ]

        self.header_fields = {}
        for label, field in fields:
            lbl = JLabel(label + ":")
            lbl.setFont(Font("Segoe UI", Font.PLAIN, 12))
            input_panel.add(lbl)
            
            if isinstance(field, JComboBox):
                listener = self.HeaderUpdateListener(self)
                field.addActionListener(listener)
                input_panel.add(field)
                self.header_fields[label] = field
            else:
                tf = JTextField(field)
                tf.setFont(Font("Segoe UI", Font.PLAIN, 12))
                tf.setMargin(Insets(5, 5, 5, 5))
                tf.getDocument().addDocumentListener(self.HeaderUpdateListener(self))
                self.header_fields[label] = tf
                input_panel.add(tf)

        preview_panel = JPanel(BorderLayout())
        preview_panel.setBorder(
            CompoundBorder(
                TitledBorder(LineBorder(Color(200, 200, 200)), "Live Preview"),
                EmptyBorder(10, 10, 10, 10)
            )
        )
        
        self.header_preview = JTextArea()
        self.header_preview.setEditable(False)
        self.header_preview.setFont(Font("DejaVu Sans Mono", Font.PLAIN, 12))
        self.header_preview.setBorder(LineBorder(Color(150, 150, 150)))
        self.header_preview.setBackground(Color(245, 245, 245))
        
        preview_panel.add(JScrollPane(self.header_preview), BorderLayout.CENTER)
        
        button_panel = JPanel()
        button_panel.setBorder(EmptyBorder(10, 0, 0, 0))
        
        insert_btn = self.create_styled_button("Insert Header", Color(70, 130, 180))
        insert_btn.addActionListener(lambda e: self.insert_formatted_header(parent_dialog))
        
        close_btn = self.create_styled_button("Close", Color(220, 80, 60))
        close_btn.addActionListener(lambda e: parent_dialog.dispose())
        
        button_panel.add(insert_btn)
        button_panel.add(close_btn)

        panel.add(input_panel, BorderLayout.NORTH)
        panel.add(preview_panel, BorderLayout.CENTER)
        panel.add(button_panel, BorderLayout.SOUTH)
        
        return panel
    
    def create_footer_panel(self, parent_dialog):
        panel = JPanel(BorderLayout())
        panel.setBorder(EmptyBorder(10, 10, 10, 10))
        
        input_panel = JPanel(GridLayout(0, 2, 10, 10))
        input_panel.setBorder(
            CompoundBorder(
                TitledBorder(LineBorder(Color(200, 200, 200)), "Footer Configuration"),
                EmptyBorder(10, 10, 10, 10)
            )
        )

        fields = [
            ("Critical Findings", "0"),
            ("High Findings", "0"),
            ("Medium Findings", "0"), 
            ("Low Findings", "0"),
            ("Conclusion", "[Overall assessment]"),
            ("Recommendation 1", "[Critical recommendation]"),
            ("Recommendation 2", "[High priority recommendation]")
        ]
        
        self.footer_fields = {}
        for label, default in fields:
            lbl = JLabel(label + ":")
            lbl.setFont(Font("Segoe UI", Font.PLAIN, 12))
            input_panel.add(lbl)
            
            field = JTextField(default)
            field.setFont(Font("Segoe UI", Font.PLAIN, 12))
            field.setMargin(Insets(5, 5, 5, 5))
            self.footer_fields[label] = field
            input_panel.add(field)
        
        preview_panel = JPanel(BorderLayout())
        preview_panel.setBorder(
            CompoundBorder(
                TitledBorder(LineBorder(Color(200, 200, 200)), "Live Preview"),
                EmptyBorder(10, 10, 10, 10)
            )
        )
        
        self.footer_preview = JTextArea()
        self.footer_preview.setEditable(False)
        self.footer_preview.setFont(Font("Consolas", Font.PLAIN, 12))
        self.footer_preview.setBorder(LineBorder(Color(150, 150, 150)))
        self.footer_preview.setBackground(Color(245, 245, 245))
        
        preview_panel.add(JScrollPane(self.footer_preview), BorderLayout.CENTER)
        
        button_panel = JPanel()
        button_panel.setBorder(EmptyBorder(10, 0, 0, 0))
        
        insert_btn = self.create_styled_button("Insert Footer", Color(70, 130, 180))
        insert_btn.addActionListener(lambda e: self.insert_formatted_footer(parent_dialog))
        
        close_btn = self.create_styled_button("Close", Color(220, 80, 60))
        close_btn.addActionListener(lambda e: parent_dialog.dispose())
        
        button_panel.add(insert_btn)
        button_panel.add(close_btn)
        
        for field in self.footer_fields.values():
            field.getDocument().addDocumentListener(self.FooterUpdateListener(self))
        
        panel.add(input_panel, BorderLayout.NORTH)
        panel.add(preview_panel, BorderLayout.CENTER)
        panel.add(button_panel, BorderLayout.SOUTH)
        
        return panel    

    def insert_formatted_header(self, dialog):
        try:
            current_date = SimpleDateFormat("yyyy-MM-dd").format(Date())
            separator = "*" * 220  

            border_attrs = SimpleAttributeSet()
            StyleConstants.setForeground(border_attrs, Color(255, 165, 0))
            StyleConstants.setBold(border_attrs, True)

            normal_attrs = SimpleAttributeSet()
            StyleConstants.setForeground(normal_attrs, Color.BLACK)

            client = self.get_field_value('Client Name')
            project = self.get_field_value('Scope Details')
            tester = self.get_field_value('Tester Name')
            burp_version = self._callbacks.getBurpVersion()[1]

            header_text = """\n
                        PENETRATION TEST REPORT
{separator}
                                    * Client:    {client}
                                    * Project:   {project}
                                    * Tester:    {tester}
                                    * Date:      {date}
                                    * Burp Ver:  {burp_version}
{separator}\n
        """.format(
                separator=separator,
                client=client,
                project=project,
                tester=tester,
                date=current_date,
                burp_version=burp_version
            )

            editor_data = self.get_current_editor_data()
            if editor_data:
                editor = editor_data['text_pane']
                doc = editor.getDocument()
                cursor_pos = editor.getCaretPosition()

                if cursor_pos > 0:
                    doc.insertString(cursor_pos, "\n", normal_attrs)  
                doc.insertString(cursor_pos, header_text, border_attrs)  

                editor.setCaretPosition(cursor_pos + len(header_text))

                dialog.dispose()

        except Exception as e:
            self._callbacks.printError("Error inserting header: {}".format(str(e)))

    def insert_formatted_footer(self, dialog):
        try:
            separator = "*" * 220  

            border_attrs = SimpleAttributeSet()
            StyleConstants.setForeground(border_attrs, Color(255, 165, 0))
            StyleConstants.setBold(border_attrs, True)

            normal_attrs = SimpleAttributeSet()
            StyleConstants.setForeground(normal_attrs, Color.BLACK)

            findings = [
                ("Critical", self.footer_fields['Critical Findings'].getText()),
                ("High", self.footer_fields['High Findings'].getText()),
                ("Medium", self.footer_fields['Medium Findings'].getText()),
                ("Low", self.footer_fields['Low Findings'].getText()),
            ]

            footer_text = """\n
                        VULNERABILITY STATISTICS
{separator}
                                * Critical:  {critical}
                                * High:      {high}
                                * Medium:    {medium}
                                * Low:       {low}
{separator}\n
                        CONCLUSION
{separator}
        {conclusion}
{separator}\n
                        RECOMMENDATIONS
{separator}
        {recommendations}
{separator}\n
            """.format(
                separator=separator,
                critical=findings[0][1],
                high=findings[1][1],
                medium=findings[2][1],
                low=findings[3][1],
                conclusion=self.footer_fields['Conclusion'].getText(),
                recommendations="\n".join(
                    ["    {0}. {1}".format(i+1, self.footer_fields["Recommendation {}".format(i+1)].getText()) for i in range(2)]
                )
            )

            editor_data = self.get_current_editor_data()
            if editor_data:
                editor = editor_data['text_pane']
                doc = editor.getDocument()
                cursor_pos = editor.getCaretPosition()

                if cursor_pos > 0:
                    doc.insertString(cursor_pos, "\n", normal_attrs)
                
                doc.insertString(cursor_pos, footer_text, border_attrs)

                doc.insertString(doc.getLength(), "\n", normal_attrs)

                dialog.dispose()

        except Exception as e:
            self._callbacks.printError("Error inserting footer: {}".format(str(e)))

    def show_multiple_symbols_panel(self, event=None):
        try:
            if not hasattr(self, 'symbols_frame') or not self.symbols_frame.isVisible():
                self.symbols_frame = JFrame("Multiple Symbols")
                self.symbols_frame.setSize(650, 180)
                self.symbols_frame.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE)
                
                main_panel = JPanel(BorderLayout())
                
                button_panel = JPanel(FlowLayout(FlowLayout.CENTER, 10, 10))
                
                symbols = [
                    ("Happy", u"\u263a"),
                    ("Heart", u"\u2665"),
                    ("Check", u"\u2713"),
                    ("Star", u"\u2605"),
                    ("Warning", u"\u26a0"),
                    ("Note", u"\u266b"),
                    ("Point", u"\u2192"),
                    ("Important", u"\u2757")
                ]
                
                for name, symbol in symbols:
                    btn = JButton(symbol)
                    try:
                        btn.setFont(Font("Segoe UI Symbol", Font.PLAIN, 18))
                    except:
                        btn.setFont(Font("Dialog", Font.PLAIN, 18))
                    btn.setPreferredSize(Dimension(60, 50))
                    btn.setToolTipText(name)
                    btn.addActionListener(lambda e, s=symbol: self.insert_symbol(s))
                    button_panel.add(btn)
                
                close_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
                close_button = JButton("Close")
                close_button.addActionListener(lambda e: self.symbols_frame.setVisible(False))
                close_panel.add(close_button)
                
                main_panel.add(button_panel, BorderLayout.CENTER)
                main_panel.add(close_panel, BorderLayout.SOUTH)
                
                self.symbols_frame.add(main_panel)
                self.symbols_frame.setLocationRelativeTo(None)
                self.symbols_frame.setVisible(True)
            else:
                self.symbols_frame.setVisible(True)
                
        except Exception as e:
            self._callbacks.printError("Multiple Symbols error: " + str(e))
            self.show_multiple_symbols_fallback(event)

    def show_multiple_symbols_fallback(self, event=None):
        try:
            if not hasattr(self, 'symbols_frame') or not self.symbols_frame.isVisible():
                self.symbols_frame = JFrame("Multiple Symbols (Text Fallback)")
                self.symbols_frame.setSize(650, 150)
                self.symbols_frame.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE)
                
                main_panel = JPanel(BorderLayout())
                button_panel = JPanel(FlowLayout(FlowLayout.CENTER, 10, 10))
                
                text_symbols = [
                    ("Smile", ":)"),
                    ("Heart", "<3"),
                    ("Check", "[✓]"),
                    ("Star", "*"),
                    ("Warning", "!"),
                    ("Note", "~"),
                    ("Point", "->"),
                    ("Important", "!!")
                ]
                
                for name, symbol in text_symbols:
                    btn = JButton(symbol)
                    btn.setFont(Font("Dialog", Font.PLAIN, 14))
                    btn.setPreferredSize(Dimension(80, 40))
                    btn.setToolTipText(name)
                    btn.addActionListener(lambda e, s=symbol: self.insert_symbol(s))
                    button_panel.add(btn)
                
                close_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
                close_button = JButton("Close")
                close_button.addActionListener(lambda e: self.symbols_frame.setVisible(False))
                close_panel.add(close_button)
                
                main_panel.add(button_panel, BorderLayout.CENTER)
                main_panel.add(close_panel, BorderLayout.SOUTH)
                self.symbols_frame.add(main_panel)
                self.symbols_frame.setLocationRelativeTo(None)
                self.symbols_frame.setVisible(True)
            else:
                self.symbols_frame.setVisible(True)
                
        except Exception as e:
            self._callbacks.printError("Multiple Symbols fallback error: " + str(e))

    def insert_symbol(self, symbol):
        try:
            editor_data = self.get_current_editor_data()
            if editor_data:
                text_pane = editor_data['text_pane']
                doc = text_pane.getDocument()
                caret_pos = text_pane.getCaretPosition()
                doc.insertString(caret_pos, symbol, None)
        except Exception as e:
            self._callbacks.printError("Error inserting symbol: " + str(e))

    def _initialize_symbols_window(self):
        self.symbols_frame = JFrame("Symbol Palette")
        self.symbols_frame.setSize(650, 180)
        self.symbols_frame.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE)
        self.symbols_frame.setLayout(BorderLayout())
        
        self.symbol_panel = JPanel(FlowLayout(FlowLayout.CENTER, 10, 10))
        self.symbol_panel.setBorder(EmptyBorder(10, 10, 10, 10))
        
        close_panel = JPanel()
        close_button = JButton("Close")
        close_button.addActionListener(lambda e: self.symbols_frame.setVisible(False))
        close_panel.add(close_button)
        
        self.symbols_frame.add(self.symbol_panel, BorderLayout.CENTER)
        self.symbols_frame.add(close_panel, BorderLayout.SOUTH)
        self.symbols_frame.setLocationRelativeTo(None)

    def _try_display_unicode_symbols(self):
        try:
            self.symbol_panel.removeAll()
            
            symbols = [
                ("Happy", u"\u263A", "Segoe UI Emoji"),
                ("Heart", u"\u2764", "Segoe UI Symbol"),
                ("Check", u"\u2713", "DejaVu Sans"),
                ("Star", u"\u2605", "Arial Unicode MS"),
                ("Warning", u"\u26A0", "Symbola"),
                ("Note", u"\u266A", "DejaVu Sans"),
                ("Point", u"\u27A4", "Segoe UI Symbol"),
                ("Important", u"\u203C", "Arial Unicode MS")
            ]
            
            for name, symbol, font_family in symbols:
                btn = JButton(symbol)
                try:
                    btn.setFont(Font(font_family, Font.PLAIN, 18))
                except:
                    btn.setFont(Font("Dialog", Font.PLAIN, 16))
                btn.setToolTipText(name)
                btn.setPreferredSize(Dimension(60, 40))
                btn.addActionListener(lambda e, s=symbol: self.insert_symbol(s))
                self.symbol_panel.add(btn)
            
            self.symbol_panel.revalidate()
            self.symbol_panel.repaint()
            return True
            
        except Exception:
            return False

    def _show_text_symbols_fallback(self):
        try:
            self.symbol_panel.removeAll()
            
            text_symbols = [
                ("Smile", ":)"),
                ("Heart", "<3"),
                ("Check", "[✓]"),
                ("Star", "*"),
                ("Warning", "!"),
                ("Note", "~"),
                ("Point", "->"),
                ("Important", "!!")
            ]
            
            for name, symbol in text_symbols:
                btn = JButton(symbol)
                btn.setFont(Font("Dialog", Font.PLAIN, 14))
                btn.setToolTipText(name)
                btn.setPreferredSize(Dimension(60, 40))
                btn.addActionListener(lambda e, s=symbol: self.insert_symbol(s))
                self.symbol_panel.add(btn)
            
            self.symbol_panel.revalidate()
            self.symbol_panel.repaint()
            
        except Exception as e:
            self._callbacks.printError("Symbol fallback failed: " + str(e))
            raise
   
    def create_methodology_combo(self):
        combo = JComboBox([
            "OWASP Testing Guide",
            "NIST SP 800-115", 
            "PTES",
            "Custom Methodology"
        ])
        combo.setFont(Font("Segoe UI", Font.PLAIN, 12))
        return combo

    def create_styled_button(self, text, color):
        btn = JButton(text)
        btn.setBackground(color)
        btn.setForeground(Color.WHITE)
        btn.setFont(Font("Segoe UI", Font.BOLD, 12))
        btn.setFocusPainted(False)
        btn.setBorder(
            CompoundBorder(
                LineBorder(Color.DARK_GRAY),
                EmptyBorder(5, 15, 5, 15)
            )
        )
        return btn

    def get_field_value(self, field_name):
        field = self.header_fields[field_name]
        if isinstance(field, JTextField):
            return field.getText()
        elif isinstance(field, JComboBox):
            return field.getSelectedItem()
        return ""

    def show_format_dialog(self, event):
        dialog = JDialog()
        dialog.setTitle("Document Formatting")
        dialog.setSize(700, 600)
        dialog.setLayout(BorderLayout())
        
        format_tabs = JTabbedPane()
        
        header_panel = self.create_header_panel(dialog)
        format_tabs.addTab("Header", header_panel)
        
        footer_panel = self.create_footer_panel(dialog)
        format_tabs.addTab("Footer", footer_panel)
        
        dialog.add(format_tabs, BorderLayout.CENTER)
        dialog.setLocationRelativeTo(self._panel)
        dialog.setVisible(True)

    def update_header_preview(self):
        try:
            client = self.get_field_value('Client Name')
            tester = self.get_field_value('Tester Name')
            scope = self.get_field_value('Scope Details')
            methodology = self.get_field_value('Methodology')
            current_date = SimpleDateFormat("yyyy-MM-dd").format(Date())
            burp_version = self._callbacks.getBurpVersion()[1]
            exec_summary = self.get_field_value('Executive Summary')

            separator = "*" * 80

            template = (
                "\n" + separator + "\n" +
                " " * ((80 - len("PENETRATION TEST REPORT")) // 2) + "PENETRATION TEST REPORT" + "\n" +
                separator + "\n\n" +
                "Client:      %s\n" % client +
                "Tester:      %s\n" % tester +
                "Scope:       %s\n" % scope +
                "Methodology: %s\n" % methodology +
                "Date:        %s\n" % current_date +
                "Burp Ver:    %s\n\n" % burp_version +
                separator + "\n" +
                " " * ((80 - len("EXECUTIVE SUMMARY")) // 2) + "EXECUTIVE SUMMARY" + "\n" +
                separator + "\n" +
                "%s\n" % exec_summary
            )

            self.header_preview.setText(template)

        except Exception as e:
            self._callbacks.printError("Error updating header preview: %s" % str(e))

    def update_footer_preview(self):
        try:
            critical = self.footer_fields['Critical Findings'].getText()
            high = self.footer_fields['High Findings'].getText()
            medium = self.footer_fields['Medium Findings'].getText()
            low = self.footer_fields['Low Findings'].getText()
            conclusion = self.footer_fields['Conclusion'].getText()
            rec1 = self.footer_fields['Recommendation 1'].getText()
            rec2 = self.footer_fields['Recommendation 2'].getText()

            separator = "*" * 80

            template = (
                "\n\n" + separator + "\n" +
                " " * ((80 - len("VULNERABILITY STATISTICS")) // 2) + "VULNERABILITY STATISTICS" + "\n" +
                separator + "\n\n" +
                "Critical:  %s\n" % critical +
                "High:      %s\n" % high +
                "Medium:    %s\n" % medium +
                "Low:       %s\n\n" % low +
                separator + "\n" +
                " " * ((80 - len("CONCLUSION")) // 2) + "CONCLUSION" + "\n" +
                separator + "\n" +
                "%s\n\n" % conclusion +
                separator + "\n" +
                " " * ((80 - len("RECOMMENDATIONS")) // 2) + "RECOMMENDATIONS" + "\n" +
                separator + "\n" +
                "1. %s\n" % rec1 +
                "2. %s\n" % rec2
            )

            self.footer_preview.setText(template)

        except Exception as e:
            self._callbacks.printError("Error updating footer preview: %s" % str(e))

    def clear_current_tab(self, event):
        editor_data = self.get_current_editor_data()
        if not editor_data:
            return
            
        editor = editor_data['text_pane']
        doc = editor.getDocument()
        
        try:
            doc.remove(0, doc.getLength())
            
            JOptionPane.showMessageDialog(self._panel,
                                        "Current tab cleared successfully",
                                        "Clear Complete",
                                        JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            self._callbacks.printError("Error clearing tab: " + str(e))
            JOptionPane.showMessageDialog(self._panel,
                                        "Error clearing tab: %s" % str(e),
                                        "Clear Error",
                                        JOptionPane.ERROR_MESSAGE)

    def import_notes(self, event):
        chooser = JFileChooser()
        chooser.setFileFilter(FileNameExtensionFilter("Text files", ["txt"]))
        
        if chooser.showOpenDialog(self._panel) == JFileChooser.APPROVE_OPTION:
            try:
                editor_data = self.get_current_editor_data()
                if not editor_data:
                    return
                
                editor = editor_data['text_pane']
                file_path = chooser.getSelectedFile().getPath()
                with open(file_path, 'r') as f:
                    content = f.read()
                
                doc = editor.getDocument()
                doc.remove(0, doc.getLength())
                doc.insertString(0, content, None)
                editor_data['modified'] = False
                editor_data['file_path'] = file_path
                
                JOptionPane.showMessageDialog(self._panel,
                                            "Successfully imported from:\n%s" % file_path,
                                            "Import Complete",
                                            JOptionPane.INFORMATION_MESSAGE)
                
            except Exception as e:
                self._callbacks.printError("Import error: " + str(e))
                JOptionPane.showMessageDialog(self._panel,
                                            "Import error: %s" % str(e),
                                            "Import Error",
                                            JOptionPane.ERROR_MESSAGE)

    def duplicate_main_tab(self):
        main_editor_data = self.editor_data_map.get(self.main_tab_title)
        if not main_editor_data:
            return
            
        main_editor = main_editor_data['text_pane']
        main_doc = main_editor.getDocument()
        main_content = main_doc.getText(0, main_doc.getLength())
        
        new_tab_title = "Document " + str(self.tabbed_pane.getTabCount() + 1)
        new_editor = self.create_new_editor_tab(new_tab_title)
        
        new_doc = new_editor.getDocument()
        try:
            new_doc.insertString(0, main_content, None)
            self.editor_data_map.get(new_tab_title)['modified'] = True
        except:
            pass
            
    def insert_symbol(self, symbol):
        try:
            editor_data = self.get_current_editor_data()
            if editor_data:
                text_pane = editor_data['text_pane']  
                doc = text_pane.getDocument()  
                caret_position = text_pane.getCaretPosition()  

                attrs = SimpleAttributeSet()
                StyleConstants.setFontFamily(attrs, "Segoe UI Emoji, Segoe UI Symbol, DejaVu Sans, Arial Unicode MS")

                doc.insertString(caret_position, symbol, attrs)

        except Exception as e:
            self._callbacks.printError("Error inserting symbol: " + str(e))

    def create_new_editor_tab(self, title):
        panel = JPanel(BorderLayout())
        text_pane = JTextPane()
        text_pane.setFont(Font("Segoe UI Symbol, DejaVu Sans, Symbola, Arial Unicode MS", Font.PLAIN, 14))
        
        line_numbers = LineNumberView(text_pane)
        scroll_pane = JScrollPane(text_pane)
        scroll_pane.setRowHeaderView(line_numbers)
        panel.add(scroll_pane, BorderLayout.CENTER)

        if title != self.main_tab_title:
            close_button = JButton("X")
            close_button.setFont(Font("Arial", Font.BOLD, 14))
            close_button.setForeground(Color.RED)
            close_button.setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 5))
            close_button.setContentAreaFilled(False)
            close_button.setFocusPainted(False)
            close_button.addMouseListener(self.create_hover_listener(close_button))
            close_button.addActionListener(lambda e: self.close_tab(title))
            
            tab_header = JPanel(BorderLayout())
            tab_header.setOpaque(False)
            tab_header.add(JLabel(title), BorderLayout.CENTER)
            tab_header.add(close_button, BorderLayout.EAST)
            self.tabbed_pane.addTab(title, panel)
            self.tabbed_pane.setTabComponentAt(self.tabbed_pane.indexOfTab(title), tab_header)
        else:
            self.tabbed_pane.addTab(title, panel)

        class DocumentChangeListener(DocumentListener):
            def __init__(self, outer, title):
                self.outer = outer
                self.title = title
                
            def changedUpdate(self, e):
                self._handle_change()
                
            def insertUpdate(self, e):
                self._handle_change()
                
            def removeUpdate(self, e):
                self._handle_change()
                
            def _handle_change(self):
                editor_data = self.outer.editor_data_map.get(self.title)
                if editor_data:
                    editor_data['modified'] = True

        listener = DocumentChangeListener(self, title)
        text_pane.getDocument().addDocumentListener(listener)

        editor_data = {
            'text_pane': text_pane,
            'file_path': None,
            'modified': False,
            'listener': listener
        }
        self.editor_data_map.put(title, editor_data)
        
        return text_pane
    def create_hover_listener(self, button):
        class HoverListener(MouseAdapter):
            def mouseEntered(self, e):
                button.setContentAreaFilled(True)
                button.setBackground(Color(255, 200, 200))
                
            def mouseExited(self, e):
                button.setContentAreaFilled(False)
        
        return HoverListener()
    def close_tab(self, title):
        if title == self.main_tab_title:
            return
        
        index = self.tabbed_pane.indexOfTab(title)
        if index >= 0:
            editor_data = self.editor_data_map.get(title)
            if editor_data and editor_data['modified']:
                response = JOptionPane.showConfirmDialog(
                    self._panel,
                    "Tab has unsaved changes. Close anyway?",
                    "Confirm Close",
                    JOptionPane.YES_NO_OPTION
                )
                if response != JOptionPane.YES_OPTION:
                    return
            
            self.tabbed_pane.removeTabAt(index)
            self.editor_data_map.remove(title)
    def close_current_tab(self):
        current_index = self.tabbed_pane.getSelectedIndex()
        if current_index >= 0:
            title = self.tabbed_pane.getTitleAt(current_index)
            self.close_tab(title)
    def get_current_editor_data(self):
        current_idx = self.tabbed_pane.getSelectedIndex()
        if current_idx == -1:
            return None
            
        tab_title = self.tabbed_pane.getTitleAt(current_idx)
        return self.editor_data_map.get(tab_title)

    def getTabCaption(self):
        return "Notes Editor"

    def getUiComponent(self):
        return self._panel

    def createMenuItems(self, context_menu_info):
        menu_items = []
        
        selected_messages = context_menu_info.getSelectedMessages()
        if selected_messages and len(selected_messages) > 0:
            req_item = JMenuItem("Send Request to Notes Editor", 
                               actionPerformed=lambda e, s=selected_messages: 
                                   self.send_request_response(s[0], send_request=True))
            menu_items.append(req_item)
            
            resp_item = JMenuItem("Send Response to Notes Editor", 
                                actionPerformed=lambda e, s=selected_messages: 
                                    self.send_request_response(s[0], send_response=True))
            menu_items.append(resp_item)
            
            menu_items.append(None)
            
            both_item = JMenuItem("Send Request & Response to Notes Editor", 
                                actionPerformed=lambda e, s=selected_messages: 
                                    self.send_request_response(s[0], send_request=True, send_response=True))
            menu_items.append(both_item)
        
        return menu_items if menu_items else None

    def send_request_response(self, message, send_request=False, send_response=False):
        try:
            http_traffic = [message]
            if not http_traffic:
                return

            for traffic in http_traffic:
                response = traffic.getResponse() if send_response else None
                
                analysis = self._helpers.analyzeRequest(traffic)
                url = analysis.getUrl()
                
                request = traffic.getRequest() if send_request else None
                request_str = self._helpers.bytesToString(request) if request else None
                
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                note = [
                    "\n=== {} - Request ===".format(timestamp),
                    "URL: {}".format(url)
                ]
                
                if request_str:
                    note.append("Request:")
                    note.append(request_str)
                
                if response:
                    note.append("Response:")
                    note.append(self._helpers.bytesToString(response))
                
                self.append_to_editor("\n".join(note))
        
        except Exception as e:
            self._callbacks.printError("Error adding request/response to notes: " + str(e))

    def append_to_editor(self, note):
        editor_data = self.editor_data_map.get(self.main_tab_title)
        if not editor_data:
            return
            
        editor = editor_data['text_pane']
        doc = editor.getStyledDocument()
        
        try:
            current_length = doc.getLength()
            if current_length > 0:
                doc.insertString(current_length, "\n\n" + ("="*40) + "\n\n", None)
            
            doc.insertString(doc.getLength(), note, None)
            
            editor.setCaretPosition(doc.getLength())
        except Exception as e:
            self._callbacks.printError("Error displaying message: " + str(e))

    def save_to_file(self, event):
        try:
            editor_data = self.get_current_editor_data()
            if not editor_data:
                return
            
            editor = editor_data['text_pane']
            doc = editor.getDocument()
            text = doc.getText(0, doc.getLength())
            
            if not text.strip():
                JOptionPane.showMessageDialog(self._panel,
                                            "No content to Save!",
                                            "Save Error",
                                            JOptionPane.WARNING_MESSAGE)
                return
            
            file_chooser = JFileChooser()
            file_chooser.setDialogTitle("Save Document As")
            file_chooser.setSelectedFile(File("burp_notes.txt"))
            file_chooser.setFileFilter(FileNameExtensionFilter("Text files", ["txt"]))
            
            if file_chooser.showSaveDialog(self._panel) == JFileChooser.APPROVE_OPTION:
                file_path = file_chooser.getSelectedFile().getPath()
                if not file_path.lower().endswith('.txt'):
                    file_path += '.txt'
                
                writer = None
                try:
                    writer = BufferedWriter(FileWriter(File(file_path)))
                    writer.write(text)
                    writer.flush()
                    editor_data['modified'] = False
                    editor_data['file_path'] = file_path
                    JOptionPane.showMessageDialog(self._panel,
                                                "Successfully saved to:\n%s" % file_path,
                                                "Save Complete",
                                                JOptionPane.INFORMATION_MESSAGE)
                finally:
                    if writer:
                        writer.close()
                        
        except Exception as e:
            self._callbacks.printError("Error in save_to_file: %s" % str(e))
            JOptionPane.showMessageDialog(self._panel,
                                        "Error saving file: %s" % str(e),
                                        "Save Error",
                                        JOptionPane.ERROR_MESSAGE)

    def highlight_selected_text(self, event):
        editor_data = self.get_current_editor_data()
        if not editor_data:
            return
            
        editor = editor_data['text_pane']
        doc = editor.getStyledDocument()
        start = editor.getSelectionStart()
        end = editor.getSelectionEnd()
        
        if start != end:
            style = SimpleAttributeSet()
            StyleConstants.setForeground(style, Color.BLUE)
            StyleConstants.setBold(style, True)
            doc.setCharacterAttributes(start, end - start, style, False)
        else:
            System.out.println("No text selected for highlighting")