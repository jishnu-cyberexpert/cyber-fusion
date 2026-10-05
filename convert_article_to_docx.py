import os
import re
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn
import latex2mathml.converter
import lxml.etree as ET

# Load MML2OMML.XSL from standard Microsoft Office path
XSLT_PATH = r"C:\Program Files\Microsoft Office\Office15\MML2OMML.XSL"
if not os.path.exists(XSLT_PATH):
    # Check alternate Office paths if any
    alt_paths = [
        r"C:\Program Files (x86)\Microsoft Office\Office15\MML2OMML.XSL",
        r"C:\Program Files\Microsoft Office\root\Office16\MML2OMML.XSL"
    ]
    for ap in alt_paths:
        if os.path.exists(ap):
            XSLT_PATH = ap
            break

print(f"Using Math XSLT transform from: {XSLT_PATH}")
xslt_doc = ET.parse(XSLT_PATH)
xslt_transform = ET.XSLT(xslt_doc)

def latex_to_omml_element(latex_str, is_inline=True):
    """Convert LaTeX formula to native Word OMML XML element."""
    clean_latex = latex_str.strip()
    # Normalize common LaTeX artifacts
    clean_latex = clean_latex.replace(r"\textasciicircum", "^")
    
    try:
        mathml = latex2mathml.converter.convert(clean_latex)
        dom = ET.fromstring(mathml)
        new_dom = xslt_transform(dom)
        root = new_dom.getroot()
        xml_str = ET.tostring(root).decode('utf-8')
        if xml_str.startswith("<?xml"):
            xml_str = xml_str.split("?>", 1)[1].strip()
            
        if is_inline:
            return parse_xml(xml_str)
        else:
            wrapped = f'<m:oMathPara xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math">{xml_str}</m:oMathPara>'
            return parse_xml(wrapped)
    except Exception as e:
        print(f"[MATH PARSE ERROR] '{clean_latex[:40]}...': {e}")
        return None

# Color palette: IEEE Academic & CyberFusion Executive
COLOR_PRIMARY = RGBColor(15, 41, 66)       # Deep Navy
COLOR_SECONDARY = RGBColor(30, 58, 138)   # Royal Blue
COLOR_ACCENT = RGBColor(2, 132, 199)      # Sky Blue
COLOR_TEXT_MAIN = RGBColor(30, 41, 59)    # Slate 800
COLOR_TEXT_MUTED = RGBColor(100, 116, 139) # Slate 500
COLOR_CODE = RGBColor(190, 24, 93)        # Rose 700
COLOR_BORDER = "CBD5E1"                   # Slate 300
HEX_TABLE_HEADER = "1E3A8A"               # Deep Navy
HEX_ROW_ALT = "F8FAFC"                    # Slate 50
HEX_CODE_BG = "F1F5F9"                    # Slate 100

FONT_SERIF = "Times New Roman"
FONT_MONO = "Consolas"

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=140, right=140):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tcPr.append(tcMar)

def set_table_borders(table, color=COLOR_BORDER, sz="4"):
    tblPr = table._tbl.tblPr
    borders = parse_xml(
        f'<w:tblBorders {nsdecls("w")}>'
        f'<w:top w:val="single" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'<w:bottom w:val="single" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'<w:left w:val="none"/>'
        f'<w:right w:val="none"/>'
        f'<w:insideH w:val="single" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'<w:insideV w:val="none"/>'
        f'</w:tblBorders>'
    )
    tblPr.append(borders)

def add_header_footer(doc):
    for section in doc.sections:
        # Header
        header = section.header
        hp = header.paragraphs[0]
        hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        hrun = hp.add_run("CyberFusion: Enterprise Endpoint Security via Adaptive Baselining | IEEE Research Manuscript")
        hrun.font.name = FONT_SERIF
        hrun.font.size = Pt(8.5)
        hrun.font.italic = True
        hrun.font.color.rgb = COLOR_TEXT_MUTED
        
        # Footer
        footer = section.footer
        fp = footer.paragraphs[0]
        fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        frun = fp.add_run("Department of Computer Science & Engineering — CyberFusion Research Report")
        frun.font.name = FONT_SERIF
        frun.font.size = Pt(8.5)
        frun.font.color.rgb = COLOR_TEXT_MUTED

def add_formatted_content(paragraph, text, default_color=COLOR_TEXT_MAIN, font_size=Pt(10.5), is_bold=False, is_italic=False):
    """Tokenize markdown text and insert runs or native OMML equations directly into paragraph."""
    token_pattern = re.compile(
        r'(\[.*?\]\(.*?\)|\*\*.*?\*\*|\*.*?\*|`.*?`|\$.*?\$)'
    )
    parts = token_pattern.split(text)
    for part in parts:
        if not part:
            continue
        
        # Inline Math: $...$
        if part.startswith("$") and part.endswith("$") and len(part) >= 2:
            math_text = part[1:-1].strip()
            omml_elem = latex_to_omml_element(math_text, is_inline=True)
            if omml_elem is not None:
                paragraph._p.append(omml_elem)
            else:
                # Fallback to styled text run if OMML conversion failed
                run = paragraph.add_run(math_text)
                run.font.name = "Cambria Math"
                run.font.size = font_size
                run.font.italic = True
                run.font.color.rgb = RGBColor(15, 23, 42)
        # Bold: **...**
        elif part.startswith("**") and part.endswith("**") and len(part) >= 4:
            run = paragraph.add_run(part[2:-2])
            run.font.name = FONT_SERIF
            run.font.size = font_size
            run.font.bold = True
            run.font.italic = is_italic
            run.font.color.rgb = default_color
        # Italic: *...*
        elif part.startswith("*") and part.endswith("*") and len(part) >= 2:
            run = paragraph.add_run(part[1:-1])
            run.font.name = FONT_SERIF
            run.font.size = font_size
            run.font.italic = True
            run.font.bold = is_bold
            run.font.color.rgb = default_color
        # Inline code: `...`
        elif part.startswith("`") and part.endswith("`") and len(part) >= 2:
            run = paragraph.add_run(part[1:-1])
            run.font.name = FONT_MONO
            run.font.size = Pt(9.5)
            run.font.color.rgb = COLOR_CODE
        # Markdown Link: [text](url)
        elif part.startswith("[") and "](" in part and part.endswith(")"):
            m = re.match(r'\[(.*?)\]\((.*?)\)', part)
            if m:
                run = paragraph.add_run(m.group(1))
                run.font.name = FONT_SERIF
                run.font.size = font_size
                run.font.color.rgb = COLOR_ACCENT
                run.underline = True
            else:
                run = paragraph.add_run(part)
                run.font.name = FONT_SERIF
                run.font.size = font_size
                run.font.color.rgb = default_color
        else:
            run = paragraph.add_run(part)
            run.font.name = FONT_SERIF
            run.font.size = font_size
            run.font.bold = is_bold
            run.font.italic = is_italic
            run.font.color.rgb = default_color

def build_docx(md_path, docx_path):
    print(f"Loading markdown content from: {md_path}")
    with open(md_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    doc = docx.Document()

    # IEEE Standard Page Setup: Letter, 1-inch margins
    for section in doc.sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)
        section.page_width = Inches(8.5)
        section.page_height = Inches(11.0)

    add_header_footer(doc)

    # Base Normal Style
    normal_style = doc.styles['Normal']
    normal_style.font.name = FONT_SERIF
    normal_style.font.size = Pt(10.5)
    normal_style.font.color.rgb = COLOR_TEXT_MAIN
    normal_style.paragraph_format.line_spacing = 1.15
    normal_style.paragraph_format.space_after = Pt(4)

    i = 0
    n = len(lines)

    in_code_block = False
    code_block_lines = []

    in_table_block = False
    table_lines = []

    while i < n:
        line = lines[i]
        raw = line.rstrip("\r\n")
        stripped = raw.strip()

        # Handle Fenced Code Blocks: ``` ... ```
        if stripped.startswith("```"):
            if in_code_block:
                in_code_block = False
                p = doc.add_paragraph()
                p.paragraph_format.left_indent = Inches(0.2)
                p.paragraph_format.right_indent = Inches(0.2)
                p.paragraph_format.space_before = Pt(4)
                p.paragraph_format.space_after = Pt(6)
                p.paragraph_format.line_spacing = 1.05
                
                code_text = "\n".join(code_block_lines)
                if code_text.strip().startswith("TABLE "):
                    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    run = p.add_run(code_text.strip())
                    run.font.name = FONT_SERIF
                    run.font.size = Pt(9.5)
                    run.font.bold = True
                    run.font.color.rgb = COLOR_PRIMARY
                elif code_text.strip().startswith("[1]") or code_text.strip().startswith("[19]"):
                    for ref_line in code_block_lines:
                        if not ref_line.strip():
                            continue
                        ref_p = doc.add_paragraph()
                        ref_p.paragraph_format.left_indent = Inches(0.3)
                        ref_p.paragraph_format.first_line_indent = Inches(-0.3)
                        ref_p.paragraph_format.space_after = Pt(3)
                        ref_p.paragraph_format.line_spacing = 1.1
                        add_formatted_content(ref_p, ref_line.strip(), font_size=Pt(9.0))
                else:
                    table_box = doc.add_table(rows=1, cols=1)
                    table_box.alignment = WD_TABLE_ALIGNMENT.CENTER
                    cell = table_box.rows[0].cells[0]
                    set_cell_background(cell, HEX_CODE_BG)
                    set_cell_margins(cell, top=80, bottom=80, left=120, right=120)
                    
                    cp = cell.paragraphs[0]
                    cp.paragraph_format.line_spacing = 1.0
                    cp.paragraph_format.space_after = Pt(0)
                    for c_idx, cl in enumerate(code_block_lines):
                        c_run = cp.add_run(cl + ("\n" if c_idx < len(code_block_lines) - 1 else ""))
                        c_run.font.name = FONT_MONO
                        c_run.font.size = Pt(8.5)
                        c_run.font.color.rgb = RGBColor(30, 41, 59)
                
                code_block_lines = []
                i += 1
                continue
            else:
                in_code_block = True
                code_block_lines = []
                i += 1
                continue

        if in_code_block:
            code_block_lines.append(raw)
            i += 1
            continue

        # Handle Markdown Tables: lines starting with '|'
        if stripped.startswith("|"):
            table_lines.append(stripped)
            i += 1
            if i < n and lines[i].strip().startswith("|"):
                continue
            else:
                if len(table_lines) >= 2:
                    rows_data = []
                    for t_line in table_lines:
                        cells = [c.strip() for c in t_line.split("|")[1:-1]]
                        if all(re.match(r'^:?-+:?$', c) for c in cells if c):
                            continue
                        rows_data.append(cells)
                    
                    if rows_data:
                        n_rows = len(rows_data)
                        n_cols = max(len(r) for r in rows_data)
                        
                        tbl = doc.add_table(rows=n_rows, cols=n_cols)
                        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
                        set_table_borders(tbl, color="CBD5E1", sz="4")
                        
                        for r_idx, r_data in enumerate(rows_data):
                            row = tbl.rows[r_idx]
                            is_header = (r_idx == 0)
                            
                            for c_idx in range(n_cols):
                                cell = row.cells[c_idx]
                                cell_val = r_data[c_idx] if c_idx < len(r_data) else ""
                                cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
                                
                                if is_header:
                                    set_cell_background(cell, HEX_TABLE_HEADER)
                                    set_cell_margins(cell, top=100, bottom=100, left=120, right=120)
                                    cp = cell.paragraphs[0]
                                    cp.alignment = WD_ALIGN_PARAGRAPH.CENTER
                                    cp.paragraph_format.space_after = Pt(0)
                                    cp.paragraph_format.line_spacing = 1.05
                                    add_formatted_content(cp, cell_val, default_color=RGBColor(255, 255, 255),
                                                          font_size=Pt(9.0), is_bold=True)
                                else:
                                    bg_color = HEX_ROW_ALT if (r_idx % 2 == 1) else "FFFFFF"
                                    set_cell_background(cell, bg_color)
                                    set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
                                    cp = cell.paragraphs[0]
                                    cp.paragraph_format.space_after = Pt(0)
                                    cp.paragraph_format.line_spacing = 1.05
                                    
                                    if len(cell_val) <= 10 and not any(w in cell_val for w in ["Conf", "Rule"]):
                                        cp.alignment = WD_ALIGN_PARAGRAPH.CENTER
                                    else:
                                        cp.alignment = WD_ALIGN_PARAGRAPH.LEFT
                                    
                                    add_formatted_content(cp, cell_val, default_color=COLOR_TEXT_MAIN, font_size=Pt(8.5))
                        
                        p_space = doc.add_paragraph()
                        p_space.paragraph_format.space_before = Pt(4)
                        p_space.paragraph_format.space_after = Pt(4)
                
                table_lines = []
                continue

        # Skip empty lines
        if not stripped:
            i += 1
            continue

        # Horizontal rule: ---
        if stripped == "---":
            i += 1
            continue

        # Heading 1: # ...
        if stripped.startswith("# ") and not stripped.startswith("## "):
            h_text = stripped[2:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(16)
            p.paragraph_format.space_after = Pt(6)
            p.paragraph_format.keep_with_next = True
            
            if not any(h_text.startswith(x) for x in ["I.", "II.", "III.", "IV.", "V.", "VI.", "VII.", "VIII.", "IX.", "X.", "XI.", "XII.", "XIII.", "XIV.", "XV.", "XVI.", "XVII.", "XVIII.", "XIX.", "XX.", "XXI.", "XXII.", "REFERENCES"]):
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                run = p.add_run(h_text)
                run.font.name = FONT_SERIF
                run.font.size = Pt(18)
                run.font.bold = True
                run.font.color.rgb = COLOR_PRIMARY
            else:
                p.alignment = WD_ALIGN_PARAGRAPH.LEFT
                run = p.add_run(h_text)
                run.font.name = FONT_SERIF
                run.font.size = Pt(13)
                run.font.bold = True
                run.font.color.rgb = COLOR_PRIMARY
            
            i += 1
            continue

        # Heading 2: ## ...
        if stripped.startswith("## "):
            h_text = stripped[3:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(12)
            p.paragraph_format.space_after = Pt(4)
            p.paragraph_format.keep_with_next = True
            
            if h_text.upper() in ["ABSTRACT", "INDEX TERMS", "EXECUTIVE SUMMARY & METADATA"]:
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                run = p.add_run(h_text.upper())
                run.font.name = FONT_SERIF
                run.font.size = Pt(11)
                run.font.bold = True
                run.font.color.rgb = COLOR_SECONDARY
            else:
                p.alignment = WD_ALIGN_PARAGRAPH.LEFT
                run = p.add_run(h_text)
                run.font.name = FONT_SERIF
                run.font.size = Pt(11.5)
                run.font.bold = True
                run.font.color.rgb = COLOR_SECONDARY
            
            i += 1
            continue

        # Heading 3: ### ...
        if stripped.startswith("### "):
            h_text = stripped[4:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(10)
            p.paragraph_format.space_after = Pt(3)
            p.paragraph_format.keep_with_next = True
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT
            run = p.add_run(h_text)
            run.font.name = FONT_SERIF
            run.font.size = Pt(10.5)
            run.font.bold = True
            run.font.italic = True
            run.font.color.rgb = COLOR_PRIMARY
            i += 1
            continue

        # Display Math Block: $$ ... $$ -> Rendered as native Word OMML equation!
        if stripped.startswith("$$") and stripped.endswith("$$") and len(stripped) >= 4:
            math_expr = stripped[2:-2].strip()
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(8)
            p.paragraph_format.space_after = Pt(8)
            
            omml_block = latex_to_omml_element(math_expr, is_inline=False)
            if omml_block is not None:
                p._p.append(omml_block)
            else:
                run = p.add_run(math_expr)
                run.font.name = "Cambria Math"
                run.font.size = Pt(11)
                run.font.italic = True
            i += 1
            continue

        # Image embed: ![alt](path)
        img_match = re.match(r'!\[(.*?)\]\((.*?)\)', stripped)
        if img_match:
            img_rel_path = img_match.group(2)
            if img_rel_path.startswith("./"):
                img_rel_path = img_rel_path[2:]
            
            img_abs_path = os.path.abspath(img_rel_path)
            if os.path.exists(img_abs_path):
                p_img = doc.add_paragraph()
                p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
                p_img.paragraph_format.space_before = Pt(10)
                p_img.paragraph_format.space_after = Pt(2)
                p_img.paragraph_format.keep_with_next = True
                
                if "fig1" in img_abs_path.lower():
                    p_img.add_run().add_picture(img_abs_path, width=Inches(6.5))
                elif "fig4" in img_abs_path.lower() or "fig3" in img_abs_path.lower():
                    p_img.add_run().add_picture(img_abs_path, width=Inches(5.8))
                else:
                    p_img.add_run().add_picture(img_abs_path, width=Inches(5.2))
            else:
                print(f"[WARNING] Image path not found: {img_abs_path}")
            
            i += 1
            continue

        # Italic Figure Caption: *Fig. X. ...*
        if stripped.startswith("*Fig.") or stripped.startswith("*Table") or stripped.startswith("*Editorial Note:"):
            p_cap = doc.add_paragraph()
            p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p_cap.paragraph_format.space_before = Pt(2)
            p_cap.paragraph_format.space_after = Pt(8)
            cap_text = stripped.strip("*").strip()
            add_formatted_content(p_cap, cap_text, default_color=COLOR_TEXT_MUTED, font_size=Pt(9.0), is_italic=True)
            i += 1
            continue

        # Bullet List Item: - ... or * ...
        if stripped.startswith("- ") or (stripped.startswith("* ") and not stripped.endswith("*")):
            bullet_text = stripped[2:].strip()
            p_b = doc.add_paragraph()
            p_b.paragraph_format.left_indent = Inches(0.25)
            p_b.paragraph_format.space_after = Pt(3)
            p_b.paragraph_format.line_spacing = 1.12
            
            r_sym = p_b.add_run("•  ")
            r_sym.font.name = FONT_SERIF
            r_sym.font.size = Pt(10)
            r_sym.font.bold = True
            r_sym.font.color.rgb = COLOR_SECONDARY
            
            add_formatted_content(p_b, bullet_text, default_color=COLOR_TEXT_MAIN, font_size=Pt(10.0))
            i += 1
            continue

        # Numbered List Item: 1. ...
        num_match = re.match(r'^(\d+\.)\s+(.*)$', stripped)
        if num_match:
            num_str = num_match.group(1)
            item_text = num_match.group(2)
            
            p_num = doc.add_paragraph()
            p_num.paragraph_format.left_indent = Inches(0.25)
            p_num.paragraph_format.space_after = Pt(3)
            p_num.paragraph_format.line_spacing = 1.12
            
            r_num = p_num.add_run(num_str + "  ")
            r_num.font.name = FONT_SERIF
            r_num.font.size = Pt(10)
            r_num.font.bold = True
            r_num.font.color.rgb = COLOR_SECONDARY
            
            add_formatted_content(p_num, item_text, default_color=COLOR_TEXT_MAIN, font_size=Pt(10.0))
            i += 1
            continue

        # Standard Paragraph
        p_para = doc.add_paragraph()
        if stripped.startswith("**Author:**") or stripped.startswith("**Affiliation:**") or stripped.startswith("**Target Publication Scope:**"):
            p_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p_para.paragraph_format.space_after = Pt(2)
            add_formatted_content(p_para, stripped, font_size=Pt(10.0))
        elif i > 15 and i < 35 and not stripped.startswith("#"):
            p_para.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            p_para.paragraph_format.left_indent = Inches(0.3)
            p_para.paragraph_format.right_indent = Inches(0.3)
            p_para.paragraph_format.space_after = Pt(6)
            p_para.paragraph_format.line_spacing = 1.15
            add_formatted_content(p_para, stripped, font_size=Pt(9.5))
        else:
            p_para.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            p_para.paragraph_format.space_after = Pt(4)
            p_para.paragraph_format.line_spacing = 1.15
            add_formatted_content(p_para, stripped, font_size=Pt(10.0))

        i += 1

    print(f"Saving compiled document to: {docx_path}")
    doc.save(docx_path)
    print(f"[OK] Document successfully generated: {docx_path}")

def convert_to_pdf_via_word(docx_path, pdf_path):
    print("Exporting Word Document to PDF via native MS Word COM...")
    try:
        import win32com.client
        import pythoncom
        pythoncom.CoInitialize()
        
        word = win32com.client.DispatchEx("Word.Application")
        word.Visible = False
        word.DisplayAlerts = False
        
        abs_docx = os.path.abspath(docx_path)
        abs_pdf = os.path.abspath(pdf_path)
        
        doc = word.Documents.Open(abs_docx)
        doc.SaveAs(abs_pdf, FileFormat=17) # wdFormatPDF = 17
        doc.Close()
        word.Quit()
        pythoncom.CoUninitialize()
        print(f"[OK] PDF successfully generated: {abs_pdf}")
        return True
    except Exception as e:
        print(f"[WARNING] Word COM PDF export failed: {e}")
        return False

if __name__ == "__main__":
    src_md = "Jishnu_Article_Readme.md"
    out_docx = "Jishnu_Article_Readme.docx"
    out_pdf = "Jishnu_Article_Readme.pdf"
    
    build_docx(src_md, out_docx)
    convert_to_pdf_via_word(out_docx, out_pdf)
