import re
import latex2mathml.converter
import lxml.etree as ET

xslt_path = r'C:\Program Files\Microsoft Office\Office15\MML2OMML.XSL'
xslt = ET.parse(xslt_path)
transform = ET.XSLT(xslt)

with open("Jishnu_Article_Readme.md", "r", encoding="utf-8") as f:
    text = f.read()

# Extract all block math $$...$$
block_matches = re.findall(r"\$\$(.*?)\$\$", text, re.DOTALL)
print(f"Testing {len(block_matches)} block equations...")

for idx, eq in enumerate(block_matches, 1):
    eq_clean = eq.strip()
    try:
        mathml = latex2mathml.converter.convert(eq_clean)
        dom = ET.fromstring(mathml)
        new_dom = transform(dom)
        root = new_dom.getroot()
        xml_str = ET.tostring(root).decode('utf-8')
        print(f"  [OK] Eq {idx}: length {len(eq_clean)} -> OMML len {len(xml_str)}")
    except Exception as e:
        print(f"  [FAIL] Eq {idx}: {e}")
        print(f"         Snippet: {eq_clean[:60]}...")
