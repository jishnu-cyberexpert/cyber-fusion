import re
import latex2mathml.converter
import lxml.etree as ET

xslt_path = r'C:\Program Files\Microsoft Office\Office15\MML2OMML.XSL'
xslt = ET.parse(xslt_path)
transform = ET.XSLT(xslt)

with open("Jishnu_Article_Readme.md", "r", encoding="utf-8") as f:
    text = f.read()

# Find all inline $...$
inline_matches = re.findall(r"(?<!\$)\$(?!\$)(.*?)(?<!\$)\$(?!\$)", text)
print(f"Testing {len(inline_matches)} inline equations...")

failures = 0
for idx, eq in enumerate(inline_matches, 1):
    eq_clean = eq.strip()
    try:
        mathml = latex2mathml.converter.convert(eq_clean)
        dom = ET.fromstring(mathml)
        new_dom = transform(dom)
        root = new_dom.getroot()
        xml_str = ET.tostring(root).decode('utf-8')
    except Exception as e:
        failures += 1
        print(f"  [FAIL] Inline {idx}: '{eq_clean}' -> {e}")

print(f"Total inline tested: {len(inline_matches)}, Failures: {failures}")
