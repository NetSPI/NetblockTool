from lxml.etree import tostring
import html

class TXTML:

  @classmethod
  def _clean_text_(cls, text):
    return text.replace('\n', '')

  @classmethod
  def get_document_type(cls, document):
    return document.getchildren()[0].text

  @classmethod
  def get_HTML_from_document(cls, document):
    properties = {}

    while document.tag != 'text':
      properties[document.tag] = cls._clean_text_(document.text)
      docs = document.getchildren()
      if docs:
        document = docs[0]
      else:
        break

    return document, properties

  @classmethod
  def parse_full_10K(cls, doc) -> str:
    text = ""
    for child in doc.getchildren():
      if child.tag == 'sec-header':
          continue
      html, properties = TXTML.get_HTML_from_document(child)
      if properties.get('type') and '10-K' in properties['type']:
        text = text + html.text_content()
    return text

  @classmethod
  def to_xml(cls, doc):
    return html.unescape(tostring(doc).decode("utf8"))

  @classmethod
  def to_xml_bytes(cls, doc):
    return html.unescape(tostring(doc).decode("utf8"))
