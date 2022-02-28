from typing import Dict, List
import re
from datetime import datetime
from lxml import etree

def findnth(haystack, needle, n):
  parts= haystack.split(needle, n+1)
  if len(parts)<=n+1:
      return -1
  return len(haystack)-len(parts[-1])-len(needle)

class XBRL(etree.ElementBase):

  def __init__(self, *children, attrib=None, nsmap=None, **_extra):
    super().__init__(*children, attrib=None, nsmap=None, **_extra)
    self.definitions = dict(
        (child.attrib["id"], self.__parse_context__(child)) for child in self.child.getchildren() if not isinstance(child, etree._Comment) and "context" in child.tag)
    self.relevant_children = [child for child in self.child.getchildren() if not isinstance(child, etree._Comment) and "context" not in child.tag]
    children = [child for child in self.child.getchildren() if XBRL.is_parsable(child)]
    for elem in children:
      XBRL.clean_tag(elem)

    self.relevant_children_parsed = children
    self.relevant_children_elements = [XBRLElement(child, context_ref=self.definitions[child.attrib["contextRef"]] if child.attrib.get("contextRef") else None) for child in children]

  def __parse_context__(self, context):
    children = [child for child in context.getchildren() if not isinstance(child, etree._Comment)]
    [XBRL.clean_tag(child) for child in children]
    period = [child for child in children if child.tag == 'period'][0]
    return {
        "period": self.__parse_base_elem__(period)
        }

  def __parse_base_elem__(self, elem):
    children = [child for child in elem.getchildren() if XBRL.is_parsable(child)]
    [XBRL.clean_tag(child) for child in children]
    return dict((child.tag, child.text) for child in children)

  @classmethod
  def is_parsable(cls, child):
    return not isinstance(child, etree._Comment) and "context" not in child.tag and "unit" not in child.tag and "schemaRef" not in child.tag

  @classmethod
  def clean_tag(cls, elem):
    """
    Parse tag so 
      {http://fasb.org/us-gaap/2018-01-31}Assets
    becomes
      Assets
    """
    elem.tag = elem.tag[elem.tag.find("}")+1:]

  @classmethod
  def parse_context_ref(cls, context_ref):
    """
    Duration_1_1_2018_To_12_31_2018 becomes 2018-01-01 to 2018-12-31
    As_Of_12_31_2017 becomes 2017-12-31
    """
    context_ref_to_date_text = lambda s: datetime.strptime(s, "%m_%d_%Y").date().strftime("%Y-%m-%d")
    if context_ref.startswith("Duration"):
      if len(context_ref.split("_")) <= 9:
        from_date = context_ref_to_date_text(context_ref[len("DURATION")+1:context_ref.find("_To_")])
        to_date = context_ref_to_date_text(context_ref[context_ref.find("_To_")+4:])
        return {"from": from_date, "to": to_date}
      else:
        from_date = context_ref_to_date_text(context_ref[len("DURATION")+1:context_ref.find("_To_")])
        end_idx = findnth(context_ref, "_", 7)+1
        to_date = context_ref_to_date_text(context_ref[context_ref.find("_To_")+4:end_idx-1])
        return {"from": from_date, "to": to_date}

    elif context_ref.startswith("As_Of"):
      if len(context_ref.split("_")) <= 5:
        return {"from": context_ref_to_date_text(context_ref[len("As_Of")+1:])}
      else:
        end_idx = findnth(context_ref, "_", 4)+1
        from_date = context_ref_to_date_text(context_ref[len("As_Of")+1:end_idx-1])
        return {"from": from_date}
    else:
      return {"other": context_ref.split("_")[0]}

  @property
  def child(self):
    return self.getchildren()[0]

  def find_relevant_elements_by_name(self, name):
    return [elem for elem in self.relevant_children_elements if name.lower() in elem.name.lower()]

  def match_relevant_elements_by_name(self, name):
    return [elem for elem in self.relevant_children_elements if name.lower() == elem.name.lower()]

class XBRLElement(etree.ElementBase):

  def __init__(self, *children, attrib=None, nsmap=None, context_ref=None, **_extra):
    super().__init__(*children, attrib=None, nsmap=None, **_extra)
    self.child = self.getchildren()[0]
    self.context_ref = context_ref
    self.name = ' '.join(re.findall('[A-Z][^A-Z]*', self.child.tag))
    self.unit_ref = self.attrib.get("unitRef") or None

  @property
  def attrib(self) -> Dict:
    return self.child.attrib

  @property
  def value(self) -> str:
    return self.child.text.replace("\n", "").strip() if self.child.text else ""

  def to_dict(self) -> Dict:
    if self.context_ref and self.context_ref.get("period"):
      return { **{
        "name": self.name,
        "value": self.value,
        "unit_ref": self.unit_ref
      }, **self.context_ref["period"]}
    else:
      return {
        "name": self.name,
        "value": self.value,
        "unit_ref": self.unit_ref
      }

  def __repr__(self):
    return f'<{self.name}="{self.value} {self.unit_ref}" context_ref={self.context_ref}>'
