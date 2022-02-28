import requests
from lxml import html

class Document:

  def __init__(self, url, user_agent, timeout=10):
    self.url = url
    self.user_agent = user_agent
    self.text = requests.get(self.url, timeout=timeout, headers={'User-Agent':self.user_agent}).content

class Documents(str):

  def __get_text_from_list__(self, arr):
    return [val.text_content() for val in arr]

  def __init__(self, url, user_agent, timeout=10):
    self.url = url
    self.user_agent = user_agent
    page = requests.get(self.url, timeout=timeout, headers={'User-Agent':self.user_agent})
    tree = html.fromstring(page.content)
    content = tree.find_class("formContent")[0]
    info_head = self.__get_text_from_list__(content.find_class("infoHead"))
    info = self.__get_text_from_list__(content.find_class("info"))
    self.content = dict(zip(info_head, info))
    self.element = html.fromstring(requests.get(self.url, timeout=timeout).content, headers={'User-Agent':self.user_agent})

  def __repr__(self):
    return str(self.__dict__)

  def __str__(self):
    return str(self.__dict__)
