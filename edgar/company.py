from typing import List
import os
import requests
from lxml import html, etree
from .document import Documents
import lxml

BASE_URL = "https://www.sec.gov"

class Company():

    def __init__(self, name, cik, user_agent, timeout=10):
        self.name = name
        self.cik = cik
        self.url = f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}"
        self.timeout = timeout
        self._document_urls = []
        self.user_agent = user_agent
        self.get_company_info()

    @property
    def document_urls(self):
      return list(set(self._document_urls))

    def _get(self, url):
      return requests.get(url, timeout=self.timeout, headers={'User-Agent':self.user_agent})

    def get_company_info(self):
        page = html.fromstring(self._get(self.url).content)
        companyInfo = page.xpath("//div[@class='companyInfo']")[0] if page.xpath("//div[@class='companyInfo']") else None
        if companyInfo is not None:
          indentInfo = companyInfo.getchildren()[1]
          self.sic = indentInfo.getchildren()[1].text if len(indentInfo.getchildren()) > 2 else ""
          self.us_state = indentInfo.getchildren()[3].text if len(indentInfo.getchildren()) > 4 else ""

        self._document_urls = [ BASE_URL + elem.attrib["href"]
            for elem in page.xpath("//*[@id='documentsbutton']") if elem.attrib.get("href")]

    def get_filings_url(self, filing_type="", prior_to="", ownership="include", no_of_entries=100) -> str:
        url = self.url + "&type=" + filing_type + "&dateb=" + prior_to + "&owner=" +  ownership + "&count=" + str(no_of_entries)
        return url

    def get_all_filings(self, filing_type="", prior_to="", ownership="include", no_of_entries=100) -> lxml.html.HtmlElement:
      url = self.get_filings_url(filing_type, prior_to, ownership, no_of_entries)
      page = self._get(url)
      return html.fromstring(page.content)

    def _group_document_type(self, tree, document_type):
      result = []
      grouped = []
      for i, elem in enumerate(tree.xpath('//*[@id="seriesDiv"]/table/tr')):
        if i == 0:
          continue
        url = elem.xpath("td")[1].getchildren()[0].attrib["href"]
        grouped.append(url)
        if elem.xpath("td")[0].text == document_type:
          result.append(grouped)
          grouped = []
      return result

    def get_document_type_from_10K(self, document_type, no_of_documents=1) -> List[lxml.html.HtmlElement]:
      tree = self.get_all_filings(filing_type="10-K")
      url_groups = self._group_document_type(tree, "10-K")[:no_of_documents]
      result = []
      for url_group in url_groups:
        for url in url_group:
          url = BASE_URL + url
          self._document_urls.append(url)
          content_page = Company.get_request(url)
          table = content_page.find_class("tableFile")[0]
          for row in table.getchildren():
            if document_type in row.getchildren()[3].text:
              href = row.getchildren()[2].getchildren()[0].attrib["href"]
              href = BASE_URL + href
              href = href.replace("ix?doc=/", "") # required for new iXBRL to HTML
              if len(href.split("/")[-1].split(".")) == 1:
                continue
              doc = Company.get_request(href)
              result.append(doc)
      return result

    def get_data_files_from_10K(self, document_type, no_of_documents=1, isxml=False) -> List[lxml.html.HtmlElement]:
      tree = self.get_all_filings(filing_type="10-K")
      url_groups = self._group_document_type(tree, "10-K")[:no_of_documents]
      result = []
      for url_group in url_groups:
        for url in url_group:
          url = BASE_URL + url
          self._document_urls.append(url)
          content_page = Company.get_request(url)
          tableFile = content_page.find_class("tableFile")
          if len(tableFile) < 2:
            continue
          table = tableFile[1]
          for row in table.getchildren():
            if document_type in row.getchildren()[3].text:
              href = row.getchildren()[2].getchildren()[0].attrib["href"]
              href = BASE_URL + href
              doc = Company.get_request(href, isxml=isxml)
              result.append(doc)
      return result

    @classmethod
    def __get_documents_from_element__(cls, elem, as_documents=False):
      url = BASE_URL + elem.attrib["href"]
      if as_documents:
        return Documents(url)
      else:
        content_page = Company.get_request(url)
        table = content_page.find_class("tableFile")[0]
        last_row = table.getchildren()[-1]
        href = last_row.getchildren()[2].getchildren()[0].attrib["href"]
        href = BASE_URL + href
        return Company.get_request(href)

    def get_10Ks(self, no_of_documents=1, as_documents=False) -> List[lxml.html.HtmlElement]:
      tree = self.get_all_filings(filing_type="10-K")
      elems = tree.xpath('//*[@id="documentsbutton"]')[:no_of_documents]
      result = []
      for elem in elems:
          doc = Company.__get_documents_from_element__(elem, as_documents=as_documents)
          result.append(doc)
      return result

    def get_10K(self) -> List[lxml.html.HtmlElement]:
      return self.get_10Ks(no_of_documents=1)[0]

    @classmethod
    def get_request(cls, href, isxml=False, timeout=10):
        #print(dir(cls.__class__.__getattribute__.classAttr))
        page = requests.get(href, timeout=timeout, headers={'User-Agent': 'Testing Testing test@example.com'})
        if isxml:
          p = etree.XMLParser(huge_tree=True)
          return etree.fromstring(page.content, parser=p)
        else:
          return html.fromstring(page.content)

    @classmethod
    def get_documents(cls, tree: html.HtmlElement, no_of_documents=1, debug=False, as_documents=False) -> List:
        elems = tree.xpath('//*[@id="documentsbutton"]')[:no_of_documents]
        result = []
        for elem in elems:
            filing = Company.__get_documents_from_element__(elem, as_documents=as_documents)
            result.append(filing)

        if len(result) == 1:
            return result[0]
        return result

    @classmethod
    def get_CIK_from_company(cls, company_name):
        tree = cls.get_request("https://www.sec.gov/cgi-bin/browse-edgar?company=" + company_name)
        CIKList = tree.xpath('//*[@id="seriesDiv"]/table/tr[*]/td[1]/a/text()')
        names_list = []
        for elem in tree.xpath('//*[@id="seriesDiv"]/table/tr[*]/td[2]'):
            names_list.append(elem.text_content())
        return list(zip(CIKList, names_list))
