import pytest
import re
from solution import Sacumen

class TestSolution:

#This method will check if the input string is empty 
    def test_empty(self):
        input_data_empty = ""
        final_result_empty = "Input data is empty"     
        obj1 = Sacumen(input_data_empty).dictlog()
        assert obj1 == final_result_empty

#This method will check if the format of the string is correct and there is no data 
    def test_format_emptydata(self):
        data = "SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|asndlkaslkasn"
        result= {}
        expression = re.search(".+\|$",data)
        obj1 = Sacumen(data).dictlog()
        if(expression):           
                assert obj1 == result
        else:
            result="Data Format is in-correct"
            assert obj1 == result

#This method will check if the format of the string is correct with correct format data 
    def test_format(self):
        data = "SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1"
        result = {
            'cat': 'C2', 
            'cs1Label': 'subcat', 
            'cs1': 'DNS_TUNNELING', 
            'cs2Label': 'vueUrls', 
            'cs2': 'https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650', 
            'cs3Label': 'Tags', 
            'cs3': 'USA,Finance', 
            'cs4Label': 'Url', 
            'cs4': 'https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323', 
            'cn1Label': 'severityScore', 
            'cn1': '900', 
            'msg': 'Malicious activity was reported in CAAS\\= A threat intelligence rule has been automatically created in DAAS.', 
            'dhost': 'bad.com', 
            'dst': '1.1.1.1'
            }
           
        obj1 = Sacumen(data).dictlog()
        assert obj1 == result

#This method will check if the format of another string is correct with correct format data 
    def test_format2(self):
        data = "SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|Medium|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%356780 cs3Label=Tags cs3=Canada,Accounts cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=987683 cn1Label=severityScore cn1=500 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.0.0.1"
        result = {
            'cat': 'C2',
            'cs1Label': 'subcat', 
            'cs1': 'DNS_TUNNELING', 
            'cs2Label': 'vueUrls', 
            'cs2': 'https://aws-dev.sacdev.io/alerts?filter=alertId%3D%356780', 
            'cs3Label': 'Tags', 
            'cs3': 'Canada,Accounts', 
            'cs4Label': 'Url', 
            'cs4': 'https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=987683', 
            'cn1Label': 'severityScore', 
            'cn1': '500', 
            'msg': 'Malicious activity was reported in CAAS\\= A threat intelligence rule has been automatically created in DAAS.', 
            'dhost': 'bad.com', 
            'dst': '1.0.0.1'
            }
           
        obj1 = Sacumen(data).dictlog()
        assert obj1 == result
#This method will check if the format of the string is in-correct      
    def test_negative_format(self):
        data = "The format of the string is not correct"
        expression= re.findall("[^.+\|[a-zA-Z]+\=.+\s]",data) #invalid format 
        if(expression):
            result="Data Format is in-correct"
            obj1 = Sacumen(data).dictlog()
            assert obj1 == result 

        
    

 