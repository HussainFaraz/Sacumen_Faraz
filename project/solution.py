import re


#creating custom exception classes to handle the 'Empty string' and 'Invalid format' in the input string
class EmptyStringException(Exception):
    pass
class InvalidFormatException(Exception):
    pass

class Sacumen:
    def __init__(self,data):
        self.data = data
    
    def dictlog(self):
        list_index_of_pipeline = []                                        #this list will contain the index of all the pipelines(|) in the string
        final_list=[]                                                      
        final_dict = {}                                                    #this dict will hold the final value
        expression_data= re.search(".+\|[a-zA-Z]+\=.+\s",self.data)        #checking the format of the input string
        expression_no_data = re.search(".+\|$",self.data)                  #checking the format of the input string but there is no data after the last pipeline(|)
        try:
            #this if block will raise the EmptyString Exception if the input string is empty
            if(len(self.data)==0):     
                raise EmptyStringException()
            
            #this if block will return the empty dictionary if there is no data after the last pipeline (|)
            if(expression_no_data):
                return final_dict

            #this if block will raise the Invalid format Exception if the input string is not in the correct format
            elif(not expression_data):
                raise InvalidFormatException
           
            #else block will take care if the input string is having data and is in a correct format
            else:
                for index in range(0,len(self.data)):
                    if(self.data[index] == "|"):
                        list_index_of_pipeline.append(index)
        
                index_of_vertical_bar= max(list_index_of_pipeline)       #Index of last "|" so that we can make a substring as
                                                                         #the main pattern starts after the last pipeline |

                temp_data = self.data[index_of_vertical_bar+1:]          #creating a substring such that pipelines are eradicated from the string



                msg_span  = re.search("msg=.+\.\s",temp_data)           
                if(not msg_span):                                       #checks if there is a 'msg' block in the string
                    raise InvalidFormatException
        
                # Dividing string into three sections - first,msg and rest
                first= temp_data[:msg_span.start()].strip()         #this holds the value before the "msg" section
                msg  = temp_data[msg_span.start():msg_span.end()]   # this holds the value of msg piece
                rest = temp_data[msg_span.end():]                   #this holds the value of rest of the string


                f = re.split("\s",first)                            #splitting based on space as per the pattern requirement
                s = re.findall("msg=.+\.\s",temp_data)              #msg
                t= re.split("\s",rest)                              #splitting based on space as per the pattern requirement
                final_list = f+s+t                
                for item in final_list:   
                    splitvariable = item.find("=")                  #splitting based on the first occurence of "="
                    final_dict.update({item[:splitvariable].strip():item[splitvariable+1:].strip()})
                return final_dict
                
        
        except EmptyStringException:
            return("Input data is empty")
            
        except InvalidFormatException:
            return("Data Format is in-correct")
            
        except Exception as e:
            return(str(e))
            

# A:Uncomment Below code to run the solution.py independently
# data = input("Enter the Antivirus Log\n")
# result = Sacumen(data).dictlog()
# print(result)

"""***************************** Below are the sample strings ************************************"""

# B: Use below input - If input string is empty    
# data = ""

# C:Use below input - If input string is having correct format
# data = "SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1"             


# D:Use below input - If 'msg' block is not present in the string or the string is having incorrect format
# data = "SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 dhost=bad.com dst=1.1.1.1"       
