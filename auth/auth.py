#!/usr/bin/python
import requests
from flask import Flask,request
app=Flask(__name__)

def call911():
	ENDPOINT="127.0.0.1:8181"
	data={"info":"test"}
	r=requests.post(url=ENDPOINT,data=data)
@app.route('/login',methods=["POST"])
def login():
	#receive data (username password posted by h2 or h3)
	#in case of succuessful login
	#send post request to onos (sb) api to activate connectivity for ip
	return "LOGIN SUCCESSFUL\n{} DEVICE CONNECTITY ON".format(request.remote_addr), 200


@app.route('/')
def web_service():

	#IF LOGIN IS SUCCESSFUL THEN CALL 911
	
	return "LOGIN"


#POST REQUEST TO ONOS / appGrande
#is it port 8181 or can app Grande run on a different port to receive REST cals 



if __name__ == '__main__':
    app.run(host="0.0.0.0")
