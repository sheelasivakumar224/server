from flask import Flask, request,jsonify
import requests
from requests_oauthlib import OAuth2Session
from urllib.parse import urlparse, parse_qs
import jwt
import weaviate
import json
import firebase_admin
from firebase_admin import credentials, firestore,auth
from dotenv import load_dotenv
import os
load_dotenv()

app = Flask(__name__)
app.secret_key = "xyzabcdefghijkl"


'''Firestore'''

cred = credentials.Certificate("prompt-dash-firebase-adminsdk-cnikp-185af4d4a3.json")
firebase_app = firebase_admin.initialize_app(cred)
db = firestore.client()

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET=os.getenv("CLIENT_SECRET")
REDIRECT_URI=os.getenv("REDIRECT_URI")
AUTHORIZATION_URL=os.getenv("AUTHORIZATION_URL")
TOKEN_URL=os.getenv("TOKEN_URL")
SECRET_KEY=os.getenv("SECRET_KEY")

'''
------------------------------- Weaviate Code ----------------------------------------------
'''

API_KEY_WEAVIATE=os.getenv("API_KEY_WEAVIATE")
API_KEY_HUGGINGFACE=os.getenv("API_KEY_HUGGINGFACE")
CLASS=os.getenv("CLASS")
WEAVIATE_URL=os.getenv("WEAVIATE_URL")

auth_config = weaviate.AuthApiKey(api_key = API_KEY_WEAVIATE)



# Creating an Instance of the Client
client = weaviate.Client(
    url = WEAVIATE_URL,
    auth_client_secret= auth_config,
        additional_headers={
        "X-HuggingFace-Api-Key": API_KEY_HUGGINGFACE
    }
)


def addToClass(email,prompt,title,category):
    try:
        properties = {
            "public" : False,
            "email" : email,
            "title" : title,
            "prompt" : prompt,
            "category" : category,
            "isPinned" : False
        }
        uuid = client.data_object.create(properties,class_name=CLASS)
        print(uuid)
        doc_ref = db.collection("All_Prompt").document(uuid)
        data = {
            "uuid" : uuid,
            "public" : False,
            "email" : email,
            "title" : title,
            "prompt" : prompt,
            "category" : category,
            "deleted" : False,
            "created_date":firestore.SERVER_TIMESTAMP,
            "modified_date":firestore.SERVER_TIMESTAMP 
        }
        #add to Firestore DB
        doc_ref.set(data)
    except Exception as e:
        return f"An Error occured : {str(e)}",404


def searchMyPrompt(email,prompt,mode,category):
    try:
        if(mode == "private"):
            if(category == "All"):
                where_filter = {
                    "operands" : [
                        {
                            "path" : ["public"],
                            "operator" : "Equal",
                            "valueBoolean" : False
                        },
                        {
                            "path": ["email"],
                            "operator" : "Equal",
                            "valueString" : email
                        }
                    ],
                    "operator" : "And"
                }
                query = (client.query.get(CLASS,['title','prompt','category','public','isPinned']).with_near_text({"concepts": prompt,"accuracy": 0.8}).with_where(where_filter).do())
                prompts = query["data"]["Get"]["PromptDash2"]
                prompt_texts = [prompt for prompt in prompts]
                results = []
                for text in prompt_texts:
                    prompt_data = {
                            "prompt": text["prompt"],
                            "title": text["title"],
                            "category": text["category"],
                            "public" : text["public"],
                            "isPinned" : text["isPinned"]
                    }
                    results.append(prompt_data)
                final = json.dumps(results)
                return final   
            else:
                where_filter = {
                    "operands" : [
                        {
                            "path" : ["public"],
                            "operator" : "Equal",
                            "valueBoolean" : False
                        },
                        {
                        "path": ["category"],
                        "operator" : "Equal",
                        "valueString" : category
                        },
                        {
                            "path": ["email"],
                            "operator" : "Equal",
                            "valueString" : email
                        }
                    ],
                    "operator" : "And"
                    }
                query = (client.query.get(CLASS,['title','prompt','category','public','isPinned']).with_near_text({"concepts": prompt,"accuracy": 0.4}).with_where(where_filter).do())
                prompts = query["data"]["Get"]["PromptDash2"]
                prompt_texts = [prompt for prompt in prompts]
                results = []
                for text in prompt_texts:
                        prompt_data = {
                                "prompt": text["prompt"],
                                "title": text["title"],
                                "category": text["category"],
                                "public" : text["public"],
                                "isPinned" : text['isPinned']
                        }
                        results.append(prompt_data)
                final = json.dumps(results)
                return final   
        else:
            if(category == "All"):
                query = (client.query.get(CLASS,['title','prompt','category','public','isPinned']).with_near_text({"concepts": prompt,"accuracy": 0.4}).do())
                prompts = query["data"]["Get"][CLASS]
                prompt_texts = [prompt for prompt in prompts]
                results = []
                for text in prompt_texts:
                    prompt_data = {
                            "prompt": text["prompt"],
                            "title": text["title"],
                            "category": text["category"],
                            "public" : text["public"],
                            "isPinned" : text["isPinned"]
                    }
                    results.append(prompt_data)
                final = json.dumps(results)
                return final   
            else:
                where_filter = {
                        "path": ["category"],
                        "operator" : "Equal",
                        "valueString" : category
                    }
                query = (client.query.get(CLASS,['title','prompt','category','public','isPinned']).with_near_text({"concepts": prompt,"accuracy": 0.4}).with_where(where_filter).do())
                prompts = query["data"]["Get"][CLASS]
                prompt_texts = [prompt for prompt in prompts]
                results = []
                for text in prompt_texts:
                        prompt_data = {
                                "prompt": text["prompt"],
                                "title": text["title"],
                                "category": text["category"],
                                "public" : text["public"],
                                "isPinned" : text["isPinned"]
                        }
                        results.append(prompt_data)
                final = json.dumps(results)
                return final   
    except Exception as  e:
        error_message = "No data found"
        return error_message, 404      

def getPromptinfo(text):
    res = client.query.get(CLASS,['public','email','title','prompt','category','isPinned']).with_additional("id").with_near_text({"concepts" : [text]}).with_limit(1).do()
    prompts = res["data"]["Get"]["PromptDash2"]
    prompt_texts = [prompt for prompt in prompts]
    for text in prompt_texts:
        return text
   

def deleteMyprompt(text):
     info =  getPromptinfo(text)
     print(info)  
     id = info['_additional']["id"]  
     email = info['email']
     if id is not None:
         client.data_object.delete(uuid = id,class_name=CLASS)
         doc_ref = db.collection("All_Prompt").document(id)
         doc_ref.update({"deleted":True})
         pinned_ref = db.collection("Pinned").document(email)
         pinned_ref.update({"Pinned_prompt": firestore.ArrayRemove([doc_ref])})
         return "Deleted the Prompt and Unpinned the prompt"
     else:
         return "Prompt doesnt exist"


def updateMyprompt(text,editedText):
    info = getPromptinfo(text)
    id = info['_additional']["id"]
    update_data = {
        "public" : False,
        "email" : info["email"],
        "prompt" : editedText,
        "title" : info["title"],
        "category" : info["category"],
        "isPinned" : info["isPinned"]
    }  
    if id is not None:
         client.data_object.replace(uuid = id,class_name=CLASS,data_object=update_data)
         doc_ref = db.collection("All_prompt").document(id)
         doc_ref.update({"prompt":text,"modified_date":firestore.SERVER_TIMESTAMP })
    else:
         return "Prompt doesn't exist"

# Need to check the code logic to pin the prompt
def pinThePrompt(query,email):
    info = getPromptinfo(query)
    id = info['_additional']["id"]
    update_data = {
        "public" : False,
        "email" : info["email"],
        "prompt" : info["prompt"],
        "title" : info["title"],
        "category" : info["category"],
        "isPinned" : True
    }  
    client.data_object.replace(uuid = id,class_name=CLASS,data_object=update_data)
    doc_ref = db.collection("All_Prompt").document(id)
    pinned_ref = db.collection("Pinned").document(email)
    pinned_ref.update({"Pinned_prompt": firestore.ArrayUnion([doc_ref])})
    return "Inserted into firestore"

def unpinThePrompt(query,email):
    info = getPromptinfo(query)
    id = info['_additional']["id"]
    update_data = {
        "public" : False,
        "email" : info["email"],
        "prompt" : info["prompt"],
        "title" : info["title"],
        "category" : info["category"],
        "isPinned" : False
    }  
    client.data_object.replace(uuid = id,class_name=CLASS,data_object=update_data)
    doc_ref = db.collection("All_Prompt").document(id)
    pinned_ref = db.collection("Pinned").document(email)
    pinned_ref.update({"Pinned_prompt": firestore.ArrayRemove([doc_ref])})
    return "Unpinned the prompt"

# Need to check the code logic to pin the prompt
def displayPinned(email):
    try:
        pinned_doc = db.collection("Pinned").document(email).get()
        if pinned_doc.exists:
            prompt_ref = pinned_doc.get("Pinned_prompt")
            if prompt_ref:
                prompt_data_result = []
                for prompt_refs in prompt_ref:
                    prompt_doc = prompt_refs.get()
                    prompt_doc2 = prompt_doc.to_dict()
                    if prompt_doc.exists:
                        prompt_data = {
                            "title": prompt_doc2.get("title", ""),
                            "prompt": prompt_doc2.get("prompt", ""),
                            "category": prompt_doc2.get("category", "")
                        }
                        prompt_data_result.append(prompt_data)
                return prompt_data_result
            else:
                return "No data Found",404
        else:
            return "No data Found",404
    except Exception as e:
        return "No data Found",404

def adduser(name,email):
    doc_ref = db.collection("users").document(email)
    doc = doc_ref.get()
    if doc.exists:
        doc_ref.update({"last_login" : firestore.SERVER_TIMESTAMP })
        print("Updated Existing user")
    else:
        doc_ref.set({
            "username" : name,
            "Signed_on" : firestore.SERVER_TIMESTAMP,
            "last_login" : firestore.SERVER_TIMESTAMP
        })
        print("Added new users")


oauth = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI)
    
@app.route('/login', methods=['GET'])
def start_auth():
    auth_url = f'{AUTHORIZATION_URL}?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope=openid profile'
    return  jsonify({"auth_url":auth_url})

@app.route('/authenticate',methods=['GET','POST'])
def callback():
    try:
        data = request.get_json()
        url = data['code']
        parsed_url = urlparse(url)
        query_parameters = parse_qs(parsed_url.query)
        code = query_parameters.get('code',[None])[0]
        if code is None:
            return jsonify({'msg' : "Authorization code Missing"})
        
        try:
            token = oauth.fetch_token(TOKEN_URL,code = code,client_secret=CLIENT_SECRET)
            if 'access_token' in token:
                access_token = token['access_token']
                expires_in = token['expires_in']
                refresh_token = token.get('refresh_token',None)
                print(expires_in)
                print("Access Token: ",access_token)
                print("Refresh Token: ",refresh_token)
                user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo'
                headers = {'Authorization': f'Bearer {access_token}'}
                response = requests.get(user_info_url, headers=headers)

                if response.status_code == 200:
                    user_info = response.json()
                    name = user_info.get('name')
                    email = user_info.get('email')
                    profile = user_info.get('picture')
                    info = {
                        'name': name,
                        'email': email,
                        'profile':profile
                    }
                    jwt_token = jwt.encode(info,SECRET_KEY,algorithm='HS256')
                    adduser(name,email)
                    return jsonify({'msg' : jwt_token})
                else:
                  return jsonify({'msg' : "token exchange error"})
            else:
                return jsonify({'msg' :"token Exchange Failed"})
        except Exception as e:
            msg = f"Token exchange error: {str(e)}"
            return jsonify({'msg' : msg})
        
    except Exception as e:
        return f"Error: {str(e)}"     

@app.route('/getinfo',methods = ['GET'])
def info():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split('Bearer ')[1]
        try:
            payload = jwt.decode(token,SECRET_KEY,algorithms=['HS256'])
            adduser(payload["name"],payload["email"])
            pinnedPrompt = displayPinned(payload["email"])
            return jsonify({'msg': 'JWT is valid','payload':payload,"pinnedPrompt":pinnedPrompt})
        except jwt.ExpiredSignatureError:
            return jsonify({'error':'Token has expired'})
        except jwt.DecodeError:
            return jsonify({'error':'Invalid token'})
    else:
        return jsonify({'error':'Invalid authorization header'})


@app.route('/add',methods = ["POST"])
def add():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split('Bearer ')[1]
        try:
            payload = jwt.decode(token,SECRET_KEY,algorithms=['HS256'])
            data = request.get_json()
            title = data["title"]
            prompt = data["prompt"]
            category = data["category"]
            email = payload["email"]
            print(title,prompt,category)
            addToClass(email,prompt,title,category)
            return jsonify({'msg': 'prompt added'})
        except jwt.ExpiredSignatureError:
            return jsonify({'error':'Token has expired'})
        except jwt.DecodeError:
            return jsonify({'error':'Invalid token'})
    else:
        return jsonify({'error':'Invalid authorization header'})


@app.route('/search',methods=['POST'])
def search():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split('Bearer ')[1]
        try:
            payload = jwt.decode(token,SECRET_KEY,algorithms=['HS256'])
            data = request.get_json()
            prompt = data["query"]
            category = data["category"]
            mode = data["mode"]
            email = payload["email"]
            final = searchMyPrompt(email,prompt,mode,category)
            return final
        except jwt.ExpiredSignatureError:
            return jsonify({'error':'Token has expired'})
        except jwt.DecodeError:
            return jsonify({'error':'Invalid token'})
    else:
        return jsonify({'error':'Invalid authorization header'})
    

@app.route('/delete',methods = ['POST'])
def delete():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split('Bearer ')[1]
        try:
            payload = jwt.decode(token,SECRET_KEY,algorithms=['HS256'])
            data = request.get_json()
            prompt = data["query"]
            deleteMyprompt(prompt)
            return jsonify({"msg" : "Delete works"})
        except jwt.ExpiredSignatureError:
            return jsonify({'error':'Token has expired'})
        except jwt.DecodeError:
            return jsonify({'error':'Invalid token'})
    else:
        return jsonify({'error':'Invalid authorization header'})

@app.route('/update',methods = ["POST"])
def update():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split('Bearer ')[1]
        try:
            payload = jwt.decode(token,SECRET_KEY,algorithms=['HS256'])
            data = request.get_json()
            originalText = data["originalPrompt"]
            editedText = data["editedPrompt"]
            updateMyprompt(originalText,editedText)
            return jsonify({"msg" : "update works"})
        except jwt.ExpiredSignatureError:
            return jsonify({'error':'Token has expired'})
        except jwt.DecodeError:
            return jsonify({'error':'Invalid token'})
    else:
        return jsonify({'error':'Invalid authorization header'})


@app.route('/pin',methods = ["POST"])
def pinPrompt():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split('Bearer ')[1]
        try:
            payload = jwt.decode(token,SECRET_KEY,algorithms=['HS256'])
            data = request.get_json()
            prompt = data["query"]
            email = payload["email"]
            pinThePrompt(prompt,email)
            return jsonify({"msg" : "pin works"})
        except jwt.ExpiredSignatureError:
            return jsonify({'error':'Token has expired'})
        except jwt.DecodeError:
            return jsonify({'error':'Invalid token'})
    else:
        return jsonify({'error':'Invalid authorization header'})

@app.route('/unpin',methods = ["POST"])
def unpinPrompt():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split('Bearer ')[1]
        try:
            payload = jwt.decode(token,SECRET_KEY,algorithms=['HS256'])
            data = request.get_json()
            prompt = data["query"]
            email = payload["email"]
            unpinThePrompt(prompt,email)
            return jsonify({"msg" : "unpin works"})
        except jwt.ExpiredSignatureError:
            return jsonify({'error':'Token has expired'})
        except jwt.DecodeError:
            return jsonify({'error':'Invalid token'})
    else:
        return jsonify({'error':'Invalid authorization header'})

@app.route('/displaypin',methods = ["GET"])
def displaypin():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split('Bearer ')[1]
        try:
            payload = jwt.decode(token,SECRET_KEY,algorithms=['HS256'])
            email = payload["email"]
            pinprompt = displayPinned(email)
            return pinprompt
        except jwt.ExpiredSignatureError:
            return jsonify({'error':'Token has expired'})
        except jwt.DecodeError:
            return jsonify({'error':'Invalid token'})
    else:
        return jsonify({'error':'Invalid authorization header'})



if __name__ == ("__main__"):
    app.run(debug= True)