import streamlit as st
import os
import json
import logging
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
SCOPES = ['https://www.googleapis.com/auth/indexing', 'openid', 'https://www.googleapis.com/auth/userinfo.email']
REDIRECT_URI = 'https://indexer-udtjm78jffotdonak9obsp.streamlit.app'  # Update this with your Streamlit Cloud URL

def create_flow():
    client_config = json.loads(os.environ.get('CLIENT_SECRET', '{}'))
    if not client_config:
        st.error("CLIENT_SECRET environment variable is not set.")
        return None
    
    try:
        return Flow.from_client_config(
            client_config,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI)
    except Exception as e:
        st.error(f"Error creating OAuth flow: {str(e)}")
        return None

def get_user_info(credentials):
    try:
        user_info_service = build('oauth2', 'v2', credentials=credentials)
        user_info = user_info_service.userinfo().get().execute()
        return user_info.get('email')
    except Exception as e:
        logging.error(f"Error getting user info: {e}")
        return None

def get_indexing_service(credentials):
    try:
        return build('indexing', 'v3', credentials=credentials)
    except Exception as e:
        logging.error(f"Failed to create the indexing service: {e}")
        return None

def index_url(service, url):
    body = {
        "url": url,
        "type": "URL_UPDATED"
    }
    try:
        response = service.urlNotifications().publish(body=body).execute()
        return response
    except HttpError as e:
        if "Permission denied. Failed to verify the URL ownership." in str(e):
            return f"Error: Permission denied. Please ensure you have verified ownership of {url} in Google Search Console."
        return f"An error occurred: {e}"

def main():
    st.title("Google Indexing API with Streamlit")

    # Debug information
    st.sidebar.title("Debug Info")
    st.sidebar.write(f"Session State: {st.session_state}")

    # Check for OAuth callback
    if "code" in st.query_params:
        try:
            flow = create_flow()
            if not flow:
                st.error("Failed to create OAuth flow. Please check your client_secret.json file.")
                return

            flow.fetch_token(code=st.query_params["code"])
            credentials = flow.credentials
            st.session_state.credentials = credentials.to_json()
            st.session_state.is_authenticated = True
            st.success("Authentication successful!")
            logging.info("Authentication successful")
        except Exception as e:
            st.error(f"An error occurred during authentication: {str(e)}")
            logging.error(f"Authentication error: {str(e)}")
        finally:
            st.query_params.clear()
            st.rerun()

    # Main app logic
    if not st.session_state.get('is_authenticated', False):
        st.markdown("Please sign in with Google to use the Indexing API.")
        flow = create_flow()
        if flow:
            auth_url, _ = flow.authorization_url(prompt='consent')
            logging.info(f"Generated auth URL: {auth_url}")
            st.markdown(f'<a href="{auth_url}" target="_blank"><button style="background-color:#4285F4;color:white;padding:8px 12px;border:none;border-radius:4px;cursor:pointer;">Sign in with Google</button></a>', unsafe_allow_html=True)
    else:
        try:
            credentials_info = json.loads(st.session_state.credentials)
            credentials = Credentials.from_authorized_user_info(credentials_info, SCOPES)
            
            email = get_user_info(credentials)
            if email:
                st.write(f"Signed in as {email}")
            else:
                st.warning("Unable to retrieve user email. You may need to re-authenticate.")
            
            if st.button("Sign Out"):
                st.session_state.clear()
                st.rerun()

            service = get_indexing_service(credentials)
            if service:
                urls = st.text_area("Enter URLs to be indexed (one per line)")
                if st.button("Index URLs"):
                    if urls:
                        url_list = urls.split("\n")
                        for url in url_list:
                            url = url.strip()
                            if url:
                                with st.spinner(f"Indexing {url}..."):
                                    response = index_url(service, url)
                                st.write(f"Response for {url}: {response}")
                    else:
                        st.warning("Please enter at least one URL.")
            else:
                st.error("Failed to create indexing service. Please try signing in again.")
        except Exception as e:
            st.error(f"An error occurred: {str(e)}. Please try signing in again.")
            logging.error(f"Error in authenticated state: {str(e)}")
            st.session_state.clear()
            st.rerun()

if __name__ == "__main__":
    main()
