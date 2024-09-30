import yaml
import streamlit as st
from yaml.loader import SafeLoader
import streamlit_authenticator as stauth
from streamlit_authenticator.utilities import (CredentialsError,
                                               ForgotError,
                                               Hasher,
                                               LoginError,
                                               RegisterError,
                                               ResetError,
                                               UpdateError)

# Loading config file
with open('config.yaml', 'r', encoding='utf-8') as file:
    config = yaml.load(file, Loader=SafeLoader)

st.image('logo.png')

st.code(f"""
Credentials:

Name: {config['credentials']['usernames']['jsmith']['name']}
Username: jsmith
Password: {'abc' if 'pp' not in config['credentials']['usernames']['jsmith'].keys() else config['credentials']['usernames']['jsmith']['pp']}

Name: {config['credentials']['usernames']['rbriggs']['name']}
Username: rbriggs
Password: {'def' if 'pp' not in config['credentials']['usernames']['rbriggs'].keys() else config['credentials']['usernames']['rbriggs']['pp']}
"""
)

# Creating the authenticator object
authenticator = stauth.Authenticate(
    config['credentials'],
    config['cookie']['name'],
    config['cookie']['key'],
    config['cookie']['expiry_days'],
    config['pre-authorized']
)

# authenticator = stauth.Authenticate(
#     '../config.yaml'
# )

# Creating a login widget
try:
    authenticator.login()
except LoginError as e:
    st.error(e)

# Creating a guest login button
try:
    authenticator.experimental_guest_login('Login with Google', provider='google',
                                            oauth2=st.secrets["oauth2"])
    authenticator.experimental_guest_login('Login with Microsoft', provider='microsoft',
                                            oauth2=st.secrets["oauth2"])
except LoginError as e:
    st.error(e)

if st.session_state["authentication_status"]:
    authenticator.logout()
    st.write(f'Welcome *{st.session_state["name"]}*')
    st.title('Some content')
elif st.session_state["authentication_status"] is False:
    st.error('Username/password is incorrect')
elif st.session_state["authentication_status"] is None:
    st.warning('Please enter your username and password')

# Creating a password reset widget
if st.session_state["authentication_status"]:
    try:
        if authenticator.reset_password(st.session_state["username"]):
            st.success('Password modified successfully')
            config['credentials']['usernames'][username_of_forgotten_password]['pp'] = new_random_password
    except ResetError as e:
        st.error(e)
    except CredentialsError as e:
        st.error(e)
    st.write('_If you use the password reset widget please revert the password to what it was before once you are done._')

# Creating a new user registration widget
try:
    (email_of_registered_user,
     username_of_registered_user,
     name_of_registered_user) = authenticator.register_user(pre_authorization=False)
    if email_of_registered_user:
        st.success('User registered successfully')
except RegisterError as e:
    st.error(e)

# Creating a forgot password widget
try:
    (username_of_forgotten_password,
     email_of_forgotten_password,
     new_random_password) = authenticator.forgot_password()
    if username_of_forgotten_password:
        st.success(f"New password **'{new_random_password}'** to be sent to user securely")
        config['credentials']['usernames'][username_of_forgotten_password]['pp'] = new_random_password
        # Random password to be transferred to the user securely
    elif not username_of_forgotten_password:
        st.error('Username not found')
except ForgotError as e:
    st.error(e)

# Creating a forgot username widget
try:
    (username_of_forgotten_username,
     email_of_forgotten_username) = authenticator.forgot_username()
    if username_of_forgotten_username:
        st.success(f"Username **'{username_of_forgotten_username}'** to be sent to user securely")
        # Username to be transferred to the user securely
    elif not username_of_forgotten_username:
        st.error('Email not found')
except ForgotError as e:
    st.error(e)

# Creating an update user details widget
if st.session_state["authentication_status"]:
    try:
        if authenticator.update_user_details(st.session_state["username"]):
            st.success('Entries updated successfully')
    except UpdateError as e:
        st.error(e)

# Saving config file
with open('config.yaml', 'w', encoding='utf-8') as file:
    yaml.dump(config, file, default_flow_style=False)
