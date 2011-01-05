# Be sure to restart your server when you modify this file.

RoodoCasServer::Application.config.session_store :cookie_store, :key => '_roodo-cas-server_session', :domain => 'localhost'

# Use the database for sessions instead of the cookie-based default,
# which shouldn't be used to store highly confidential information
# (create the session table with "rails generate session_migration")
# RoodoCasServer::Application.config.session_store :active_record_store
